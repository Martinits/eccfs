use std::io::prelude::*;
use std::path::{Path, PathBuf};
use crate::*;
use std::fs::{OpenOptions, self, File};
use crate::crypto::*;
use crate::vfs::*;
use super::*;
use super::disk::*;
use super::superblock::*;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;
use std::io::Write;
use crate::htree::*;
use std::time::*;


type ChildInfo = (PathBuf, FileType, InodeID);

const DATA_TEMP_FILE: &str = ".data.eccfs";
const ITBL_IID: InodeID = InodeID::MAX;

pub fn create_empty(to: &Path, encrypted: Option<Key128>) -> FsResult<FSMode> {
    // check to
    if to.exists() {
        if io_try!(fs::read_dir(to)).next().is_some() {
            return Err(new_error!(FsError::DirectoryNotEmpty));
        }
    } else {
        info!("{} not found, create dir", to.display());
        io_try!(fs::create_dir(to));
    }

    let mut builder = RWBuilder::new(
        to, encrypted,
    )?;

    builder.handle_empty_root_dir()?;
    let root_mode = builder.finalize(ROOT_INODE_ID)?;

    Ok(root_mode)
}

/// build a rwfs image under dir [`to`] from all files under [`from`]
pub fn build_from_dir(
    from: &Path,
    to: &Path,
    encrypted: Option<Key128>,
) -> FsResult<FSMode> {
    // check to
    if to.exists() {
        if io_try!(fs::read_dir(to)).next().is_some() {
            return Err(new_error!(FsError::DirectoryNotEmpty));
        }
    } else {
        info!("{} not found, create dir", to.display());
        io_try!(fs::create_dir(to));
    }

    // check from
    if !io_try!(fs::metadata(from)).is_dir() {
        return Err(new_error!(FsError::NotADirectory));
    }

    let mut builder = RWBuilder::new(
        to,
        encrypted.clone(),
    )?;

    // stack holds (full paths, father_idx, inode id)
    let mut stack = vec![Some((from.to_path_buf(), 0usize, 1u64))];
    // de_info maps full path to children, holding child names, not full paths
    let mut de_info = HashMap::new();
    assert!(de_info.insert(from.to_path_buf(), Vec::new()).is_none());

    let mut next_iid = 2;
    push_all_children(&mut stack, from, 0, &mut next_iid)?;

    // travel file tree in post order
    // we don't use recursion but iteration by a stack
    while stack.len() > 1 {
        if let Some((pb, fidx, iid)) = stack.pop().unwrap() {
            let father_idx = stack.len();
            stack.push(Some((pb.clone(), fidx, iid)));
            stack.push(None);
            assert!(de_info.insert(pb.clone(), Vec::new()).is_none());
            push_all_children(&mut stack, pb.as_path(), father_idx, &mut next_iid)?;
        } else {
            let (pb, fidx, iid) = stack.pop().unwrap().unwrap();
            // access this node
            let m = io_try!(fs::symlink_metadata(&pb));
            let (fpb, _, fiid) = &stack.get(fidx).unwrap().as_ref().unwrap();
            if m.is_dir() {
                let child_info = de_info.remove(&pb).unwrap();
                builder.handle_dir(iid, *fiid, &pb, child_info)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Dir, iid
                    )
                );
            } else if m.is_file() {
                builder.handle_reg(iid, &pb)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Reg, iid
                    )
                );
            } else if m.is_symlink() {
                builder.handle_sym(iid, &pb)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Lnk, iid
                    )
                );
            } else {
                warn!("Unsupported file type of {}, skip.", pb.display());
            };
        }
    }
    assert_eq!(stack.len(), 1);

    // create and write root inode
    let root_pb: PathBuf = from.to_path_buf();
    builder.handle_dir(
        ROOT_INODE_ID,
        ROOT_INODE_ID,
        &root_pb,
        de_info.remove(&root_pb).unwrap(),
    )?;

    // complete image conversion
    let ret = builder.finalize(next_iid - 1)?;

    Ok(ret)
}

fn push_all_children(
    stack: &mut Vec<Option<(PathBuf, usize, InodeID)>>,
    path: &Path,
    father_idx: usize,
    next_iid: &mut InodeID,
) -> FsResult<()> {
    if io_try!(fs::symlink_metadata(path)).is_dir() {
        for p in io_try!(fs::read_dir(path)) {
            stack.push(Some((io_try!(p).path(), father_idx, *next_iid)));
            *next_iid += 1;
        }
    }
    Ok(())
}

fn push_child_info(
    map: &mut HashMap<PathBuf, Vec<ChildInfo>>,
    fpb: &PathBuf,
    child_info: ChildInfo,
) {
    map.get_mut(fpb).unwrap().push(child_info);
}

struct RWBuilder {
    encrypted: Option<Key128>,
    to_dir: PathBuf,
    itbl: HashMap<InodeID, InodeBytes>,
    key_gen: KeyGen,
    ht: HTreeBuilder,
    files: usize,
    blocks: usize,
    nr_data_file: usize,
}

impl RWBuilder {
    fn new(
        to: &Path,
        encrypted: Option<Key128>,
    ) -> FsResult<Self> {
        Ok(Self {
            encrypted,
            to_dir: to.into(),
            itbl: HashMap::new(),
            files: 0,
            blocks: 0,
            key_gen: KeyGen::new(),
            ht: HTreeBuilder::new(encrypted.is_some())?,
            nr_data_file: 2, // sb file and itbl
        })
    }

    fn write_inode(&mut self, iid: InodeID, ib: InodeBytes) {
        assert!(iid != 0);
        assert!(self.itbl.insert(iid, ib).is_none());
    }

    fn gen_inode_base(pb: &PathBuf) -> FsResult<DInodeBase> {
        let m = io_try!(fs::symlink_metadata(&pb));

        Ok(DInodeBase {
            mode: get_mode_from_libc_mode(m.mode()),
            nlinks: m.nlink() as u16,
            uid: m.uid(),
            gid: m.gid(),
            atime: m.atime() as u32,
            mtime: m.mtime() as u32,
            ctime: m.ctime() as u32,
            size: m.size(),
        })

    }

    fn gen_dir_entries(
        &mut self,
        cinfo: Vec<ChildInfo>
    ) -> FsResult<Vec<DiskDirEntry>> {
        Ok(cinfo.into_iter().map(
            |(name, tp, iid)| {
                let bname = name.as_os_str();
                assert!(bname.len() < NAME_MAX as usize);

                let mut dde = DiskDirEntry {
                    ipos: iid,
                    tp: tp.into(),
                    len: bname.len() as u16,
                    name: [0u8; DIRENT_NAME_MAX],
                };
                dde.name[..bname.len()].copy_from_slice(bname.to_str().unwrap().as_bytes());
                dde
            }
        ).collect())
    }

    fn create_data_file_from_iid(&self, iid: InodeID) -> FsResult<(Hash256, File)> {
        let mut dir = self.to_dir.clone();
        let data_file = iid_hash(iid)?;
        dir.push(hex::encode_upper(data_file));
        let f = io_try!(OpenOptions::new().create_new(true).write(true).open(dir));
        Ok((data_file, f))
    }

    fn build_htree_from_data(
        &mut self,
        mut dir: PathBuf,
        data: &[u8],
        iid: InodeID,
    ) -> FsResult<(u64, KeyEntry, Hash256)> { // return htree_len, htree_ke and data_file_name
        // write to temp data file
        dir.push(DATA_TEMP_FILE);
        let mut f = io_try!(OpenOptions::new().write(true).create_new(true).open(&dir));
        let data_raw_path = dir.clone();
        dir.pop();
        io_try!(f.write_all(&data));

        dir.push(iid_hash_name(iid)?);
        let mut f = io_try!(OpenOptions::new().read(true).write(true)
                            .create_new(true).open(&dir));
        dir.pop();
        let (sz, ke) = self.ht.build_htree(&mut f, &data_raw_path)?;

        // remove temp data file
        io_try!(fs::remove_file(data_raw_path));

        Ok((sz as u64, ke, iid_hash(iid)?))
    }

    fn handle_empty_root_dir(
        &mut self,
    ) -> FsResult<()> {
        // insert dot and dotdot
        let mut child_info = Vec::new();
        child_info.insert(0, (".".into(), FileType::Dir, ROOT_INODE_ID));
        child_info.insert(0, ("..".into(), FileType::Dir, ROOT_INODE_ID));
        let dde_list = self.gen_dir_entries(child_info)?;

        // dinode dir base
        let now = SystemTime::now()
                    .duration_since(SystemTime::UNIX_EPOCH).unwrap()
                    .as_secs() as u32;
        let mut dibase = DInodeBase {
            mode: get_mode(FileType::Dir, &FilePerm::from_bits(0o755).unwrap()),
            nlinks: 1,
            uid: unsafe { libc::getuid() },
            gid: unsafe { libc::getgid() },
            atime: now,
            ctime: now,
            mtime: now,
            size: 2 * DIRENT_SZ as u64,
        };
        // for dir inodes, size represents entry data size
        dibase.size = (dde_list.len() * DIRENT_SZ) as u64;

        let (len, data_file_ke, data_file) = self.build_htree_from_data(
            self.to_dir.clone(),
            unsafe {
                std::slice::from_raw_parts(
                    dde_list.as_ptr() as *const u8,
                    dde_list.len() * DIRENT_SZ,
                )
            },
            ROOT_INODE_ID,
        )?;
        let ino = DInodeDir {
            base: dibase,
            data_file,
            data_file_ke,
            len,
            _padding: [0u8; 24],
        };

        self.write_inode(ROOT_INODE_ID, ino.into());
        self.blocks += len as usize;
        self.nr_data_file += 1;

        Ok(())
    }
    fn handle_dir(
        &mut self,
        iid: InodeID,
        fiid: InodeID,
        path: &PathBuf,
        mut child_info: Vec<ChildInfo>,
    ) -> FsResult<()> {
        // insert dot and dotdot
        child_info.insert(0, (".".into(), FileType::Dir, iid));
        child_info.insert(0, ("..".into(), FileType::Dir, fiid));
        let dde_list = self.gen_dir_entries(child_info)?;

        // dinode dir base
        let mut dibase = Self::gen_inode_base(path)?;
        // for dir inodes, size represents entry data size
        dibase.size = (dde_list.len() * DIRENT_SZ) as u64;

        let (len, data_file_ke, data_file) = self.build_htree_from_data(
            self.to_dir.clone(),
            unsafe {
                std::slice::from_raw_parts(
                    dde_list.as_ptr() as *const u8,
                    dde_list.len() * DIRENT_SZ,
                )
            },
            iid,
        )?;
        let ino = DInodeDir {
            base: dibase,
            data_file,
            data_file_ke,
            len,
            _padding: [0u8; 24],
        };

        self.write_inode(iid, ino.into());
        self.blocks += len as usize;
        self.nr_data_file += 1;

        Ok(())
    }

    fn handle_reg(
        &mut self,
        iid: InodeID,
        path: &PathBuf,
    ) -> FsResult<()> {
        let dibase = Self::gen_inode_base(path)?;
        let sz = dibase.size;

        let inode = if sz <= REG_INLINE_DATA_MAX as u64 {
            // inline data
            let mut inode = DInodeRegInline {
                base: dibase,
                data: [0u8; REG_INLINE_DATA_MAX],
            };

            // read all bytes from source file
            let mut f = io_try!(File::open(path));
            if io_try!(f.read(&mut inode.data[..sz as usize])) != sz as usize {
                return Err(new_error!(FsError::UnexpectedEof));
            }

            inode.into()
        } else {
            let (data_file, mut f) = self.create_data_file_from_iid(iid)?;
            // generate hash tree
            let (nr_blk, data_file_ke) = self.ht.build_htree(&mut f, path)?;

            self.blocks += nr_blk;
            self.nr_data_file += 1;

            DInodeReg {
                base: dibase,
                data_file_ke,
                data_file,
                len: nr_blk as u64,
                _padding: [0u8; 24],
            }.into()
        };
        self.write_inode(iid, inode);
        self.files += 1;

        Ok(())
    }

    fn handle_sym(&mut self, iid: InodeID, path: &PathBuf) -> FsResult<()> {
        let mut dibase = Self::gen_inode_base(path)?;

        // for symlnk inodes, size represents sym name length
        let target = io_try!(fs::read_link(path));
        let size = target.as_os_str().len();
        dibase.size = size as u64;

        let dinode = if size <= LNK_INLINE_MAX {
            // inline name
            let mut d = DInodeLnkInline {
                base: dibase,
                name: [0u8; LNK_INLINE_MAX],
            };
            d.name[..size].copy_from_slice(target.as_os_str().to_str().unwrap().as_bytes());
            d.into()
        } else {
            // single block file
            let (data_file, mut f) = self.create_data_file_from_iid(iid)?;
            let mut blk = [0u8; BLK_SZ];
            blk[..size].copy_from_slice(target.as_os_str().to_str().unwrap().as_bytes());
            let name_file_ke = crypto_out(
                &mut blk,
                if self.encrypted.is_some() {
                    Some(self.key_gen.gen_key(0)?)
                } else {
                    None
                },
                0,
            )?.into_key_entry();
            io_try!(f.write_all(&blk));

            self.blocks += 1;
            self.nr_data_file += 1;

            DInodeLnk {
                base: dibase,
                name_file_ke,
                data_file,
                len: 1,
                _padding: [0u8; 24],
            }.into()
        };

        self.write_inode(iid, dinode);
        Ok(())
    }

    fn build_sb_file(
        &mut self,
        max_iid: InodeID,
        itbl_info: (u64, KeyEntry, Hash256),
    ) -> FsResult<FSMode> {
        let mut bm_blks = BitMap::write_from_list((0..=max_iid).collect())?;
        let mut bm_ke = vec![];
        for (i, blk) in bm_blks.iter_mut().enumerate() {
            let pos = 1 + i as u64;
            let ke = crypto_out(
                blk,
                if self.encrypted.is_some() {
                    Some(self.key_gen.gen_key(pos)?)
                } else {
                    None
                },
                pos,
            )?.into_key_entry();
            bm_ke.push(ke);
        }
        let sb = SuperBlock {
            nr_data_file: self.nr_data_file,
            encrypted: self.encrypted.is_some(),
            magic: RWFS_MAGIC,
            bsize: BLK_SZ,
            blocks: self.blocks + bm_blks.len() + 1, // + bitmap + sb
            files: self.files,
            namemax: NAME_MAX as usize,
            ibitmap_start: 1,
            ibitmap_len: bm_blks.len() as usize,
            ibitmap_ke: bm_ke,
            itbl_name: itbl_info.2,
            itbl_len: itbl_info.0 as usize,
            itbl_ke: itbl_info.1,
        };
        let mut sb_blk = sb.write()?;
        let root_mode = crypto_out(
            &mut sb_blk,
            self.encrypted,
            SUPERBLOCK_POS,
        )?;
        // write to file
        self.to_dir.push(SB_FILE_NAME);
        let mut sb_file = io_try!(OpenOptions::new().write(true)
                            .create_new(true).open(&self.to_dir));

        io_try!(sb_file.write_all(&sb_blk));
        for blk in bm_blks {
            io_try!(sb_file.write_all(&blk));
        }

        Ok(root_mode)
    }

    fn finalize(mut self, max_iid: InodeID) -> FsResult<FSMode> {
        let mut itbl = vec![[0u8; INODE_SZ]; max_iid as usize + 1];
        self.itbl.iter().for_each(
            |(iid, ib)| {
                assert!(*iid <= max_iid);
                assert!(*iid != 0);
                itbl[*iid as usize] = ib.clone();
            }
        );

        let itbl_info = self.build_htree_from_data(
            self.to_dir.clone(),
            unsafe {
                std::slice::from_raw_parts(
                    itbl.as_ptr() as *const u8,
                    itbl.len() * INODE_SZ,
                )
            },
            ITBL_IID,
        )?;
        self.blocks += itbl_info.0 as usize;

        let root_mode = self.build_sb_file(max_iid, itbl_info)?;
        Ok(root_mode)
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn build_empty() {
        use std::path::Path;
        use crate::*;
        use std::fs::OpenOptions;
        use std::fs;
        use std::env;
        use std::io::prelude::*;
        #[allow(unused)]
        use rand_core::RngCore;

        if cfg!(debug_assertions) {
            env::set_var("RUST_BACKTRACE", "1");
            env_logger::builder()
                .filter_level(log::LevelFilter::Debug)
                .init();
        }

        let args: Vec<String> = env::args().collect();
        assert!(args.len() >= 5);
        let mode = args[3].clone();
        let target = args[4].clone();
        debug!("Creating empty RWFS {}", target);

        let to = format!("test/{}.rwimage", &target);

        let k = match mode.as_str() {
            "enc" => {
                let mut k = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut k);
                Some(k)
            }
            "int" => {
                None
            }
            _ => panic!("unrecognized fsmode"),
        };

        let mode = super::create_empty(
            Path::new(&to),
            k,
        ).unwrap();
        match &mode {
            FSMode::IntegrityOnly(hash) => {
                let s = hex::encode_upper(hash);
                println!("Built in IntegrityOnly Mode:");
                println!("Hash: {}", s);
            }
            FSMode::Encrypted(key, mac) => {
                assert_eq!(k.unwrap(), *key);
                println!("Built in Encrypted Mode:");
                let k = hex::encode_upper(key);
                let m = hex::encode_upper(mac);
                println!("Key: {}", k);
                println!("Mac: {}", m);
            }
        }
        // save mode to file
        let name = format!("test/{}.mode", target);
        let _ = fs::remove_file(name.clone());
        let mut f = OpenOptions::new().write(true).create_new(true).open(name).unwrap();
        let written = f.write(unsafe {
            std::slice::from_raw_parts(
                &mode as *const FSMode as *const u8,
                std::mem::size_of::<FSMode>(),
            )
        }).unwrap();
        assert_eq!(written, std::mem::size_of::<FSMode>());
    }

    #[test]
    fn build_rw() {
        use std::path::Path;
        use crate::*;
        use std::fs::OpenOptions;
        use std::fs;
        use std::env;
        use std::io::prelude::*;
        #[allow(unused)]
        use rand_core::RngCore;

        if cfg!(debug_assertions) {
            env::set_var("RUST_BACKTRACE", "1");
            env_logger::builder()
                .filter_level(log::LevelFilter::Debug)
                .init();
        }

        let args: Vec<String> = env::args().collect();
        assert!(args.len() >= 5);
        let mode = args[3].clone();
        let target = args[4].clone();
        debug!("Building RWFS {}", target);

        let from = format!("test/{}", &target);
        let to = format!("test/{}.rwimage", &target);

        let k = match mode.as_str() {
            "enc" => {
                let mut k = [0u8; 16];
                rand::thread_rng().fill_bytes(&mut k);
                Some(k)
            }
            "int" => {
                None
            }
            _ => panic!("unrecognized fsmode"),
        };

        let mode = super::build_from_dir(
            Path::new(&from),
            Path::new(&to),
            k,
        ).unwrap();
        match &mode {
            FSMode::IntegrityOnly(hash) => {
                let s = hex::encode_upper(hash);
                println!("Built in IntegrityOnly Mode:");
                println!("Hash: {}", s);
            }
            FSMode::Encrypted(key, mac) => {
                assert_eq!(k.unwrap(), *key);
                println!("Built in Encrypted Mode:");
                let k = hex::encode_upper(key);
                let m = hex::encode_upper(mac);
                println!("Key: {}", k);
                println!("Mac: {}", m);
            }
        }
        // save mode to file
        let name = format!("test/{}.mode", target);
        let _ = fs::remove_file(name.clone());
        let mut f = OpenOptions::new().write(true).create_new(true).open(name).unwrap();
        let written = f.write(unsafe {
            std::slice::from_raw_parts(
                &mode as *const FSMode as *const u8,
                std::mem::size_of::<FSMode>(),
            )
        }).unwrap();
        assert_eq!(written, std::mem::size_of::<FSMode>());
    }
}
