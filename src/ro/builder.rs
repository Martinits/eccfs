use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use crate::*;
use std::fs::{OpenOptions, self, File};
use log::warn;
use crate::crypto::*;
use rand_core::RngCore;
use crate::vfs::*;
use super::*;
use std::mem::{size_of_val, size_of};
use super::disk::*;
use std::collections::HashMap;
use std::ffi::OsString;
use std::cmp::Ordering;
use std::os::unix::fs::MetadataExt;
use std::io::Write;


const MAX_ENTRY_GROUP_LEN: usize = 16;

type ChildInfo = (PathBuf, FileType, InodeID, Option<u64>);

const ROOT_PATHBUF: &str = "/";

/// build a rofs image named [`to`] from all files under [`from`]
pub fn build_from_dir(
    from: &Path,
    to: &Path,
    mode: FSMode,
) -> FsResult<()> {
    // check to
    if fs::metadata(to).is_ok() {
        return Err(FsError::AlreadyExists);
    }
    let image = io_try!(OpenOptions::new().write(true).create(true).open(to));

    // check from
    if !io_try!(fs::metadata(from)).is_dir() {
        return Err(FsError::NotADirectory);
    }

    // prepare
    let mut to_dir = to.to_path_buf();
    assert!(to_dir.pop());

    let mut builder = ROBuilder::new(
        image,
        to_dir,
        io_try!(fs::read_dir(from)).count(),
        mode,
    )?;

    // stack holds full paths
    let mut stack = vec![Some((ROOT_PATHBUF.into(), 0usize))];
    push_all_children(&mut stack, from, 0)?;
    // de_info maps full path to children, holding child names, not full paths
    let mut de_info = HashMap::new();

    // travel file tree in post order
    // we don't use recursion but iteration by a stack
    while stack.len() > 1 {
        if let Some((pb, fidx)) = stack.pop().unwrap() {
            let father_idx = stack.len();
            stack.push(Some((pb.clone(), fidx)));
            stack.push(None);
            push_all_children(&mut stack, pb.as_path(), father_idx)?;
        } else {
            let (pb, fidx) = stack.pop().unwrap().unwrap();
            // access this node
            let m = io_try!(fs::symlink_metadata(&pb));
            let fpb = &stack.get(fidx).unwrap().as_ref().unwrap().0;
            if m.is_dir() {
                let child_info = de_info.remove(&pb).unwrap();
                let (iid, dotdot) = builder.handle_dir(&pb, child_info)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Dir, iid, Some(dotdot)
                    )
                );
            } else if m.is_file() {
                let iid = builder.handle_reg(&pb)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Reg, iid, None
                    )
                );
            } else if m.is_symlink() {
                let iid = builder.handle_sym(&pb)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Lnk, iid, None
                    )
                );
            } else {
                warn!("Unsupported file type of {}, skip.", pb.display());
            };
        }
    }
    assert_eq!(stack.len(), 1);

    let root_pb: PathBuf = ROOT_PATHBUF.into();
    builder.finalize(de_info.remove(&root_pb).unwrap())?;

    Ok(())
}

fn push_all_children(
    stack: &mut Vec<Option<(PathBuf, usize)>>,
    path: &Path,
    father_idx: usize
) -> FsResult<()> {
    if io_try!(fs::symlink_metadata(path)).is_dir() {
        for p in io_try!(fs::read_dir(path)) {
            stack.push(Some((io_try!(p).path(), father_idx)));
        }
    }
    Ok(())
}

fn push_child_info(
    map: &mut HashMap<PathBuf, Vec<ChildInfo>>,
    fpb: &PathBuf,
    child_info: ChildInfo,
) {
    if let Some(child) = map.get_mut(fpb) {
        child.push(child_info);
    } else {
        map.insert(fpb.clone(), vec![child_info]);
    }
}

fn write_vec_as_bytes<T>(f: &mut File, v: &Vec<T>) -> FsResult<()> {
    io_try!(f.write_all(
        unsafe {
            std::slice::from_raw_parts(
                v.as_ptr() as *const u8,
                v.len() * size_of::<T>()
            )
        }
    ));
    Ok(())
}

fn seek_and_write(f: &mut File, seek: u64, b: &[u8]) -> FsResult<()> {
    if io_try!(f.seek(SeekFrom::Start(seek))) != seek {
        return Err(FsError::NotSeekable);
    }

    io_try!(f.write_all(b));
    Ok(())
}

fn get_file_sz(f: &mut File) -> FsResult<u64> {
    Ok(io_try!(f.seek(SeekFrom::Current(0))))
}

#[derive(Default, Clone)]
struct DirEntryRaw {
    hash: u64,
    ipos: u64,
    len: u16,
    tp: u16,
    name: OsString,
}

struct ROBuilder {
    mode: FSMode,
    image: File,
    itbl: File,
    ptbl: File,
    dtbl: File,
    dtbl_next_blk: usize,
    data: File,
    kdk: (Key128, u64),
    key_gen_counter: u64,
    next_inode: InodeID,
    root_inode_max_sz: u16,
}

impl ROBuilder {
    fn new(
        to: File,
        mut to_dir: PathBuf,
        root_dir_nr_entry: usize,
        mode: FSMode,
    ) -> FsResult<Self> {
        // open meta temp file and data temp file
        to_dir.push(".inode.eccfs");
        let itbl = io_try!(OpenOptions::new().write(true).create_new(true).open(&to_dir));
        to_dir.pop();
        to_dir.push(".dirent.eccfs");
        let dtbl = io_try!(OpenOptions::new().write(true).create_new(true).open(&to_dir));
        to_dir.pop();
        to_dir.push(".path.eccfs");
        let ptbl = io_try!(OpenOptions::new().write(true).create_new(true).open(&to_dir));
        to_dir.pop();
        to_dir.push(".data.eccfs");
        let data = io_try!(OpenOptions::new().write(true).create_new(true).open(&to_dir));

        // init kdk
        let mut kdk = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut kdk);

        // estimate root inode size
        let (nr_idx, _) = Self::estimate_idx(root_dir_nr_entry);
        let root_inode_max_sz: u16 = (size_of::<DInodeDirBase>()
                            + size_of::<EntryIndex>() * nr_idx) as u16;

        Ok(Self {
            mode,
            image: to,
            itbl,
            dtbl,
            dtbl_next_blk: 0,
            ptbl,
            data,
            kdk: (kdk, 0),
            key_gen_counter: 0,
            next_inode: 0,
            root_inode_max_sz,
        })
    }

    // estimate max_nr_idx and min_group_len
    fn estimate_idx(nr_de: usize) -> (usize, usize) {
        let mut nr_idx = nr_de.div_ceil(MAX_ENTRY_GROUP_LEN);
        // if only 1 idx is needed, we don't need any index
        if nr_idx == 0 {
            return (0, 0);
        } else if nr_idx == 1 {
            nr_idx = 0;
        }
        (nr_idx, nr_de / nr_idx)
    }

    fn jump_over_root_inode(&self, pos: u64, off: u16) -> (u64, u16) {
        if pos == 1 && off < self.root_inode_max_sz {
            // jump over root_inode at blk 1
            (1, self.root_inode_max_sz)
        } else {
            (pos, off)
        }
    }
    fn write_inode(&mut self, inode: &[u8]) -> FsResult<InodeID> {
        assert_eq!(inode.len() % INODE_ALIGN, 0);

        let (mut pos, mut off) = iid_split(self.next_inode);
        if BLK_SZ - off as usize % BLK_SZ > inode.len() {
            // not enough space in current block, move to next
            (pos, off) = self.jump_over_root_inode(pos + 1, 0);
        }

        seek_and_write(
            &mut self.itbl,
            pos * BLK_SZ as u64 + off as u64,
            inode,
        )?;

        let ret = iid_join(pos, off);

        // set new next_inode
        off += inode.len() as u16;
        pos += off as u64 / BLK_SZ as u64;
        off %= BLK_SZ as u16;
        (pos, off) = self.jump_over_root_inode(pos, off);
        self.next_inode = iid_join(pos, off);

        Ok(ret)
    }

    fn write_root_inode(&mut self, rinode: &[u8]) -> FsResult<()> {
        seek_and_write(
            &mut self.itbl,
            1 * BLK_SZ as u64 + self.root_inode_max_sz as u64,
            rinode,
        )
    }

    fn gen_inode_tp(pb: &PathBuf) -> FsResult<FileType> {
        let m = io_try!(fs::symlink_metadata(pb));
        Ok(if m.is_file() {
            FileType::Reg
        } else if m.is_dir() {
            FileType::Dir
        } else if m.is_symlink() {
            FileType::Lnk
        } else {
            panic!("Unsupported file type!");
        })
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

    fn gen_short_name(v: &[u8], threshold: usize) -> FsResult<Vec<u8>> {
        assert!(v.len() <= threshold);
        let mut ret = vec![0u8; threshold];
        let mut writer: &mut [u8] = ret.as_mut_slice();
        let written = io_try!(writer.write(v));
        assert_eq!(written, v.len());
        Ok(ret)
    }

    fn handle_long_path(&mut self, path: &[u8], threshold: usize) -> FsResult<Vec<u8>> {
        if path.len() > threshold {
            // write to ptbl
            let pos = io_try!(self.ptbl.seek(SeekFrom::Current(0)));
            io_try!(self.ptbl.write_all(path));
            Self::gen_short_name(&pos.to_le_bytes(), threshold)
        } else {
            Self::gen_short_name(path, threshold)
        }
    }

    fn write_dir_entries(
        &mut self,
        mytp: FileType,
        de_list_raw: Vec<DirEntryRaw>
    ) -> FsResult<(u32, u64, u64)> {
        // seek to next block
        let next = (self.dtbl_next_blk * BLK_SZ) as u64;
        if io_try!(self.dtbl.seek(SeekFrom::Start(next))) != next {
            return Err(FsError::NotSeekable);
        }
        let data_start = self.dtbl_next_blk;
        let nr_de = de_list_raw.len() + 2;

        // write dot and dotdot first
        let dots = vec![
            DirEntry {
                hash: 0,
                ipos: 0, // pending
                len: 1,
                tp: mytp.into(),
                name: Self::gen_short_name(
                        ".".as_bytes(),
                        DE_MAX_INLINE_NAME,
                    )?.try_into().unwrap(),
            },
            DirEntry {
                hash: 0,
                ipos: 0, // pending
                len: 2,
                tp: FileType::Dir.into(),
                name: Self::gen_short_name(
                        "..".as_bytes(),
                        DE_MAX_INLINE_NAME,
                    )?.try_into().unwrap(),
            },
        ];
        write_vec_as_bytes(&mut self.dtbl, &dots)?;

        // write all dir entries
        let mut de_list = Vec::with_capacity(de_list_raw.len());
        for de_raw in de_list_raw {
            assert!(de_raw.name.len() <= u16::MAX as usize);
            de_list.push(DirEntry {
                hash: de_raw.hash,
                ipos: de_raw.ipos,
                len: de_raw.name.len() as u16,
                tp: de_raw.tp,
                name: self.handle_long_path(
                        de_raw.name.as_encoded_bytes(),
                        DE_MAX_INLINE_NAME,
                    )?.try_into().unwrap(),
            });
        }
        write_vec_as_bytes(&mut self.dtbl, &de_list)?;

        // move to next block
        self.dtbl_next_blk += (
            size_of::<DirEntry>() * nr_de
        ).div_ceil(BLK_SZ);

        // return data_start and dotdot position(in bytes of the whole de_tbl)
        // and dot position(in bytes of the whole de_tbl) of its own dir entries
        Ok((
            data_start as u32,
            (data_start * BLK_SZ + size_of::<DirEntry>() + 8) as u64,
            (data_start * BLK_SZ + 8) as u64
        ))
    }

    fn handle_dir(
        &mut self,
        path: &PathBuf,
        child_info: Vec<ChildInfo>,
    ) -> FsResult<(InodeID, u64)> {

        let mut dotdot_list = Vec::new();
        for (_, tp, _, dotdot) in child_info.iter() {
            if let Some(dotdot) = dotdot {
                assert!(*tp == FileType::Dir);
                dotdot_list.push(*dotdot);
            }
        }

        let mut de_raw_list: Vec<DirEntryRaw> = child_info.into_iter().map(
            |(name, tp, iid, _)| {
                let name = name.into_os_string();
                assert!(name.len() < u16::MAX as usize);
                DirEntryRaw {
                    hash: half_md4(name.as_os_str().as_encoded_bytes()).unwrap(),
                    ipos: iid,
                    len: name.len() as u16,
                    tp: tp.into(),
                    name,
                }
            }
        ).collect();
        de_raw_list.sort_by(
            |a, b| {
                // compare dir entry with hash first, then name
                if a.hash < b.hash {
                    Ordering::Less
                } else if a.hash > b.hash {
                    Ordering::Greater
                } else if a.name < b.name {
                    Ordering::Less
                } else if a.name > b.name {
                    Ordering::Greater
                } else {
                    Ordering::Equal
                }
            }
        );

        // generting entry index
        let mut deidx: Vec<EntryIndex> = Vec::new();
        let (max_nr_deidx, min_grp_len) = Self::estimate_idx(de_raw_list.len());
        if max_nr_deidx != 0 {
            let mut cur = 0;
            while cur < de_raw_list.len() {
                // find next idx point
                let grp_start = cur;
                cur += min_grp_len;
                if cur >= de_raw_list.len() {
                    cur = de_raw_list.len()
                }
                // include all following entries with same hash
                let same_hash = de_raw_list.get(cur - 1).unwrap().hash;
                while cur < de_raw_list.len() {
                    if de_raw_list.get(cur).unwrap().hash != same_hash {
                        break;
                    }
                    cur += 1;
                }
                // grp_start .. cur is a group
                deidx.push(EntryIndex {
                    hash: de_raw_list.get(grp_start).unwrap().hash,
                    position: grp_start as u32 + 2,
                    group_len: (cur - grp_start) as u32,
                });
            }
        }

        // write dir entries
        let inode_base_size = de_raw_list.len() as u64;
        let (data_start, dotdot, self_dot)
            = self.write_dir_entries(Self::gen_inode_tp(path)?, de_raw_list)?;

        // dinode dir base
        let mut dinode_base = Self::gen_inode_base(path)?;
        // for dir inodes, size represents entry num
        dinode_base.size = inode_base_size;
        let dir_base = DInodeDirBase {
            base: dinode_base,
            data_start,
            nr_idx: deidx.len() as u32,
            _padding: 0,
        };

        // combine to parts of dinodedir to u8 slice, then write
        let mut dinode_bytes = Vec::with_capacity(
            size_of::<DInodeDirBase>() + deidx.len() * size_of::<EntryIndex>()
        );
        dinode_bytes.extend_from_slice(dir_base.as_ref());
        dinode_bytes.extend_from_slice(
            unsafe {
                std::slice::from_raw_parts(
                    deidx.as_ptr() as *const u8,
                    deidx.len() * size_of::<EntryIndex>()
                )
            }
        );
        let iid = self.write_inode(dinode_bytes.as_slice())?;

        // write this INodeID as all dir children's '..' and its own '.'
        dotdot_list.push(self_dot);
        for dd in dotdot_list {
            seek_and_write(
                &mut self.dtbl,
                dd,
                unsafe {
                    std::slice::from_raw_parts(
                        &iid as *const u64 as *const u8,
                        size_of_val(&iid),
                    )
                },
            )?;
        }

        // return this inode's iid and it's byte position of dotdot InodeID
        Ok((iid, dotdot))
    }

    fn handle_reg(&mut self, path: &PathBuf) -> FsResult<InodeID> {
        let dinode_base = Self::gen_inode_base(path)?;

        let data_start = get_file_sz(&mut self.data)?;

        // generate hash tree
        let mut f = io_try!(OpenOptions::new().read(true).open(path));

        let (nr_blk, keys) = build_htree(&mut self.data, &mut f, self.mode.is_encrypted())?;

        let dinode_reg = DInodeReg {
            base: dinode_base,
            crypto_blob: keys,
            data_start,
            data_len: nr_blk as u64,
        };
        let iid = self.write_inode(dinode_reg.as_ref())?;
        Ok(iid)
    }

    fn handle_sym(&mut self, path: &PathBuf) -> FsResult<InodeID> {
        let mut dinode_base = Self::gen_inode_base(path)?;

        // for symlnk inodes, size represents sym name length
        let target = io_try!(fs::read_link(path));
        dinode_base.size = target.as_os_str().as_encoded_bytes().len() as u64;

        let dinode_sym = DInodeLnk {
            base: dinode_base,
            name: self.handle_long_path(
                target.as_os_str().as_encoded_bytes(),
                DI_LNK_MAX_INLINE_NAME,
            )?.try_into().unwrap(),
        };

        let iid = self.write_inode(dinode_sym.as_ref())?;
        Ok(iid)
    }

    fn finalize(&mut self, root_child_info: Vec<ChildInfo>) -> FsResult<()> {
        // create and write root inode
        // round all file sizes up to multiple of BLK_SZ
        // write superblock to image file
        // filter all meta files through hash tree, append to image file
        // filter all reg files through hash tree, append to image file
        Ok(())
    }
}

fn build_htree(
    to: &mut File,
    from: &mut File,
    encrypted: bool,
) -> FsResult<(usize, KeyEntry)> {
    // return size of htree in block, root block keys
    Ok((0, [0u8; 32]))
}
