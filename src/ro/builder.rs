use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use crate::*;
use std::fs::{OpenOptions, self, File};
use crate::crypto::*;
use rand_core::RngCore;
use crate::vfs::*;
use super::*;
use std::mem::{size_of_val, size_of};
use super::disk::*;
use super::superblock::*;
use std::collections::HashMap;
use std::ffi::OsString;
use std::cmp::Ordering;
use std::os::unix::fs::MetadataExt;
use std::io::Write;


const MAX_ENTRY_GROUP_LEN: usize = 16;

#[derive(Clone, Debug)]
enum DotDotPos {
    InodeTable(u64),
    DirEntryTable(u64),
}

type ChildInfo = (PathBuf, FileType, InodeID, Option<DotDotPos>);

/// build a rofs image named [`to`] from all files under [`from`]
pub fn build_from_dir(
    from: &Path,
    to: &Path,
    encrypted: Option<Key128>,
) -> FsResult<FSMode> {
    // check to
    if to.exists() {
        return Err(new_error!(FsError::AlreadyExists));
    }
    let image = io_try!(OpenOptions::new().write(true).create_new(true).open(to));

    // check from
    if !io_try!(fs::metadata(from)).is_dir() {
        return Err(new_error!(FsError::NotADirectory));
    }

    // prepare
    let mut to_dir = to.to_path_buf();
    assert!(to_dir.pop());

    let mut builder = ROBuilder::new(
        image,
        to_dir,
        io_try!(fs::read_dir(from)).count(),
        encrypted.clone(),
    )?;
    let mut ht_builder = HTreeBuilder::new(encrypted.is_some())?;

    // stack holds full paths
    let mut stack = vec![Some((from.to_path_buf(), 0usize))];
    // de_info maps full path to children, holding child names, not full paths
    let mut de_info = HashMap::new();
    assert!(de_info.insert(from.to_path_buf(), Vec::new()).is_none());
    push_all_children(&mut stack, from, 0)?;

    // travel file tree in post order
    // we don't use recursion but iteration by a stack
    while stack.len() > 1 {
        if let Some((pb, fidx)) = stack.pop().unwrap() {
            let father_idx = stack.len();
            stack.push(Some((pb.clone(), fidx)));
            stack.push(None);
            assert!(de_info.insert(pb.clone(), Vec::new()).is_none());
            push_all_children(&mut stack, pb.as_path(), father_idx)?;
        } else {
            let (pb, fidx) = stack.pop().unwrap().unwrap();
            // access this node
            let m = io_try!(fs::symlink_metadata(&pb));
            let fpb = &stack.get(fidx).unwrap().as_ref().unwrap().0;
            if m.is_dir() {
                let child_info = de_info.remove(&pb).unwrap();
                let (iid, dotdot) = builder.handle_dir(&pb, child_info, false)?;
                push_child_info(
                    &mut de_info,
                    fpb,
                    (
                        pb.file_name().unwrap().to_os_string().into(),
                        FileType::Dir, iid, Some(dotdot)
                    )
                );
            } else if m.is_file() {
                let iid = builder.handle_reg(&pb, &mut ht_builder)?;
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

    // create and write root inode
    let root_pb: PathBuf = from.to_path_buf();
    let (root_iid, _) = builder.handle_dir(
        &root_pb,
        de_info.remove(&root_pb).unwrap(),
        true,
    )?;
    assert_eq!(root_iid, ROOT_INODE_ID);

    // complete image conversion
    let ret = builder.finalize()?;

    Ok(ret)
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
    map.get_mut(fpb).unwrap().push(child_info);
}


#[derive(Default, Clone)]
struct DirEntryRaw {
    hash: u64,
    ipos: u64,
    tp: u16,
    name: OsString,
}

struct ROBuilder {
    encrypted: Option<Key128>,
    image: File,
    itbl: File,
    itbl_path: PathBuf,
    dtbl: File,
    dtbl_path: PathBuf,
    ptbl: File,
    ptbl_path: PathBuf,
    data: File,
    data_path: PathBuf,
    next_inode: InodeID,
    root_inode_max_sz: u16,
    files: u64,
}

const ITBL_TEMP_FILE: &str = ".inode.eccfs";
const DTBL_TEMP_FILE: &str = ".dirent.eccfs";
const PTBL_TEMP_FILE: &str = ".path.eccfs";
const DATA_TEMP_FILE: &str = ".data.eccfs";

impl ROBuilder {
    fn new(
        to: File,
        mut to_dir: PathBuf,
        root_dir_nr_entry: usize,
        encrypted: Option<Key128>,
    ) -> FsResult<Self> {
        // open meta temp file and data temp file
        // inode table
        to_dir.push(ITBL_TEMP_FILE);
        let itbl_path = to_dir.clone();
        let itbl = io_try!(OpenOptions::new()
                            .read(true).write(true).create_new(true)
                            .open(&to_dir));
        to_dir.pop();
        // dirent table
        to_dir.push(DTBL_TEMP_FILE);
        let dtbl_path = to_dir.clone();
        let dtbl = io_try!(OpenOptions::new()
                            .read(true).write(true).create_new(true)
                            .open(&to_dir));
        to_dir.pop();
        // path table
        to_dir.push(PTBL_TEMP_FILE);
        let ptbl_path = to_dir.clone();
        let ptbl = io_try!(OpenOptions::new()
                            .read(true).write(true).create_new(true)
                            .open(&to_dir));
        to_dir.pop();
        // data
        to_dir.push(DATA_TEMP_FILE);
        let data_path = to_dir.clone();
        let data = io_try!(OpenOptions::new()
                            .read(true).write(true).create_new(true)
                            .open(&to_dir));

        // estimate root inode size
        let root_inode_max_sz = if root_dir_nr_entry as u64 <= DE_INLINE_MAX {
            // inline de
            (size_of::<DInodeBase>()
                + size_of::<DirEntry>() * (root_dir_nr_entry + 2)) as u16
        } else {
            let (nr_idx, _) = Self::estimate_idx(root_dir_nr_entry);
            (size_of::<DInodeDirBaseNoInline>()
                + size_of::<EntryIndex>() * nr_idx) as u16
        };
        assert_eq!(root_inode_max_sz as usize % INODE_ALIGN, 0);

        Ok(Self {
            encrypted,
            image: to,
            itbl,
            itbl_path,
            dtbl,
            dtbl_path,
            ptbl,
            ptbl_path,
            data,
            data_path,
            // inode 0 means null inode, we should jump over it
            next_inode: pos64_join(0, INODE_ALIGN as u16),
            root_inode_max_sz,
            files: 0,
        })
    }

    // estimate max_nr_idx and min_group_len
    fn estimate_idx(nr_de: usize) -> (usize, usize) {
        let mut nr_idx = nr_de.div_ceil(MAX_ENTRY_GROUP_LEN);
        // if only 1 idx is needed, we don't need any index
        if nr_idx == 1 {
            nr_idx = 0;
        }

        if nr_idx == 0 {
            (0, 0)
        } else {
            (nr_idx, nr_de.div_ceil(nr_idx))
        }
    }

    fn jump_over_root_inode(&self, pos: u64, off: u16, sz: usize) -> (u64, u16) {
        // every pos and off is filter by this funciton,
        // so they can not be inside root_inode
        assert!(!(pos == 1 && off < self.root_inode_max_sz));
        if pos == 0 && off as usize + sz > BLK_SZ {
            (1, self.root_inode_max_sz)
        } else {
            (pos, off)
        }
    }

    fn write_inode(&mut self, inode: &[u8], is_root: bool) -> FsResult<InodeID> {
        if is_root {
            assert!(inode.len() <= self.root_inode_max_sz as usize);
            write_file_at(
                &mut self.itbl,
                blk2byte!(1),
                inode,
            )?;
            return Ok(ROOT_INODE_ID);
        }

        assert_eq!(inode.len() % INODE_ALIGN, 0);

        let (mut pos, mut off) = pos64_split(self.next_inode);
        (pos, off) = self.jump_over_root_inode(pos, off, inode.len());

        write_file_at(
            &mut self.itbl,
            pos64_to_byte(pos, off),
            inode,
        )?;

        let ret = pos64_join(pos, off);

        // set new next_inode
        (pos, off) = pos64_add((pos, off), inode.len() as u64);
        self.next_inode = pos64_join(pos, off);

        Ok(ret)
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
            let pos = get_file_pos(&mut self.ptbl)?;
            io_try!(self.ptbl.write_all(path));
            Self::gen_short_name(&pos.to_le_bytes(), threshold)
        } else {
            Self::gen_short_name(path, threshold)
        }
    }

    fn gen_dir_entries(
        &mut self,
        mytp: FileType,
        de_list_raw: Vec<DirEntryRaw>
    ) -> FsResult<Vec<DirEntry>> {

        // generate dot and dotdot first
        let mut de_list = Vec::with_capacity(de_list_raw.len() + 2);
        de_list.push(
            DirEntry {
                hash: 0,
                ipos: 0, // pending
                len: 1,
                tp: mytp.into(),
                name: Self::gen_short_name(
                        ".".as_bytes(),
                        DE_MAX_INLINE_NAME,
                    )?.try_into().unwrap(),
            }
        );
        de_list.push(
            DirEntry {
                hash: 0,
                ipos: 0, // pending
                len: 2,
                tp: FileType::Dir.into(),
                name: Self::gen_short_name(
                        "..".as_bytes(),
                        DE_MAX_INLINE_NAME,
                    )?.try_into().unwrap(),
            }
        );

        // write all dir entries
        for de_raw in de_list_raw {
            assert!(de_raw.name.len() <= NAME_MAX as usize);
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

        Ok(de_list)
    }

    fn write_dir_entries(
        &mut self,
        mytp: FileType,
        de_list_raw: Vec<DirEntryRaw>
    ) -> FsResult<(u64, u64, u64)> {

        let de_start_raw = get_file_pos(&mut self.dtbl)?;
        assert!(de_start_raw as usize % size_of::<DirEntry>() == 0);
        let de_start_pos = de_start_raw / BLK_SZ as u64;
        let de_start_off = de_start_raw % BLK_SZ as u64;

        let de_list = self.gen_dir_entries(mytp, de_list_raw)?;

        write_vec_as_bytes(&mut self.dtbl, &de_list)?;

        // return de_start(pos64) and dotdot position(in bytes of the whole de_tbl)
        // and dot position(in bytes of the whole de_tbl) of its own dir entries
        Ok((
            pos64_join(de_start_pos, de_start_off as u16),
            de_start_raw + size_of::<DirEntry>() as u64 + 8,
            de_start_raw + 8
        ))
    }

    fn gen_entry_idx(de_list_raw: &Vec<DirEntryRaw>) -> Vec<EntryIndex> {
        assert!(de_list_raw.len() > DE_INLINE_MAX as usize);

        let mut deidx: Vec<EntryIndex> = Vec::new();
        let (max_nr_deidx, min_grp_len) = Self::estimate_idx(de_list_raw.len());
        if max_nr_deidx != 0 {
            let mut cur = 0;
            while cur < de_list_raw.len() {
                // find next idx point
                let grp_start = cur;
                cur += min_grp_len;
                if cur >= de_list_raw.len() {
                    cur = de_list_raw.len()
                }
                // include all following entries with same hash
                let same_hash = de_list_raw.get(cur - 1).unwrap().hash;
                while cur < de_list_raw.len() {
                    if de_list_raw.get(cur).unwrap().hash != same_hash {
                        break;
                    }
                    cur += 1;
                }
                // grp_start .. cur is a group
                deidx.push(EntryIndex {
                    hash: de_list_raw.get(grp_start).unwrap().hash,
                    position: grp_start as u32 + 2,
                    group_len: (cur - grp_start) as u32,
                });
            }
        }

        deidx
    }

    fn handle_dir(
        &mut self,
        path: &PathBuf,
        child_info: Vec<ChildInfo>,
        is_root: bool,
    ) -> FsResult<(InodeID, DotDotPos)> {

        let mut dotdot_list = Vec::new();
        for (_, tp, _, dotdot) in child_info.iter() {
            if let Some(dotdot) = dotdot {
                assert!(*tp == FileType::Dir);
                dotdot_list.push(dotdot.clone());
            }
        }

        let mut de_list_raw: Vec<DirEntryRaw> = child_info.into_iter().map(
            |(name, tp, iid, _)| {
                let name = name.into_os_string();
                assert!(name.len() < NAME_MAX as usize);
                DirEntryRaw {
                    hash: half_md4(name.as_os_str().as_encoded_bytes()).unwrap(),
                    ipos: iid,
                    tp: tp.into(),
                    name,
                }
            }
        ).collect();
        de_list_raw.sort_by(
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

        // dinode dir base
        let mut dinode_base = Self::gen_inode_base(path)?;
        // // root inode nlink is always 1
        // if is_root {
        //     dinode_base.nlinks = 1;
        // }

        // for dir inodes, size represents entry num without . and ..
        let inode_base_size = de_list_raw.len() as u64;
        dinode_base.size = inode_base_size;

        let (dinode_bytes, dot) = if de_list_raw.len() <= DE_INLINE_MAX as usize {
            // inline de
            let de_list = self.gen_dir_entries(Self::gen_inode_tp(path)?, de_list_raw)?;

            // combine to parts of dinodedir to u8 slice
            let de_list_raw_sz = de_list.len() * size_of::<DirEntry>();
            let mut dinode_bytes = Vec::with_capacity(
                size_of::<DInodeBase>() + de_list_raw_sz
            );
            dinode_bytes.extend_from_slice(dinode_base.as_ref());
            dinode_bytes.extend_from_slice(
                unsafe {
                    std::slice::from_raw_parts(
                        de_list.as_ptr() as *const u8,
                        de_list_raw_sz,
                    )
                }
            );
            (dinode_bytes, None)
        } else {
            // generting entry index
            let deidx = Self::gen_entry_idx(&de_list_raw);
            // write dir entries
            let (de_list_start, dotdot, self_dot)
                = self.write_dir_entries(Self::gen_inode_tp(path)?, de_list_raw)?;

            let dir_base = DInodeDirBaseNoInline {
                base: dinode_base,
                de_list_start,
                nr_idx: deidx.len() as u32,
                _padding: 0,
            };
            // combine to parts of dinodedir to u8 slice
            let mut dinode_bytes = Vec::with_capacity(
                size_of::<DInodeDirBaseNoInline>() + deidx.len() * size_of::<EntryIndex>()
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
            (dinode_bytes, Some((dotdot, self_dot)))
        };

        let iid = self.write_inode(dinode_bytes.as_slice(), is_root)?;

        // write this INodeID as all dir children's '..' and its own '.'
        let ret = if let Some((dotdot, self_dot)) = dot {
            // no inline de
            dotdot_list.push(DotDotPos::DirEntryTable(self_dot));
            if is_root {
                // root inode's dotdot is itself
                dotdot_list.push(DotDotPos::DirEntryTable(dotdot));
            }
            (iid, DotDotPos::DirEntryTable(dotdot))
        } else {
            // inline de
            let (pos, off) = pos64_split(iid);
            let di_inline_start =
                pos64_to_byte(pos, off)
                + size_of::<DInodeBase>() as u64;
            let dotdot = di_inline_start + size_of::<DirEntry>() as u64 + 8;
            let self_dot = di_inline_start + 8;

            dotdot_list.push(DotDotPos::InodeTable(self_dot));
            if is_root {
                // root inode's dotdot is itself
                dotdot_list.push(DotDotPos::InodeTable(dotdot));
            }
            (iid, DotDotPos::InodeTable(dotdot))
        };

        let iid_bytes = unsafe {
            std::slice::from_raw_parts(
                &iid as *const u64 as *const u8,
                size_of_val(&iid),
            )
        };
        for dd in dotdot_list {
            match dd {
                DotDotPos::DirEntryTable(pos) => {
                    write_file_at(
                        &mut self.dtbl,
                        pos,
                        iid_bytes,
                    )?;
                }
                DotDotPos::InodeTable(pos) => {
                    write_file_at(
                        &mut self.itbl,
                        pos,
                        iid_bytes,
                    )?;
                }
            }
        }

        // return this inode's iid and it's byte position of dotdot InodeID
        // if is_root == true, the second return value is useless
        Ok(ret)
    }

    fn handle_reg(&mut self, path: &PathBuf, ht: &mut HTreeBuilder) -> FsResult<InodeID> {
        let dinode_base = Self::gen_inode_base(path)?;

        let iid = if dinode_base.size <= DI_REG_INLINE_DATA_MAX {
            // inline data
            let inode_ext_sz = (dinode_base.size as usize).next_multiple_of(INODE_ALIGN);
            let mut dinode_bytes = Vec::with_capacity(
                size_of::<DInodeBase>() + inode_ext_sz
            );
            dinode_bytes.extend_from_slice(dinode_base.as_ref());

            // read all bytes from source file
            let mut f = io_try!(File::open(path));
            let mut buf = vec![0u8; inode_ext_sz];
            if io_try!(f.read(&mut buf)) != dinode_base.size as usize {
                return Err(new_error!(FsError::UnexpectedEof));
            }

            dinode_bytes.extend(&buf);
            self.write_inode(&dinode_bytes, false)?
        } else {
            let data_start = get_file_pos(&mut self.data)?;
            assert!(data_start % BLK_SZ as u64 == 0);

            // generate hash tree
            let (nr_blk, ke) = ht.build_htree(&mut self.data, path)?;

            let dinode_reg = DInodeReg {
                base: dinode_base,
                key_entry: ke,
                data_start: data_start / BLK_SZ as u64,
                data_len: nr_blk as u64,
            };
            self.write_inode(dinode_reg.as_ref(), false)?
        };

        self.files += 1;
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

        let iid = self.write_inode(dinode_sym.as_ref(), false)?;
        Ok(iid)
    }

    fn round_file_up_to_blk(f: &mut File) -> FsResult<u64> {
        let len = io_try!(f.seek(SeekFrom::End(0))).next_multiple_of(BLK_SZ as u64);
        io_try!(f.set_len(len));
        Ok(len / BLK_SZ as u64)
    }

    fn finalize(mut self) -> FsResult<FSMode> {
        // round all file sizes up to multiple of BLK_SZ
        let itbl_nr_blk = Self::round_file_up_to_blk(&mut self.itbl)?;
        let dtbl_nr_blk = Self::round_file_up_to_blk(&mut self.dtbl)?;
        let ptbl_nr_blk = Self::round_file_up_to_blk(&mut self.ptbl)?;
        let file_sec_len = get_file_pos(&mut self.data)?;
        assert!(file_sec_len % BLK_SZ as u64 == 0);
        let file_nr_blk = file_sec_len / BLK_SZ as u64;

        // jumpover superblock in image file
        io_try!(self.image.set_len(BLK_SZ as u64));
        if io_try!(self.image.seek(SeekFrom::End(0))) != BLK_SZ as u64 {
            return Err(new_error!(FsError::UnexpectedEof));
        }

        // filter all meta files through hash tree, append to image file
        let mut ht = HTreeBuilder::new(self.encrypted.is_some())?;
        // inode table
        debug!("Building itbl htree size {} blocks", itbl_nr_blk);
        let (itbl_htree_nr_blk, itbl_ke) = if itbl_nr_blk == 0 {
            (0, [0u8; size_of::<KeyEntry>()])
        } else {
            assert_eq!(io_try!(self.itbl.seek(SeekFrom::Start(0))), 0);
            ht.build_htree_file(
                &mut self.image, &mut self.itbl, itbl_nr_blk
            )?
        };
        // dirent table
        debug!("Building dtbl htree size {} blocks", dtbl_nr_blk);
        let (dtbl_htree_nr_blk, dtbl_ke) = if dtbl_nr_blk == 0 {
            (0, [0u8; size_of::<KeyEntry>()])
        } else {
            assert_eq!(io_try!(self.dtbl.seek(SeekFrom::Start(0))), 0);
            ht.build_htree_file(
                &mut self.image, &mut self.dtbl, dtbl_nr_blk
            )?
        };
        // path table
        debug!("Building ptbl htree size {} blocks", ptbl_nr_blk);
        let (ptbl_htree_nr_blk, ptbl_ke) = if ptbl_nr_blk == 0 {
            (0, [0u8; size_of::<KeyEntry>()])
        } else {
            assert_eq!(io_try!(self.ptbl.seek(SeekFrom::Start(0))), 0);
            ht.build_htree_file(
                &mut self.image, &mut self.ptbl, ptbl_nr_blk
            )?
        };

        // append data temp file to image file
        if file_nr_blk != 0 {
            assert_eq!(io_try!(self.data.seek(SeekFrom::Start(0))), 0);
            let copied = io_try!(std::io::copy(&mut self.data, &mut self.image));
            assert_eq!(copied, file_sec_len);
        }

        // write superblock to image file
        let itbl_htree_nr_blk = itbl_htree_nr_blk as u64;
        let dtbl_htree_nr_blk = dtbl_htree_nr_blk as u64;
        let ptbl_htree_nr_blk = ptbl_htree_nr_blk as u64;

        let mut sb_blk = [0u8; BLK_SZ];
        assert!(size_of::<DSuperBlock>() <= BLK_SZ);
        let dsb = unsafe {
            &mut *(sb_blk.as_mut_ptr() as *mut DSuperBlock)
        };
        *dsb = DSuperBlock {
            magic: ROFS_MAGIC,
            bsize: BLK_SZ as u64,
            files: self.files,
            namemax: NAME_MAX,
            inode_tbl_key: itbl_ke,
            dirent_tbl_key: dtbl_ke,
            path_tbl_key: ptbl_ke,
            inode_tbl_start: 1,
            inode_tbl_len: itbl_htree_nr_blk,
            dirent_tbl_start: 1 + itbl_htree_nr_blk,
            dirent_tbl_len: dtbl_htree_nr_blk,
            path_tbl_start: 1 + itbl_htree_nr_blk + dtbl_htree_nr_blk,
            path_tbl_len: ptbl_htree_nr_blk,
            file_sec_start: 1 + itbl_htree_nr_blk + dtbl_htree_nr_blk + ptbl_htree_nr_blk,
            file_sec_len: file_nr_blk,
            blocks: 1 + itbl_htree_nr_blk + dtbl_htree_nr_blk + ptbl_htree_nr_blk + file_nr_blk,
            encrypted: self.encrypted.is_some(),
        };

        let ret = crypto_out(&mut sb_blk, self.encrypted, SUPERBLOCK_POS)?;
        write_file_at(&mut self.image, 0, &sb_blk)?;

        // close files
        drop(self.image);
        drop(self.itbl);
        drop(self.dtbl);
        drop(self.ptbl);
        drop(self.data);
        // remove temp files
        io_try!(fs::remove_file(self.itbl_path));
        io_try!(fs::remove_file(self.dtbl_path));
        io_try!(fs::remove_file(self.ptbl_path));
        io_try!(fs::remove_file(self.data_path));

        Ok(ret)
    }
}

struct HTreeBuilder {
    key_gen: KeyGen,
    encrypted: bool,
}

impl HTreeBuilder {
    fn new(encrypted: bool) -> FsResult<Self> {
        // init kdk
        let mut kdk = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut kdk);

        Ok(Self {
            key_gen: KeyGen::new(),
            encrypted,
        })
    }

    fn crypto_process_blk(&mut self, blk: &mut Block, pos: u64) -> FsResult<KeyEntry> {
        let mode = crypto_out(blk,
            if self.encrypted {
                Some(self.key_gen.gen_key(pos)?)
            } else {
                None
            },
            pos
        )?;

        Ok(mode.into_key_entry())
    }

    fn build_htree(
        &mut self,
        to: &mut File,
        from: &PathBuf,
    ) -> FsResult<(usize, KeyEntry)> {
        // get file logical size
        let logi_nr_blk = io_try!(fs::symlink_metadata(from)).size().div_ceil(BLK_SZ as u64);
        // open source file
        let mut f = io_try!(OpenOptions::new().read(true).open(from));

        self.build_htree_file(to, &mut f, logi_nr_blk)
    }

    fn build_htree_file(
        &mut self,
        to: &mut File,
        from: &mut File,
        from_nr_blk: u64,
    ) -> FsResult<(usize, KeyEntry)> {
        let logi_nr_blk = from_nr_blk;
        assert!(logi_nr_blk > 0);

        // get the htree start (in blocks)
        let mut to_start_blk = get_file_pos(to)?;
        assert!(to_start_blk % BLK_SZ as u64 == 0);
        to_start_blk /= BLK_SZ as u64;
        let htree_nr_blk = mht::get_phy_nr_blk(logi_nr_blk);

        let mut idx_blk = [0u8; BLK_SZ] as Block;
        // map idx_phy_pos to its ke
        let mut idx_ke = HashMap::new();

        for logi_pos in (0..logi_nr_blk).rev() {
            // read plain data block, padding 0 to integral block
            let mut d = [0u8; BLK_SZ] as Block;
            let _read = read_file_at(from, blk2byte!(logi_pos), &mut d)?;
            // process crypto
            let phy_pos = mht::logi2phy(logi_pos);
            let ke = self.crypto_process_blk(&mut d, phy_pos)?;
            // write data block
            write_file_at(to, blk2byte!(to_start_blk + phy_pos), &d)?;

            // write ke to idx_blk
            let ke_idx = mht::logi2dataidx(logi_pos);
            mht::set_ke(
                &mut idx_blk,
                mht::Data(ke_idx),
                &ke,
            )?;

            // if the written ke is the first data ke (0) in the idx_blk,
            // all its data block ke have been filled.
            if ke_idx != 0 {
                continue;
            }

            // all data blk of the idx_blk are filled, now process idx_blk
            let idx_phy_pos = mht::phy2idxphy(phy_pos);
            // fill child ke
            let mut child_phy = mht::get_first_idx_child_phy(idx_phy_pos);
            for i in 0..mht::CHILD_PER_BLK {
                if let Some(ke) = idx_ke.remove(&child_phy) {
                    mht::set_ke(
                        &mut idx_blk,
                        mht::Index(i),
                        &ke,
                    )?;
                } else {
                    break;
                }
                child_phy = mht::next_idx_sibling_phy(child_phy);
            }
            // process crypto
            let ke = self.crypto_process_blk(&mut idx_blk, idx_phy_pos)?;
            // add this idx_blk ke to the hashmap, for use of its father
            assert!(idx_ke.insert(idx_phy_pos, ke).is_none());
            // write idx block
            write_file_at(to, blk2byte!(to_start_blk + idx_phy_pos), &idx_blk)?;
            // switch to a new idx block
            idx_blk = [0u8; BLK_SZ];
        }

        let root_ke = idx_ke.remove(&HTREE_ROOT_BLK_PHY_POS).unwrap();
        // if idx_ke.len() != 0 {
        //     debug!("idx_ke keys:");
        //     let mut l: Vec<_> = idx_ke.keys().map(
        //         |k| {
        //             (*k, mht::idxphy2number(*k))
        //         }
        //     ).collect();
        //     l.sort();
        //     debug!("{l:?}");
        // }
        assert!(idx_ke.is_empty());

        // seek to end of this htree
        let file_end = blk2byte!(to_start_blk + htree_nr_blk);
        assert_eq!(io_try!(to.seek(SeekFrom::End(0))), file_end);

        // return size of htree in block, root block keys
        Ok((htree_nr_blk as usize, root_ke))
    }
}

#[cfg(test)]
mod test {
    #[test]
    fn build_ro() {
        use std::path::Path;
        use crate::*;
        use std::fs::OpenOptions;
        use std::fs;
        use std::env;
        use std::io::prelude::*;
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
        debug!("Building ROFS {}", target);

        let from = format!("test/{}", &target);
        let to = format!("test/{}.roimage", &target);

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
