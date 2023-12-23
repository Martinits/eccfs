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
use std::mem::size_of;
use super::disk::*;
use std::collections::HashMap;
use std::ffi::OsString;
use std::cmp::Ordering;
use std::os::unix::fs::MetadataExt;


const MAX_ENTRY_GROUP_LEN: usize = 16;

type ChildInfo = (PathBuf, FileType, InodeID, Option<u64>);

/// build a rofs image named [`to`] from all files under [`from`]
pub fn build_from_dir(from: &Path, to: &Path) -> FsResult<()> {
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
    )?;

    // stack holds full paths
    let mut stack = vec![Some(("/".into(), 0usize))];
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

    // write root inode

    builder.finalize()?;

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

#[derive(Default, Clone)]
struct DirEntryRaw {
    hash: u64,
    ipos: u64,
    len: u16,
    tp: u16,
    name: OsString,
}

struct ROBuilder {
    image: File,
    itbl: File,
    ptbl: File,
    dtbl: File,
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
            image: to,
            itbl,
            dtbl,
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
        let (mut pos, mut off) = iid_split(self.next_inode);
        if BLK_SZ - off as usize % BLK_SZ > inode.len() {
            // not enough space in current block, move to next
            (pos, off) = self.jump_over_root_inode(pos + 1, 0);
        }

        let fpos = pos * BLK_SZ as u64 + off as u64;
        if io_try!(self.itbl.seek(SeekFrom::Start(fpos))) != fpos {
            return Err(FsError::NotSeekable);
        }

        io_try!(self.itbl.write_all(inode));

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
        let fpos = 1 * BLK_SZ as u64 + self.root_inode_max_sz as u64;
        if io_try!(self.itbl.seek(SeekFrom::Start(fpos))) != fpos {
            return Err(FsError::NotSeekable);
        }

        io_try!(self.itbl.write_all(rinode));

        Ok(())
    }

    fn gen_inode_base(&mut self, pb: &PathBuf) -> FsResult<DInodeBase> {
        let m = io_try!(fs::symlink_metadata(&pb));
        let tp = if m.is_file() {
            FileType::Reg
        } else if m.is_dir() {
            FileType::Dir
        } else if m.is_symlink() {
            FileType::Lnk
        } else {
            panic!("Unsupported file type!");
        };

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

    fn write_dir_entries(
        &mut self,
        de_list_raw: &Vec<DirEntryRaw>
    ) -> FsResult<(u32, u64)> {
        // write dot and dotdot first

        // return data_start and dotdot position(in bytes of the whole de_tbl)
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
        let (data_start, dotdot) = self.write_dir_entries(&de_raw_list)?;

        // dinode dir base
        let mut dinode_base = self.gen_inode_base(path)?;
        // for dir inodes, size represents entry num
        dinode_base.size = de_raw_list.len() as u64;
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

        // write this INodeID as all dir children's '..'
        for dd in dotdot_list {
            if io_try!(self.dtbl.seek(SeekFrom::Start(dd))) != dd {
                return Err(FsError::NotSeekable);
            }

            io_try!(self.dtbl.write_all(
                unsafe {
                    std::slice::from_raw_parts(&iid as *const u64 as *const u8, 8)
                }
            ));
        }

        // return this inode's iid and it's byte position of dotdot InodeID
        Ok((iid, dotdot))
    }

    fn handle_reg(&mut self, path: &PathBuf) -> FsResult<InodeID> {
        Ok(0)
    }

    fn handle_sym(&mut self, path: &PathBuf) -> FsResult<InodeID> {
        let mut dinode_base = self.gen_inode_base(path)?;
        // for symlnk inodes, size represents sym name length
        dinode_base.size = ;
        Ok(0)
    }

    fn finalize(&mut self) -> FsResult<()> {
        Ok(())
    }
}

struct HTreeBuilder {
    nr_blk: usize,

}

impl HTreeBuilder {
    fn new(nr_blk: usize) -> FsResult<Self> {
        Ok(Self {
            nr_blk,
        })
    }
}
