use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::sync::Arc;
use std::time::{SystemTime, Duration};
use std::mem::size_of;
use crate::htree::*;
use crate::bcache::*;

pub enum LnkNameType {
    Short(String),
    Long(u64),
}

enum InodeExt {
    Reg {
        data_start: u64,
        data_len: u64,
        data: ROHashTree,
    },
    Dir {
        data_start: u32,
        idx_list: Vec<EntryIndex>,
    },
    Lnk(LnkNameType), // link name
}

pub struct Inode {
    tp: FileType,
    perm: FilePerm,
    nlinks: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    ctime: SystemTime,
    mtime: SystemTime,
    size: usize,
    ext: InodeExt,
}

impl Inode {
    pub fn new_from_raw(
        raw: &[u8],
        backend: ROCache,
        encrypted: bool,
        cache_data: bool,
    ) -> FsResult<Self> {
        // for now, inode cannot cross block
        // first make sure we can read a 2 byte mode
        let mode: u16 = unsafe {
            *(raw.as_ptr() as *const u16)
        };
        match super::disk::get_ftype_from_mode(mode) {
            FileType::Reg => {
                assert!(size_of::<DInodeReg>() <= raw.len());
                let dinode = unsafe {
                    &*(raw.as_ptr() as *const DInodeReg)
                };
                let ibase = &dinode.base;
                Ok(Self {
                    tp: FileType::Reg,
                    perm: get_perm_from_mode(ibase.mode),
                    nlinks: ibase.nlinks,
                    uid: ibase.uid,
                    gid: ibase.gid,
                    atime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.atime as u64),
                    ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.ctime as u64),
                    mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.mtime as u64),
                    size: ibase.size as usize,
                    ext: InodeExt::Reg {
                        data_start: dinode.data_start,
                        data_len: dinode.data_len,
                        data: ROHashTree::new(
                            backend, dinode.data_start, dinode.data_len,
                            FSMode::from_key_entry(dinode.crypto_blob, encrypted), cache_data,
                        )
                    },
                })
            }
            FileType::Dir=> {
                assert!(size_of::<DInodeDirBase>() <= raw.len());
                let dinode_base = unsafe {
                    &*(raw.as_ptr() as *const DInodeDirBase)
                };

                let dirent_num = dinode_base.base.size as usize;
                let idx_start = size_of::<DInodeDirBase>();
                let idx_end = idx_start + dirent_num * size_of::<EntryIndex>();
                assert!(idx_end <= raw.len());

                let idx_list = Vec::from(unsafe {
                    std::slice::from_raw_parts(
                        raw[idx_start..].as_ptr() as *const EntryIndex,
                        dirent_num
                    )
                });

                let ibase = &dinode_base.base;
                Ok(Self {
                    tp: FileType::Dir,
                    perm: get_perm_from_mode(ibase.mode),
                    nlinks: ibase.nlinks,
                    uid: ibase.uid,
                    gid: ibase.gid,
                    atime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.atime as u64),
                    ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.ctime as u64),
                    mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.mtime as u64),
                    size: ibase.size as usize,
                    ext: InodeExt::Dir {
                        data_start: dinode_base.data_start,
                        idx_list,
                    }
                })
            }
            FileType::Lnk => {
                assert!(size_of::<DInodeDirBase>() <= raw.len());
                let dinode = unsafe {
                    &*(raw.as_ptr() as *const DInodeLnk)
                };
                let ibase = &dinode.base;
                Ok(Self {
                    tp: FileType::Lnk,
                    perm: get_perm_from_mode(ibase.mode),
                    nlinks: ibase.nlinks,
                    uid: ibase.uid,
                    gid: ibase.gid,
                    atime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.atime as u64),
                    ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.ctime as u64),
                    mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(ibase.mtime as u64),
                    size: ibase.size as usize,
                    ext: InodeExt::Lnk(
                        if ibase.size > 32 {
                            LnkNameType::Long(
                                u64::from_le_bytes(dinode.name[..8].try_into().unwrap())
                            )
                        } else {
                            LnkNameType::Short(
                                std::str::from_utf8(
                                    dinode.name.split_at(ibase.size as usize).0
                                ).map_err(
                                    |_| FsError::UnknownError
                                )?.into()
                            )
                        }
                    )
                })
            }
        }
    }

    pub fn read_data(&self, mut offset: usize, to: &mut [u8]) -> FsResult<usize> {
        if let InodeExt::Reg { ref data, .. } = self.ext {
            let total = to.len();
            let mut done = 0;
            while done < total {
                let ablk = data.get_blk(( offset / BLK_SZ ) as u64)?;
                let round = (total - done).min(BLK_SZ - offset % BLK_SZ);
                let start = offset % BLK_SZ;
                to[offset..offset+round].copy_from_slice(&ablk[start..start+round]);
                done += round;
                offset += round;
            }
            Ok(done)
        } else {
            Err(FsError::PermissionDenied)
        }
    }
}
