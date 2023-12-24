use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::time::{SystemTime, Duration};
use std::mem::size_of;
use crate::htree::*;
use crate::bcache::*;
use std::ffi::OsStr;
use crate::crypto::half_md4;

#[derive(Clone)]
pub enum LnkName {
    Short(String),
    Long(u64, usize), // (pos, length)
}

enum InodeExt {
    Reg {
        data_start: u64,
        data_len: u64,
        data: ROHashTree,
    },
    Dir {
        de_list_start: u64,
        idx_list: Vec<EntryIndex>,
    },
    Lnk(LnkName),
}

pub struct Inode {
    iid: InodeID,
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
        iid: InodeID,
        backend: ROCache,
        encrypted: bool,
        cache_data: bool,
    ) -> FsResult<Self> {
        // for now, inode cannot cross block
        // first make sure we can read a 2 byte mode
        let mode: u16 = unsafe {
            *(raw.as_ptr() as *const u16)
        };
        match get_ftype_from_mode(mode) {
            FileType::Reg => {
                assert!(size_of::<DInodeReg>() <= raw.len());
                let dinode = unsafe {
                    &*(raw.as_ptr() as *const DInodeReg)
                };
                let ibase = &dinode.base;
                Ok(Self {
                    iid,
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

                let idx_list = if dirent_num != 0 {
                    let idx_start = size_of::<DInodeDirBase>();
                    let idx_end = idx_start + dirent_num * size_of::<EntryIndex>();
                    assert!(idx_end <= raw.len());
                    Vec::from(unsafe {
                        std::slice::from_raw_parts(
                            raw[idx_start..].as_ptr() as *const EntryIndex,
                            dirent_num
                        )
                    })
                } else {
                    vec![]
                };

                let ibase = &dinode_base.base;
                Ok(Self {
                    iid,
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
                        de_list_start: dinode_base.de_list_start,
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
                    iid,
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
                            LnkName::Long(
                                u64::from_le_bytes(dinode.name[..8].try_into().unwrap()),
                                ibase.size as usize,
                            )
                        } else {
                            LnkName::Short(
                                std::str::from_utf8(
                                    dinode.name.split_at(ibase.size as usize).0
                                ).map_err(
                                    |_| FsError::InvalidData
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

    pub fn get_meta(&self) -> FsResult<Metadata> {
        Ok(Metadata {
            iid: self.iid,
            size: self.size as u64,
            blocks: self.size.div_ceil(BLK_SZ) as u64,
            atime: self.atime,
            ctime: self.ctime,
            mtime: self.mtime,
            ftype: self.tp,
            perm: self.perm.bits(),
            nlinks: self.nlinks,
            uid: self.uid,
            gid: self.gid,
        })
    }

    pub fn get_link(&self) -> FsResult<LnkName> {
        if let InodeExt::Lnk(ref lnk) = self.ext {
            Ok(lnk.clone())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    // return de_list_start(pos64), nr entry
    pub fn get_entry_list_info(&self) -> FsResult<(u64, usize)> {
        if let InodeExt::Dir{de_list_start, ..} = self.ext {
            Ok((de_list_start, self.size))
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    // return de_list_start(pos64), group_start(num of entry), group length
    pub fn lookup_index(&self, name: &OsStr) -> FsResult<Option<(u64, usize, usize)>> {
        if let InodeExt::Dir{ref idx_list, de_list_start} = self.ext {
            if idx_list.len() == 0 {
                // no idx, need to search from the first entry
                // 2 because first two are . and ..
                return Ok(Some((de_list_start, 2, self.size)))
            }
            let hash = half_md4(name.as_encoded_bytes())?;
            if hash < idx_list[0].hash {
                // hash is smaller than smallest(first) idx, so it doesn't exist
                Ok(None)
            } else if let Some(EntryIndex{position, group_len, ..}) = idx_list.iter().find(
                |&ent| hash >= ent.hash
            ) {
                Ok(Some((de_list_start, *position as usize, *group_len as usize)))
            } else {
                Err(FsError::IncompatibleMetadata)
            }
        } else {
            Err(FsError::PermissionDenied)
        }
    }
}
