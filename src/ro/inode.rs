use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::time::{SystemTime, Duration};
use std::mem::size_of;
use crate::htree::*;
use crate::bcache::*;
use std::ffi::OsStr;
use crate::crypto::half_md4;

pub enum DirEntryInfo<'a> {
    Inline(&'a Vec<DirEntry>),
    External(u64, usize),
}

pub enum LookUpInfo<'a> {
    NonExistent,
    Inline(&'a Vec<DirEntry>),
    External(u64, usize, usize),
}

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
    RegInline {
        data: Vec<u8>,
    },
    Dir {
        de_list_start: u64,
        idx_list: Vec<EntryIndex>,
    },
    DirInline {
        de_list: Vec<DirEntry>, // include . and ..
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
        tp: FileType,
        backend: ROCache,
        encrypted: bool,
        cache_data: bool,
    ) -> FsResult<Self> {
        match tp {
            FileType::Reg => {
                assert!(size_of::<DInodeBase>() <= raw.len());
                let dinode_base = unsafe {
                    &*(raw.as_ptr() as *const DInodeBase)
                };

                let sz = dinode_base.size;
                let ext = if sz <= DI_REG_INLINE_DATA_MAX {
                    // inline data
                    let data_start = size_of::<DInodeBase>();
                    let inode_ext_sz = (sz as usize).next_multiple_of(INODE_ALIGN);
                    assert!(data_start + inode_ext_sz == raw.len());
                    let data = Vec::from(unsafe {
                        std::slice::from_raw_parts(
                            raw[data_start..].as_ptr() as *const u8,
                            sz as usize,
                        )
                    });
                    InodeExt::RegInline {
                        data,
                    }
                } else {
                    assert!(size_of::<DInodeReg>() == raw.len());
                    let dinode = unsafe {
                        &*(raw.as_ptr() as *const DInodeReg)
                    };
                    InodeExt::Reg {
                        data_start: dinode.data_start,
                        data_len: dinode.data_len,
                        data: ROHashTree::new(
                            backend, dinode.data_start, dinode.data_len,
                            FSMode::from_key_entry(dinode.crypto_blob, encrypted), cache_data,
                        )
                    }
                };
                Ok(Self {
                    iid,
                    tp: FileType::Reg,
                    perm: get_perm_from_mode(dinode_base.mode),
                    nlinks: dinode_base.nlinks,
                    uid: dinode_base.uid,
                    gid: dinode_base.gid,
                    atime: SystemTime::UNIX_EPOCH + Duration::from_secs(dinode_base.atime as u64),
                    ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(dinode_base.ctime as u64),
                    mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(dinode_base.mtime as u64),
                    size: dinode_base.size as usize,
                    ext,
                })
            }
            FileType::Dir => {
                assert!(size_of::<DInodeBase>() <= raw.len());
                let dinode_base = unsafe {
                    &*(raw.as_ptr() as *const DInodeBase)
                };

                let nr_de = dinode_base.size;
                let ext = if nr_de <= DE_INLINE_MAX {
                    // inline dir entry
                    let de_start = size_of::<DInodeBase>();
                    let nr_de_dot = nr_de + 2;
                    assert!(de_start + nr_de_dot as usize * size_of::<DirEntry>() == raw.len());
                    let de_list = Vec::from(unsafe {
                        std::slice::from_raw_parts(
                            raw[de_start..].as_ptr() as *const DirEntry,
                            nr_de_dot as usize,
                        )
                    });
                    InodeExt::DirInline {
                        de_list,
                    }
                } else {
                    assert!(size_of::<DInodeDirBaseNoInline>() <= raw.len());
                    let di_dir_base = unsafe {
                        &*(raw.as_ptr() as *const DInodeDirBaseNoInline)
                    };
                    let nr_idx = di_dir_base.nr_idx as usize;
                    let idx_list = if nr_idx != 0 {
                        let idx_start = size_of::<DInodeDirBaseNoInline>();
                        assert!(idx_start + nr_idx * size_of::<EntryIndex>() == raw.len());
                        Vec::from(unsafe {
                            std::slice::from_raw_parts(
                                raw[idx_start..].as_ptr() as *const EntryIndex,
                                nr_idx,
                            )
                        })
                    } else {
                        vec![]
                    };
                    InodeExt::Dir {
                        de_list_start: di_dir_base.de_list_start,
                        idx_list,
                    }
                };

                Ok(Self {
                    iid,
                    tp: FileType::Dir,
                    perm: get_perm_from_mode(dinode_base.mode),
                    nlinks: dinode_base.nlinks,
                    uid: dinode_base.uid,
                    gid: dinode_base.gid,
                    atime: SystemTime::UNIX_EPOCH + Duration::from_secs(dinode_base.atime as u64),
                    ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(dinode_base.ctime as u64),
                    mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(dinode_base.mtime as u64),
                    size: dinode_base.size as usize,
                    ext,
                })
            }
            FileType::Lnk => {
                assert!(size_of::<DInodeLnk>() == raw.len());
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
        if let InodeExt::Reg { data, .. } = &self.ext {
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
            size: if self.tp == FileType::Lnk {
                0
            } else {
                self.size as u64
            },
            blocks: if self.tp == FileType::Reg {
                self.size.div_ceil(BLK_SZ) as u64
            } else {
                0
            },
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
    pub fn get_entry_list_info<'a>(&'a self) -> FsResult<DirEntryInfo<'a>> {
        match &self.ext {
            InodeExt::Dir{de_list_start, ..} => {
                Ok(DirEntryInfo::External(*de_list_start, self.size))
            },
            InodeExt::DirInline { de_list } => Ok(DirEntryInfo::Inline(de_list)),
            _ => Err(FsError::PermissionDenied),
        }
    }

    // return de_list_start(pos64), group_start(num of entry), group length
    pub fn lookup_index<'a>(&'a self, name: &OsStr) -> FsResult<LookUpInfo<'a>> {
        match &self.ext {
            InodeExt::Dir{ref idx_list, de_list_start} => {
                if idx_list.len() == 0 {
                    // no idx, need to search from the first entry
                    // 2 because first two are . and ..
                    return Ok(LookUpInfo::External(*de_list_start, 2, self.size))
                }
                let hash = half_md4(name.as_encoded_bytes())?;
                if hash < idx_list[0].hash {
                    // hash is smaller than smallest(first) idx, so it doesn't exist
                    Ok(LookUpInfo::NonExistent)
                } else if let Some(EntryIndex {
                    position, group_len, ..
                }) = idx_list.iter().find(
                    |&ent| hash >= ent.hash
                ) {
                    Ok(LookUpInfo::External(
                        *de_list_start,
                        *position as usize,
                        *group_len as usize
                    ))
                } else {
                    Err(FsError::IncompatibleMetadata)
                }
            },
            InodeExt::DirInline { de_list } => Ok(LookUpInfo::Inline(de_list)),
            _ => Err(FsError::PermissionDenied),
        }
    }
}
