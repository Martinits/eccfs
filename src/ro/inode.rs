use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::time::{SystemTime, Duration};
use std::mem::size_of;
use crate::htree::*;
use crate::bcache::*;
use std::ffi::OsStr;
use crate::crypto::half_md4;
use super::*;

pub enum DirEntryInfo<'a> {
    Inline(&'a [DirEntry]),
    External(u64, usize), // u64 is byte offset in dtbl, not pos64
}

pub enum LookUpInfo<'a> {
    NonExistent,
    Inline(&'a Vec<DirEntry>),
    External(u64, usize), // u64 is byte offset in dtbl, not pos64
}

#[derive(Clone)]
pub enum LnkName {
    Short(PathBuf),
    Long(u64, usize), // (pos, length)
}

enum InodeExt {
    Reg {
        _data_start: u64,
        _data_len: u64,
        data: ROHashTree,
    },
    RegInline {
        data: Vec<u8>,
    },
    Dir {
        de_list_start: u64, // is byte offset, not pos64
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
    size: usize, // with . and ..
    ext: InodeExt,
}

impl Inode {
    pub fn new_from_raw(
        raw: &[u8],
        iid: InodeID,
        tp: FileType,
        backend: ROCache,
        file_sec_start: u64,
        file_sec_len: u64,
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
                    assert_eq!(data_start + inode_ext_sz, raw.len());
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
                    assert!(file_sec_len != 0);
                    assert!(size_of::<DInodeReg>() == raw.len());
                    let dinode = unsafe {
                        &*(raw.as_ptr() as *const DInodeReg)
                    };
                    assert!(dinode.data_start + dinode.data_len <= file_sec_len);
                    InodeExt::Reg {
                        _data_start: file_sec_start + dinode.data_start,
                        _data_len: dinode.data_len,
                        data: ROHashTree::new(
                            backend, file_sec_start + dinode.data_start, dinode.data_len,
                            FSMode::from_key_entry(dinode.key_entry, encrypted), cache_data,
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
                    let (pos, off) = pos64_split(di_dir_base.de_list_start);
                    assert_eq!(off as usize % INODE_ALIGN, 0);
                    InodeExt::Dir {
                        de_list_start: pos64_to_byte(pos, off),
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
                    size: dinode_base.size as usize + 2,
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

    pub fn read_data(&self, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        if offset >= self.size {
            Err(FsError::InvalidInput)
        } else {
            let readable = (self.size - offset).min(to.len());
            match &self.ext {
                InodeExt::Reg { data, .. } => {
                    let read = data.read_exact(offset, &mut to[..readable])?;
                    Ok(read)
                }
                InodeExt::RegInline { data } => {
                    assert!(data.len() == self.size);
                    to[..readable].copy_from_slice(&data[offset..offset+readable]);
                    Ok(readable)
                }
                _ => Err(FsError::PermissionDenied),
            }
        }
    }

    pub fn get_meta(&self) -> FsResult<Metadata> {
        Ok(Metadata {
            iid: self.iid,
            size: match self.tp {
                FileType::Reg => self.size,
                FileType::Dir => self.size * size_of::<DirEntry>(),
                FileType::Lnk => 0,
            } as u64,
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
    pub fn get_entry_list_info<'a>(
        &'a self,
        offset: usize
    ) -> FsResult<Option<DirEntryInfo<'a>>> {
        if offset >= self.size {
            return Ok(None);
        }

        let ret = match &self.ext {
            InodeExt::Dir{de_list_start, ..} => {
                DirEntryInfo::External(
                    *de_list_start + (size_of::<DirEntry>() * offset) as u64,
                    self.size - offset
                )
            },
            InodeExt::DirInline { de_list } => {
                assert!(offset < de_list.len());
                DirEntryInfo::Inline(&de_list[offset..])
            },
            _ => return Err(FsError::PermissionDenied),
        };

        Ok(Some(ret))
    }

    // return de_list_start(pos64), group_start(num of entry), group length
    pub fn lookup_index<'a>(&'a self, name: &OsStr) -> FsResult<LookUpInfo<'a>> {
        match &self.ext {
            InodeExt::Dir{ref idx_list, de_list_start} => {
                if idx_list.len() == 0 {
                    // no idx, need to search from the first entry
                    // 2 because first two are . and ..
                    return Ok(LookUpInfo::External(
                        *de_list_start +  2 * size_of::<DirEntry>() as u64,
                        self.size
                    ));
                }
                let hash = half_md4(name.as_encoded_bytes())?;
                if let Some(EntryIndex {
                    position, group_len, ..
                }) = idx_list.iter().rev().find(
                    |&ent| hash >= ent.hash
                ) {
                    Ok(LookUpInfo::External(
                        *de_list_start + *position as u64 * size_of::<DirEntry>() as u64,
                        *group_len as usize
                    ))
                } else {
                    // hash is smaller than smallest(first) idx, so it doesn't exist
                    Ok(LookUpInfo::NonExistent)
                }
            },
            InodeExt::DirInline { de_list } => Ok(LookUpInfo::Inline(de_list)),
            _ => Err(FsError::PermissionDenied),
        }
    }
}
