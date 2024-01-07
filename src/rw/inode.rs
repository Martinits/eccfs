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


struct DirEntry {
    ipos: u64,
    len: u16,
    tp: FileType,
    name: String,
}

enum InodeExt {
    Reg {
        data_file_name: KeyEntry,
        data_len: u64,
        data: RWHashTree,
    },
    RegInline {
        data: Vec<u8>,
    },
    Dir {
        data_file_name: KeyEntry,
        data_len: u64,
        data: RWHashTree,
    },
    DirInline {
        de_list: Vec<DirEntry>, // include . and ..
    },
    Lnk(String),
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

pub type InodeBytes = [u8; INODE_SZ];

pub fn iid_to_htree_logi_pos(iid: InodeID) -> usize {
    iid as usize * INODE_SZ
}

impl Inode {
    pub fn new_from_raw(
        raw: &InodeBytes,
        iid: InodeID,
        tp: FileType,
        mode: Option<FSMode>,
    ) -> FsResult<Self> {
        unimplemented!();
    }

    pub fn read_data(&mut self, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        if offset >= self.size {
            Err(FsError::InvalidInput)
        } else {
            let readable = (self.size - offset).min(to.len());
            match &mut self.ext {
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

    pub fn write_data(&mut self, offset: usize, from: &[u8]) -> FsResult<usize> {
        Ok(0)
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

    pub fn set_meta(&mut self, set_meta: SetMetadata) -> FsResult<()> {
        Ok(())
    }

    pub fn get_link(&self) -> FsResult<String> {
        if let InodeExt::Lnk(ref lnk) = self.ext {
            Ok(lnk.clone())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    pub fn lookup(&self, name: &OsStr) -> FsResult<Option<InodeID>> {
        Ok(None)
    }

    pub fn sync_data(&mut self) -> FsResult<()> {
        Ok(())
    }

    pub fn sync_meta(&self) -> FsResult<InodeBytes> {
        unimplemented!();
    }

    pub fn destroy(self) -> FsResult<InodeBytes> {
        unimplemented!();
    }
}
