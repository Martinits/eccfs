pub mod superblock;
pub mod inode;
pub mod disk;

use crate::vfs::*;
use std::sync::{Arc, RwLock, Mutex};
use std::path::Path;
use crate::*;
use std::ffi::OsStr;
use superblock::*;
use crate::htree::*;
use inode::*;
use crate::bcache::*;
use crate::storage::*;
use crate::lru::Lru;


pub struct ROFS {
    mode: FSMode,
    cache_data: bool,
    backend_template: ROCache,
    backend: Mutex<ROCache>,
    sb: RwLock<SuperBlock>,
    inode_tbl: Mutex<ROHashTree>,
    dirent_tbl: Mutex<ROHashTree>,
    path_tbl: Mutex<ROHashTree>,
    icac: Option<Mutex<Lru<InodeID, Inode>>>,
    de_cac: Option<Mutex<Lru<String, InodeID>>>,
}

impl ROFS {
    pub fn new(
        path: &Path,
        mode: FSMode,
        cache_data: Option<usize>,
        cache_inode: Option<usize>,
        cache_de: Option<usize>,
    ) -> FsResult<Self> {
        let mut storage = FileStorage::new(path, false)?;

        // read superblock
        let sb_blk = storage.read_blk(SUPERBLOCK_POS)?;
        let sb = SuperBlock::new(mode.clone(), sb_blk)?;

        // start cache channel server
        let cac = ROCache::new(
            Box::new(storage),
            cache_data.unwrap_or(DEFAULT_CACHE_CAP)
        );

        // get hash trees
        let inode_tbl = ROHashTree::new(
            cac.clone(),
            sb.inode_tbl_start,
            sb.inode_tbl_len,
            FSMode::from_key_entry(sb.inode_tbl_key, mode.is_encrypted()),
            cache_data.is_some(),
        );
        let dirent_tbl = ROHashTree::new(
            cac.clone(),
            sb.dirent_tbl_start,
            sb.dirent_tbl_len,
            FSMode::from_key_entry(sb.dirent_tbl_key, mode.is_encrypted()),
            cache_data.is_some(),
        );
        let path_tbl = ROHashTree::new(
            cac.clone(),
            sb.path_tbl_start,
            sb.path_tbl_len,
            FSMode::from_key_entry(sb.path_tbl_key, mode.is_encrypted()),
            cache_data.is_some(),
        );

        Ok(ROFS {
            mode,
            sb: RwLock::new(sb),
            backend: Mutex::new(cac.clone()),
            backend_template: cac,
            cache_data: cache_data.is_some(),
            inode_tbl: Mutex::new(inode_tbl),
            dirent_tbl: Mutex::new(dirent_tbl),
            path_tbl: Mutex::new(path_tbl),
            icac: if let Some(cap) = cache_inode {
                Some(Mutex::new(Lru::new(cap)))
            } else {
                None
            },
            de_cac: if let Some(cap) = cache_de {
                Some(Mutex::new(Lru::new(cap)))
            } else {
                None
            },
        })
    }

    fn fetch_inode(&self, iid: InodeID) -> FsResult<Inode> {
        let (bpos, offset) = iid_split(iid);
        let ablk = mutex_lock!(self.inode_tbl).get_blk(bpos)?;
        Inode::new_from_raw(
            &ablk[offset as usize..],
            iid,
            self.backend_template.clone(),
            self.mode.is_encrypted(),
            self.cache_data,
        )
    }

    fn get_inode(&self, iid: InodeID) -> FsResult<Arc<Inode>> {
        if let Some(mu_icac) = &self.icac {
            let mut icac = mutex_lock!(mu_icac);
            if let Some(ainode) = icac.get(&iid)? {
                Ok(ainode)
            } else {
                // cache miss
                let ainode = Arc::new(self.fetch_inode(iid)?);
                icac.insert_and_get(iid, &ainode)?;
                Ok(ainode)
            }
        } else {
            // no icac
            let inode = self.fetch_inode(iid)?;
            Ok(Arc::new(inode))
        }
    }
}

impl FileSystem for ROFS {
    fn destroy(&self) -> FsResult<()> {
        self.fsync()
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        rwlock_read!(self.sb).get_fsinfo()
    }

    fn fsync(&self) -> FsResult<()> {
        if let Some(ref icac) = self.icac {
            mutex_lock!(icac).flush_no_wb();
        }

        if let Some(ref de_cac) = self.de_cac {
            mutex_lock!(de_cac).flush_no_wb();
        }

        mutex_lock!(self.backend).flush()?;

        Ok(())
    }

    fn iread(&self, iid: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        self.get_inode(iid)?.read_data(offset, to)
    }

    fn get_meta(&self, iid: InodeID) -> FsResult<Metadata> {
        self.get_inode(iid)?.get_meta()
    }

    fn iread_link(&self, iid: InodeID) -> FsResult<String> {
        match self.get_inode(iid)?.get_link()? {
            LnkName::Short(s) => Ok(s),
            LnkName::Long(pos, len) => {
                let mut buf = vec![0u8; len];
                let read = mutex_lock!(self.path_tbl)
                            .read_exact(pos as usize, buf.as_mut_slice())?;
                if read != len {
                    Err(FsError::IncompatibleMetadata)
                } else {
                    Ok(String::from_utf8(buf).map_err(|_| FsError::InvalidData)?)
                }
            }
        }
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        if let Some(ref icac) = self.icac {
            mutex_lock!(icac).try_pop_key(&iid)?;
        }

        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        unimplemented!();
    }

    fn listdir(&self, iid: InodeID) -> FsResult<Vec<(InodeID, String, FileType)>> {
        unimplemented!();
    }
}

fn iid_split(iid: InodeID) -> (u64, u16) {
    (iid & 0x0ffffffffffff, (iid >> 48) as u16)
}
