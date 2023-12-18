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
    backend: ROCache,
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
            backend: cac,
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

    fn fetch_inode(&mut self, iid: InodeID) -> FsResult<Inode> {
        let (bpos, offset) = iid_split(iid);
        let ablk = mutex_lock!(self.inode_tbl).get_blk(bpos)?;
        Inode::new_from_raw(
            &ablk[offset as usize..],
            self.backend.clone(),
            self.mode.is_encrypted(),
            self.cache_data,
        )
    }

    fn get_inode(&mut self, iid: InodeID) -> FsResult<Arc<Inode>> {
        if let Some(mu_icac) = &self.icac {
            unimplemented!();
        } else {
            // no icac
            let inode = self.fetch_inode(iid)?;
            Ok(Arc::new(inode))
        }
    }
}

impl FileSystem for ROFS {
    fn init(&self) ->FsResult<()> {
        Ok(())
    }

    fn destroy(&self) -> FsResult<()> {
        self.fsync()
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        unimplemented!();
    }

    fn fsync(&self) -> FsResult<()> {
        unimplemented!();
    }

    fn iread(&mut self, inode: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        let inode = self.get_inode(inode)?;
        inode.read_data(offset, to)
    }

    fn iwrite(&self, inode: InodeID, offset: usize, from: &[u8]) -> FsResult<usize> {
        Err(FsError::Unsupported)
    }

    fn get_meta(&self, inode: InodeID) -> FsResult<Metadata> {
        unimplemented!();
    }

    fn set_meta(&self, inode: InodeID, set_md: SetMetadata) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    fn iread_link(&self, inode: InodeID) -> FsResult<String> {
        unimplemented!();
    }

    fn fallocate(&self, inode: InodeID, mode: FallocateMode, offset: usize, len: usize) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    fn isync_data(&self, inode: InodeID) -> FsResult<()> {
        unimplemented!();
    }

    fn isync_meta(&self, inode: InodeID) -> FsResult<()> {
        unimplemented!();
    }

    fn create(&self, inode: InodeID, name: &OsStr, ftype: FileType, perm: u16) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    fn link(&self, newparent: InodeID, newname: &OsStr, linkto: InodeID) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    fn unlink(&self, inode: InodeID, name: &OsStr) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    fn symlink(&self, inode: InodeID, name: &OsStr, to: &Path) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    fn rename(&self, inode: InodeID, name: &OsStr, to: InodeID, newname: &OsStr) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    fn lookup(&self, inode: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        unimplemented!();
    }

    fn listdir(&self, inode: InodeID) -> FsResult<Vec<(InodeID, String, FileType)>> {
        unimplemented!();
    }
}

fn iid_split(iid: InodeID) -> (u64, u16) {
    (iid & 0x0ffffffffffff, (iid >> 48) as u16)
}
