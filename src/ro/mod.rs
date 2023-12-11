pub mod superblock;
pub mod inode;
pub mod disk;

use crate::vfs::*;
use std::sync::{Arc, RwLock};
use std::path::Path;
use crate::crypto::Key128;
use crate::*;
use std::ffi::OsStr;
use superblock::*;
use crate::htree::*;
use std::collections::HashMap;
use inode::Inode;
use crate::bcache::*;
use crate::storage::*;
use crate::crypto::*;


pub struct ROFS {
    mode: FSMode,
    cache_data: bool,
    sb: RwLock<SuperBlock>,
    inode_tbl: ROHashTree,
    dirent_tbl: ROHashTree,
    path_tbl: ROHashTree,
    files: RwLock<HashMap<u64, ROHashTree>>,
    icac: Option<RwLock<HashMap<InodeID, Inode>>>,
    de_cac: Option<RwLock<HashMap<String, InodeID>>>,
}

impl ROFS {
    pub fn new(
        path: &Path,
        mode: FSMode,
        cache_data: bool,
        cache_inode: bool,
        cache_de: bool,
    ) -> FsResult<Self> {
        let mut storage = FileStorage::new(path, false)?;

        // read superblock
        let sb_blk = storage.read_blk(SUPERBLOCK_POS)?;
        let sb = SuperBlock::new(mode.clone(), sb_blk)?;

        // start cache channel server
        let cac = ROCache::new(Box::new(storage), DEFAULT_CACHE_CAP);

        // get hash trees
        let inode_tbl = ROHashTree::new(
            cac.clone(),
            sb.inode_tbl_start,
            sb.inode_tbl_len,
            FSMode::from_key_entry(sb.inode_tbl_key, mode.is_encrypted()),
            cache_data,
        );
        let dirent_tbl = ROHashTree::new(
            cac.clone(),
            sb.dirent_tbl_start,
            sb.dirent_tbl_len,
            FSMode::from_key_entry(sb.dirent_tbl_key, mode.is_encrypted()),
            cache_data,
        );
        let path_tbl = ROHashTree::new(
            cac.clone(),
            sb.path_tbl_start,
            sb.path_tbl_len,
            FSMode::from_key_entry(sb.path_tbl_key, mode.is_encrypted()),
            cache_data,
        );

        Ok(ROFS {
            mode,
            sb: RwLock::new(sb),
            cache_data,
            inode_tbl,
            dirent_tbl,
            path_tbl,
            files: Default::default(),
            icac: cache_inode.then(|| RwLock::new(HashMap::new())),
            de_cac: cache_de.then(|| RwLock::new(HashMap::new())),
        })
    }
}

impl FileSystem for ROFS {
    fn init(&self) ->FsResult<()> {
        Ok(())
    }

    fn destroy(&self) -> FsResult<()> {
        unimplemented!();
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        unimplemented!();
    }

    fn fsync(&self) -> FsResult<()> {
        unimplemented!();
    }

    fn iread(&self, inode: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        unimplemented!();
    }

    fn iwrite(&self, inode: InodeID, offset: usize, from: &[u8]) -> FsResult<usize> {
        unimplemented!();
    }

    fn get_meta(&self, inode: InodeID) -> FsResult<Metadata> {
        unimplemented!();
    }

    fn set_meta(&self, inode: InodeID, set_md: SetMetadata) -> FsResult<()> {
        unimplemented!();
    }

    fn iread_link(&self, inode: InodeID) -> FsResult<String> {
        unimplemented!();
    }

    fn fallocate(&self, inode: InodeID, mode: FallocateMode, offset: usize, len: usize) -> FsResult<()> {
        unimplemented!();
    }

    fn isync_data(&self, inode: InodeID) -> FsResult<()> {
        unimplemented!();
    }

    fn isync_meta(&self, inode: InodeID) -> FsResult<()> {
        unimplemented!();
    }

    fn create(&self, inode: InodeID, name: &OsStr, ftype: FileType, perm: u16) -> FsResult<InodeID> {
        unimplemented!();
    }

    fn link(&self, newparent: InodeID, newname: &OsStr, linkto: InodeID) -> FsResult<InodeID> {
        unimplemented!();
    }

    fn unlink(&self, inode: InodeID, name: &OsStr) -> FsResult<()> {
        unimplemented!();
    }

    fn symlink(&self, inode: InodeID, name: &OsStr, to: &Path) -> FsResult<InodeID> {
        unimplemented!();
    }

    fn rename(&self, inode: InodeID, name: &OsStr, to: InodeID, newname: &OsStr) -> FsResult<()> {
        unimplemented!();
    }

    fn lookup(&self, inode: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        unimplemented!();
    }

    fn get_entry(&self, inode: InodeID, id: usize) -> FsResult<String> {
        unimplemented!();
    }

    fn listdir(&self, inode: InodeID) -> FsResult<Vec<(InodeID, String, FileType)>> {
        unimplemented!();
    }
}
