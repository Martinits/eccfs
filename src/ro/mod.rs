pub mod superblock;
pub mod inode;
pub mod disk;

use crate::vfs::*;
use std::sync::Arc;
use std::path::{Path, PathBuf};
use crate::crypto::Key128;
use crate::*;
use std::ffi::OsStr;

pub enum ROFSMode {
    IntegrityOnly,
    Encrypted(Key128),
}

pub struct ROFS {
    mode: ROFSMode,
}

impl ROFS {
    pub fn new(path: &Path, mode: ROFSMode) -> FsResult<Self> {
        Ok(ROFS {
            mode,
        })
    }
}

impl FileSystem for ROFS {
    fn init(&self) ->FsResult<()> {
        unimplemented!();
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
