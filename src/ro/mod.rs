pub mod superblock;
pub mod inode;
pub mod disk;

use crate::vfs::{FileSystem, FsResult, Inode};
use std::sync::Arc;
use std::path::{Path, PathBuf};
use crate::crypto::Key128;

pub enum ROFSMode {
    IntegrityOnly,
    Encrypted(Key128),
}

pub struct ROFS {
    mode: ROFSMode,
}

impl ROFS {
    pub fn new(path: &Path, mode: ROFSMode) -> FsResult<Arc<Self>> {
        Ok(Arc::new(
            ROFS {
                mode,
            }
        ))
    }
}

impl FileSystem for ROFS {
    fn sync(&self) -> FsResult<()> {
        unimplemented!();
    }

    fn root_inode(&self) -> Arc<dyn Inode> {
        unimplemented!();
    }
}
