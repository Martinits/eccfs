use std::sync::Arc;
use std::path::Path;
use crate::storage::{ROStorage, RWStorage};
use crate::*;

// superblock is not in cache, and stick to memory during runtime
pub struct ROCache {
    backend: Arc<dyn ROStorage>,
}

impl ROCache {
    pub fn new(
        backend: Arc<dyn ROStorage>,
        capacity: usize,
    ) -> Self {
        Self {
            backend,
        }
    }
}

impl ROStorage for ROCache {
    fn read_blk(&mut self, pos: u64, to: &mut [u8], cachable: bool) -> FsResult<()> {
        Ok(())
    }
}

pub struct RWCache {
    backend: Arc<dyn RWStorage>,
}

impl RWCache {
    pub fn new(capacity: usize, backend: Arc<dyn RWStorage>) -> Self {
        Self {
            backend,
        }
    }
}

impl ROStorage for RWCache {
    fn read_blk(&mut self, pos: u64, to: &mut [u8], cachable: bool) -> FsResult<()> {
        Ok(())
    }
}

impl RWStorage for RWCache {
    fn write_blk(&mut self, pos: u64, from: &[u8], cachable: bool) -> FsResult<()> {
        Ok(())
    }
}
