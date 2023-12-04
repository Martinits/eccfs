use std::sync::Arc;
use crate::storage::{ROStorage, RWStorage};

// use features to separate impls for SGX and TDX+FUSE
// for TDX+FUSE deployment, only cache index blocks, kernel will handle the left cache
pub struct ROHashTree {
    backend: Arc<dyn ROStorage>,
    start: u64,
    length: usize,
    encrypted: bool,
    data_cache: bool,
}

impl ROHashTree {
    fn new(
        backend: Arc<dyn ROStorage>,
        start: u64,
        length: usize,
        encrypted: bool,
        data_cache: bool,
    ) -> Self {
        Self {
            backend,
            start,
            length,
            encrypted,
            data_cache,
        }
    }

    pub fn validate_root(self) {

    }

    pub fn read(self, pos: u64, nblk: usize, to: &[u8]) {

    }

    pub fn write(self, pos: u64, nblk: usize, from: &mut [u8]) {

    }

    // flush all blocks including root
    pub fn flush(self) {

    }
}

pub struct RWHashTree {
    backend: Arc<dyn RWStorage>,
    start: u64,
    length: usize,
    encrypted: bool,
}

impl RWHashTree {
    pub fn new(
        backend: Arc<dyn RWStorage>,
        start: u64,
        length: usize,
        encrypted: bool,
    ) -> Self {
        Self {
            backend,
            start,
            length,
            encrypted,
        }
    }

    pub fn validate_root(self) {

    }

    pub fn read(self, pos: u64, nblk: usize, to: &[u8]) {

    }

    pub fn write(self, pos: u64, nblk: usize, from: &mut [u8]) {

    }

    // flush all blocks including root
    pub fn flush(self) {

    }
}
