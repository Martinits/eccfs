use std::sync::Arc;
use crate::bcache::PlainBCache;
use crate::storage::Storage;

// use features to separate impls for SGX and TDX+FUSE
// for TDX+FUSE deployment, only cache index blocks, kernel will handle the left cache
struct HashTree {
    idx_cache: PlainBCache,
    start: u64,
    length: usize,
    writable: bool,
    encrypted: bool,
}

impl HashTree {
    fn new(
        storage: Arc<dyn Storage>,
        start: u64,
        length: usize,
        writable: bool,
        encrypted: bool,
    ) -> Self {
        Self {
            idx_cache: PlainBCache::new(10, storage),
            start,
            length,
            writable,
            encrypted,
        }
    }

    fn validate_root(self) {

    }

    fn read(self, pos: u64, nblk: usize, to: &[u8]) {

    }

    fn write(self, pos: u64, nblk: usize, from: &mut [u8]) {

    }

    // flush all blocks including root
    fn flush(self) {

    }
}
