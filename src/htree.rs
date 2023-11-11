use std::sync::Arc;
use crate::bcache::PlainCache;

struct HashTree {
    backend: Arc<PlainCache>,
    start: u64,
    length: usize,
    writable: bool,
    encrypted: bool,
}

impl HashTree {
    fn new(
        backend: Arc<PlainCache>,
        start: u64,
        length: usize,
        writable: bool,
        encrypted: bool,
    ) -> Self {
        Self {
            backend,
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
