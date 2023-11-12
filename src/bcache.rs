use std::sync::Arc;
use std::path::Path;
use crate::storage::Storage;

// superblock is not in cache, and stick to memory during runtime
pub struct PlainBCache {
    backend: Arc<dyn Storage>,
}

impl PlainBCache {
    pub fn new(capacity: usize, backend: Arc<dyn Storage>) -> Self {
        Self {
            backend,
        }
    }
}
