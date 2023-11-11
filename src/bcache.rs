use std::sync::Arc;
use std::path::Path;
use crate::storage::Storage;

// superblock is not in cache, and stick to memory during runtime
pub struct PlainCache {
    backend: Arc<dyn Storage>,
}
