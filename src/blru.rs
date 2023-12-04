use crate::*;
use lru::LruCache;
use std::sync::Arc;
use std::sync::RwLock;
use std::num::NonZeroUsize;

pub type LruPayload = Arc<RwLock<Block>>;
pub struct BlockLru(LruCache<u64, LruPayload>);

impl BlockLru {
    pub fn new(capacity: usize) -> Self {
        Self(LruCache::new(NonZeroUsize::new(capacity).unwrap()))
    }

    pub fn get(&mut self, key: u64) -> FsResult<Option<LruPayload>> {
        Ok(self.0.get(&key).map(
            |v| v.clone()
        ))
    }

    // just use the argument `val`, no need to get again
    pub fn insert_and_get(
        &mut self, key: u64, val: &LruPayload
    ) -> FsResult<Option<(u64, Block)>> {
        let mut ret = None;
        if self.0.len() >= self.0.cap().into() {
            // pop tail item
            if let Some((k, _)) = self.0.iter().rev().find(
                |&(_, v)| Arc::strong_count(v) == 1
            ) {
                let (k, alock) = self.0.pop_entry(&k.clone()).unwrap();
                if let Some(lock) = Arc::into_inner(alock) {
                    let blk = lock.into_inner().map_err(
                        |_| FsError::LockError
                    )?;
                    ret = Some((k, blk));
                } else {
                    return Err(FsError::UnknownError);
                }
            } else {
                return Err(FsError::CacheIsFull);
            }
        }

        if self.0.put(key, val.clone()).is_some() {
            Err(FsError::UnknownError)
        } else {
            Ok(ret)
        }
    }
}
