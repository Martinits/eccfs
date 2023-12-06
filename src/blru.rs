use crate::*;
use lru::LruCache;
use std::sync::Arc;
use std::num::NonZeroUsize;

pub struct BlockLru<T>(LruCache<u64, (Arc<T>, bool)>);

impl<T> BlockLru<T> {
    pub fn new(capacity: usize) -> Self {
        Self(LruCache::new(NonZeroUsize::new(capacity).unwrap()))
    }

    pub fn get(&mut self, key: u64) -> FsResult<Option<Arc<T>>> {
        Ok(self.0.get(&key).map(
            |v| v.0.clone()
        ))
    }

    pub fn mark_dirty(&mut self, key: u64) -> FsResult<()> {
        if let Some(v) = self.0.get_mut(&key) {
            v.1 = true;
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    // just use the argument `val`, no need to get again
    pub fn insert_and_get(
        &mut self, key: u64, val: &Arc<T>
    ) -> FsResult<Option<(u64, T)>> {
        let mut ret = None;
        if self.0.len() >= self.0.cap().into() {
            // pop tail item
            if let Some((k, _)) = self.0.iter().rev().find(
                |&(_, v)| Arc::<T>::strong_count(&v.0) == 1
            ) {
                let (k, (alock, dirty)) = self.0.pop_entry(&k.clone()).unwrap();
                if dirty {
                    if let Some(lock) = Arc::<T>::into_inner(alock) {
                        // return payload
                        ret = Some((k, lock));
                    } else {
                        return Err(FsError::UnknownError);
                    }
                }
            } else {
                return Err(FsError::CacheIsFull);
            }
        }

        if self.0.put(key, (val.clone(), false)).is_some() {
            Err(FsError::UnknownError)
        } else {
            Ok(ret)
        }
    }

    pub fn flush_no_wb(&mut self) {
        self.0.clear();
    }
}
