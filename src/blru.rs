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
            ret = self.pop_lru()?;
        }

        // push new entry into cache
        if self.0.put(key, (val.clone(), false)).is_some() {
            Err(FsError::UnknownError)
        } else {
            Ok(ret)
        }
    }

    // pop first entry by LRU rules, return it for write back if it's dirty
    fn pop_lru(&mut self) -> FsResult<Option<(u64, T)>> {
        if let Some((&k, _)) = self.0.iter().rev().find(
            |&(_, v)| Arc::<T>::strong_count(&v.0) == 1
        ) {
            let (k, (alock, dirty)) = self.0.pop_entry(&k).unwrap();
            if dirty {
                if let Some(payload) = Arc::<T>::into_inner(alock) {
                    // return payload for write back
                    Ok(Some((k, payload)))
                } else {
                    Err(FsError::UnknownError)
                }
            } else {
                Ok(None)
            }
        } else {
            Err(FsError::CacheIsFull)
        }
    }

    // get a vector of keys of all entries that is not referenced
    fn get_all_unused(&self) -> Vec<u64> {
        self.0.iter().filter_map(
            |(&k, arc)| {
                if Arc::<T>::strong_count(&arc.0) == 1 {
                    Some(k)
                } else {
                    None
                }
            }
        ).collect()
    }

    // flush all entries that is not referenced, even it's dirty
    pub fn flush_no_wb(&mut self) {
        self.get_all_unused().iter().for_each(
            |k| {
                self.0.pop(k).unwrap();
            }
        );
    }

    // flush all entries that is not referenced, return dirty ones
    pub fn flush_wb(&mut self) -> Vec<(u64, T)> {
        self.get_all_unused().iter().filter_map(
            |&k| {
                let (arc, dirty) = self.0.pop(&k).unwrap();
                if dirty {
                    let payload = Arc::<T>::into_inner(arc).unwrap();
                    // return payload for write back
                    Some((k, payload))
                } else {
                    None
                }
            }
        ).collect()
    }
}
