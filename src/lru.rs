use crate::*;
use std::sync::Arc;
use std::num::NonZeroUsize;
extern crate lru;
use std::hash::Hash;

pub struct Lru<K: Hash + Eq + Clone, V>(lru::LruCache<K, (Arc<V>, bool)>);

impl<K: Hash + Eq + Clone, V> Lru<K, V> {
    pub fn new(capacity: usize) -> Self {
        Self(lru::LruCache::new(NonZeroUsize::new(capacity).unwrap()))
    }

    pub fn get(&mut self, key: &K) -> FsResult<Option<Arc<V>>> {
        Ok(self.0.get(key).map(
            |v| v.0.clone()
        ))
    }

    pub fn mark_dirty(&mut self, key: &K) -> FsResult<()> {
        if let Some(v) = self.0.get_mut(key) {
            v.1 = true;
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    // just use the argument `val`, no need to get again
    pub fn insert_and_get(
        &mut self, key: K, val: &Arc<V>
    ) -> FsResult<Option<(K, V)>> {
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
    fn pop_lru(&mut self) -> FsResult<Option<(K, V)>> {
        let res = self.0.iter().rev().find(
            |&(_, v)| Arc::<V>::strong_count(&v.0) == 1
        );
        if res.is_none() {
            return Err(FsError::CacheIsFull);
        }

        let k = res.unwrap().0.clone();
        let (k, (alock, dirty)) = self.0.pop_entry(&k).unwrap();
        if dirty {
            if let Some(payload) = Arc::<V>::into_inner(alock) {
                // return payload for write back
                Ok(Some((k, payload)))
            } else {
                Err(FsError::UnknownError)
            }
        } else {
            Ok(None)
        }
    }

    // try to pop the key, return payload only if key exists, no one is using and it's dirty
    pub fn try_pop_key(&mut self, k: &K) -> FsResult<Option<V>> {
        if let Some((_, (alock, _))) = self.0.get_key_value(&k) {
            if Arc::<V>::strong_count(alock) == 1 {
                let (_, (alock, dirty)) = self.0.pop_entry(&k).unwrap();
                if dirty {
                    // if dirty, return payload for write back
                    Ok(Some(Arc::<V>::into_inner(alock).unwrap()))
                } else {
                    Ok(None)
                }
            } else {
                // some one is using it
                Ok(None)
            }
        } else {
            // not found this key
            Ok(None)
        }
    }

    // get a vector of keys of all entries that is not referenced
    fn get_all_unused(&self) -> Vec<K> {
        self.0.iter().filter_map(
            |(k, arc)| {
                if Arc::<V>::strong_count(&arc.0) == 1 {
                    Some(k.clone())
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
    pub fn flush_wb(&mut self) -> Vec<(K, V)> {
        self.get_all_unused().into_iter().filter_map(
            |k| {
                let (arc, dirty) = self.0.pop(&k).unwrap();
                if dirty {
                    let payload = Arc::<V>::into_inner(arc).unwrap();
                    // return payload for write back
                    Some((k, payload))
                } else {
                    None
                }
            }
        ).collect()
    }
}
