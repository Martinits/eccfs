use crate::*;
use std::sync::Arc;
use std::num::NonZeroUsize;
extern crate lru;
use std::hash::Hash;
use std::sync::mpsc::{self, Sender, Receiver};
use std::thread;

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
        }
        Ok(())
    }

    // just use the argument `val`, no need to get again
    // return error if key already exists
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
            Err(FsError::AlreadyExists)
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
    pub fn flush_no_wb(&mut self) -> FsResult<()> {
        self.get_all_unused().iter().for_each(
            |k| {
                self.0.pop(k).unwrap();
            }
        );
        Ok(())
    }

    // flush all entries that is not referenced, return dirty ones
    pub fn flush_wb(&mut self) -> FsResult<Vec<(K, V)>> {
        Ok(self.get_all_unused().into_iter().filter_map(
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
        ).collect())
    }
}


enum ChannelReq<K, V>
where
    K: Hash + Eq + Clone + Send
{
    Get {
        key: K,
        reply: Sender<FsResult<Option<Arc<V>>>>,
    },
    InsertGet {
        key: K,
        value: Arc<V>,
        reply: Sender<FsResult<Option<(K, V)>>>, // possible retire from lru
    },
    MarkDirty {
        key: K,
        reply: Sender<FsResult<()>>,
    },
    Flush {
        key: K,
        reply: Sender<FsResult<Option<V>>>, // possible write back
    },
    FlushAll {
        wb: bool,
        reply: Sender<FsResult<Vec<(K, V)>>>, // possible write back
    },
}

#[derive(Clone)]
pub struct ChannelLru<K, V>
where
    K: Hash + Eq + Clone + Send,
    V: Send,
{
    tx_to_server: Sender<ChannelReq<K, V>>,
}

impl<K, V> ChannelLru<K, V>
where
    K: Hash + Eq + Clone + Send + 'static,
    V: Send + Sync + 'static,
{
    pub fn new(capacity: usize) -> Self {
        let (tx, rx) = mpsc::channel();

        let mut server = ChannelServer::new(capacity, rx);

        let _handle = thread::spawn(move || {
            loop {
                match server.rx.recv() {
                    Ok(req) => server.process(req),
                    Err(e) => panic!("Cache server received an error: {:?}", e),
                }
            }
        });

        Self {
            tx_to_server: tx,
        }
    }

    pub fn get(&mut self, key: K) -> FsResult<Option<Arc<V>>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::Get {
            key,
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        rx.recv().map_err(|_| FsError::ChannelRecvError)?
    }

    pub fn insert_and_get(&mut self, key: K, apayload: &Arc<V>) -> FsResult<Option<(K, V)>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::InsertGet {
            key,
            value: apayload.clone(),
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        rx.recv().map_err(|_| FsError::ChannelRecvError)?
    }

    pub fn mark_dirty(&mut self, key: K) -> FsResult<()> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::MarkDirty {
            key,
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        rx.recv().map_err(|_| FsError::ChannelRecvError)?
    }

    pub fn flush_key(&mut self, key: K) -> FsResult<Option<V>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::Flush {
            key,
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        rx.recv().map_err(|_| FsError::ChannelRecvError)?
    }

    pub fn flush_all(&mut self, wb: bool) -> FsResult<Option<Vec<(K, V)>>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::FlushAll {
            wb,
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        let wb_list = rx.recv().map_err(|_| FsError::ChannelRecvError)??;
        Ok(if wb_list.len() == 0 {
            None
        } else {
            Some(wb_list)
        })
    }
}

struct ChannelServer<K, V>
where
    K: Hash + Eq + Clone + Send,
{
    rx: Receiver<ChannelReq<K, V>>,
    lru: Lru<K, V>,
}

impl<K, V> ChannelServer<K, V>
where
    K: Hash + Eq + Clone + Send,
{
    fn new(capacity: usize, rx: Receiver<ChannelReq<K, V>>) -> Self {
        Self {
            rx,
            lru: Lru::new(capacity),
        }
    }

    fn process(&mut self, req: ChannelReq<K, V>) {
        match req {
            ChannelReq::Get { key, reply } => {
                reply.send(self.lru.get(&key)).unwrap();
            }
            ChannelReq::InsertGet { key, value, reply } => {
                reply.send(self.lru.insert_and_get(key, &value)).unwrap();
            }
            ChannelReq::MarkDirty { key, reply } => {
                reply.send(self.lru.mark_dirty(&key)).unwrap();
            }
            ChannelReq::Flush { key, reply } => {
                reply.send(self.lru.try_pop_key(&key)).unwrap();
            }
            ChannelReq::FlushAll { wb, reply } => {
                if wb {
                    reply.send(self.lru.flush_wb()).unwrap();
                } else {
                    reply.send(self.lru.flush_no_wb().map(|_| Vec::new())).unwrap();
                }
            }
        }
    }
}
