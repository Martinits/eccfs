use crate::*;
use std::sync::Arc;
use std::num::NonZeroUsize;
extern crate lru;
use std::hash::Hash;

#[cfg(feature = "channel_lru")]
use std::sync::mpsc::{self, Sender, Receiver};
#[cfg(feature = "channel_lru")]
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
            Ok(())
        } else {
            Err(new_error!(FsError::NotFound))
        }
    }

    pub fn unmark_dirty(&mut self, key: &K) -> FsResult<()> {
        if let Some(v) = self.0.get_mut(key) {
            v.1 = false;
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
            Err(new_error!(FsError::AlreadyExists))
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
            return Err(new_error!(FsError::CacheIsFull));
        }

        let k = res.unwrap().0.clone();
        let (k, (alock, dirty)) = self.0.pop_entry(&k).unwrap();
        if dirty {
            let payload = Arc::<V>::try_unwrap(alock).map_err(
                |_| new_error!(FsError::UnknownError)
            ).unwrap();
            // return payload for write back
            Ok(Some((k, payload)))
        } else {
            Ok(None)
        }
    }

    // try to pop the key,
    // return payload only if key exists and no one is using,
    // if force is set, return payload even if it's not dirty
    pub fn try_pop_key(&mut self, k: &K, force: bool) -> FsResult<Option<V>> {
        if let Some((_, (alock, _))) = self.0.get_key_value(&k) {
            let arc_cnt = Arc::<V>::strong_count(alock);
            if arc_cnt == 1 {
                let (alock, dirty) = self.0.pop(&k).unwrap();
                if force || dirty {
                    // return payload for write back
                    Ok(Some(Arc::<V>::try_unwrap(alock).map_err(
                        |_| new_error!(FsError::UnknownError)
                    ).unwrap()))
                } else {
                    Ok(None)
                }
            } else {
                // some one is using it
                // debug!("lru: flush when {} is using", arc_cnt);
                Ok(None)
            }
        } else {
            // not found this key
            // debug!("lru: flush but not found");
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
                    let payload = Arc::<V>::try_unwrap(arc).map_err(
                        |_| FsError::UnknownError
                    ).unwrap();
                    // return payload for write back
                    Some((k, payload))
                } else {
                    None
                }
            }
        ).collect())
    }

    // return all keys that can be flushed, no matter dirty
    pub fn flush_keys(&self) -> FsResult<Vec<K>> {
        Ok(self.0.iter().filter_map(
            |(k, arc)| {
                if Arc::<V>::strong_count(&arc.0) == 1 {
                    Some(k.clone())
                } else {
                    None
                }
            }
        ).collect())
    }
}

#[cfg(feature = "channel_lru")]
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
    UnMarkDirty {
        key: K,
        reply: Sender<FsResult<()>>,
    },
    Flush {
        key: K,
        reply: Sender<FsResult<Option<V>>>, // possible write back
        force: bool,
    },
    FlushAll {
        wb: bool,
        reply: Sender<FsResult<Vec<(K, V)>>>, // possible write back
    },
    Abort,
}

#[cfg(feature = "channel_lru")]
#[derive(Clone)]
pub struct ChannelLru<K, V>
where
    K: Hash + Eq + Clone + Send,
    V: Send,
{
    tx_to_server: Sender<ChannelReq<K, V>>,
}

#[cfg(feature = "channel_lru")]
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
                    Ok(ChannelReq::Abort) => break,
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
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))?
    }

    pub fn insert_and_get(&mut self, key: K, apayload: &Arc<V>) -> FsResult<Option<(K, V)>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::InsertGet {
            key,
            value: apayload.clone(),
            reply: tx,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))?
    }

    pub fn mark_dirty(&mut self, key: K) -> FsResult<()> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::MarkDirty {
            key,
            reply: tx,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))?
    }

    pub fn unmark_dirty(&mut self, key: K) -> FsResult<()> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::UnMarkDirty {
            key,
            reply: tx,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))?
    }

    // return even if it's not dirty
    pub fn flush_key_force(&mut self, key: K) -> FsResult<Option<V>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::Flush {
            key,
            reply: tx,
            force: true,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))?
    }

    pub fn flush_key(&mut self, key: K) -> FsResult<Option<V>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::Flush {
            key,
            reply: tx,
            force: false,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))?
    }

    pub fn flush_all(&mut self, wb: bool) -> FsResult<Option<Vec<(K, V)>>> {
        let (tx, rx) = mpsc::channel();

        self.tx_to_server.send(ChannelReq::FlushAll {
            wb,
            reply: tx,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        let wb_list = rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))??;
        Ok(if wb_list.len() == 0 {
            None
        } else {
            Some(wb_list)
        })
    }

    pub fn abort(&mut self) -> FsResult<()> {
        self.tx_to_server.send(ChannelReq::Abort).map_err(
            |_| new_error!(FsError::ChannelSendError)
        )?;
        Ok(())
    }
}

#[cfg(feature = "channel_lru")]
struct ChannelServer<K, V>
where
    K: Hash + Eq + Clone + Send,
{
    rx: Receiver<ChannelReq<K, V>>,
    lru: Lru<K, V>,
}

#[cfg(feature = "channel_lru")]
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
            ChannelReq::UnMarkDirty { key, reply } => {
                reply.send(self.lru.unmark_dirty(&key)).unwrap();
            }
            ChannelReq::Flush { key, reply, force } => {
                reply.send(self.lru.try_pop_key(&key, force)).unwrap();
            }
            ChannelReq::FlushAll { wb, reply } => {
                if wb {
                    reply.send(self.lru.flush_wb()).unwrap();
                } else {
                    reply.send(self.lru.flush_no_wb().map(|_| Vec::new())).unwrap();
                }
            }
            _ => panic!("Abort request should be handled before this funciton"),
        }
    }
}
