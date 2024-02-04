use alloc::{
    boxed::Box,
    sync::Arc,
    vec::Vec,
};

use crate::storage::ROStorage;
use crate::*;
use crate::lru::Lru;
use spin::RwLock;
use crate::crypto::*;

#[cfg(feature = "ro_cache_server")]
use std::sync::mpsc::{self, Sender, Receiver};
#[cfg(feature = "ro_cache_server")]
use std::thread;

#[cfg(feature = "ro_cache_server")]
enum ROCacheReq {
    Get {
        pos: u64,
        cachable: bool,
        miss_hint: Option<CryptoHint>,
        reply: Sender<FsResult<Option<Arc<Block>>>>,
    },
    Flush,
    Abort,
}

// superblock is not in cache, and stick to memory during runtime
#[cfg(feature = "ro_cache_server")]
#[derive(Clone)]
pub struct ROCache {
    tx_to_server: Sender<ROCacheReq>,
    // server_handle: Option<JoinHandle<()>>,
}

pub const DEFAULT_CACHE_CAP: usize = 256;

#[cfg(feature = "ro_cache_server")]
struct ROCacheServer {
    rx: Receiver<ROCacheReq>,
    lru: Lru<u64, Block>,
    _capacity: usize,
    backend: Box<dyn ROStorage>,
}

// const DEFAULT_CHANNEL_SIZE: usize = 20;

#[cfg(feature = "ro_cache_server")]
impl ROCache {
    pub fn new(
        backend: Box<dyn ROStorage>,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel();

        let mut server = ROCacheServer::new(backend, capacity, rx);

        let _handle = thread::spawn(move || {
            loop {
                match server.rx.recv() {
                    Ok(req) => {
                        if let ROCacheReq::Abort = &req {
                            break;
                        }
                        server.process(req);
                    },
                    Err(e) => panic!("Cache server received an error: {:?}", e),
                }
            }
        });

        Self {
            tx_to_server: tx,
            // server_handle: Some(handle),
        }
    }

    pub fn get_blk_try(&mut self, pos: u64, cachable: bool) -> FsResult<Option<Arc<Block>>> {
        self.get_blk_impl(pos, cachable, None)
    }

    pub fn get_blk_hint(
        &mut self, pos: u64, cachable: bool, hint: CryptoHint
    ) -> FsResult<Arc<Block>> {
        self.get_blk_impl(pos, cachable, Some(hint))?.ok_or_else(
            || new_error!(FsError::NotFound)
        )
    }

    fn get_blk_impl(
        &mut self, pos: u64, cachable: bool, hint: Option<CryptoHint>
    ) -> FsResult<Option<Arc<Block>>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(ROCacheReq::Get {
            pos,
            cachable,
            reply: tx,
            miss_hint: hint,
        }).map_err(|_| new_error!(FsError::ChannelSendError))?;

        let ablk = rx.recv().map_err(|_| new_error!(FsError::ChannelRecvError))??;

        Ok(ablk)
    }

    pub fn flush(&mut self) -> FsResult<()> {
        self.tx_to_server.send(ROCacheReq::Flush).map_err(|_| new_error!(FsError::ChannelSendError))
    }

    pub fn abort(&mut self) -> FsResult<()> {
        self.tx_to_server.send(ROCacheReq::Abort).map_err(|_| new_error!(FsError::ChannelSendError))
    }
}

#[cfg(feature = "ro_cache_server")]
impl ROCacheServer {
    fn new(
        backend: Box<dyn ROStorage>,
        capacity: usize,
        rx: Receiver<ROCacheReq>,
    ) -> Self {
        Self {
            rx,
            backend,
            _capacity: capacity,
            lru: Lru::new(capacity),
        }
    }

    fn process(&mut self, req: ROCacheReq) {
        match req {
            ROCacheReq::Get {cachable, reply, pos, miss_hint } => {
                let send = if cachable {
                    match self.lru.get(&pos) {
                        Ok(Some(ablk)) => {
                            Ok(Some(ablk))
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            if let Some(hint) = miss_hint {
                                self.cache_miss(pos, hint)
                            } else {
                                // if cachable but no hint,
                                // return None to remind caller to provide hint
                                Ok(None)
                            }
                        }
                        Err(e) => Err(e),
                    }
                } else if let Some(hint) = miss_hint {
                    self.fetch_from_backend(pos, hint).map(
                        |blk| Some(Arc::new(blk))
                    )
                } else {
                    // This means block is not cachable and no hint is provided.
                    // Ideally, caller should always provide hint for a uncachable block,
                    // and we should return an error like this:
                    // Err(new_error!(FsError::CacheNeedHint))

                    // But maybe caller just want to know whether such a block is cached,
                    // so we handle this gently.
                    Ok(None)
                };
                reply.send(send).unwrap();
            }
            ROCacheReq::Flush => {
                self.lru.flush_no_wb().unwrap();
            }
            _ => panic!("ROCacheServer: Unexpected msg"),
        }
    }

    fn fetch_from_backend(&mut self, pos: u64, hint: CryptoHint) -> FsResult<Block> {
        let mut blk = self.backend.read_blk(pos)?;
        crypto_in(&mut blk, hint)?;
        Ok(blk)
    }

    fn cache_miss(&mut self, pos: u64, hint: CryptoHint) -> FsResult<Option<Arc<Block>>> {
        let blk = self.fetch_from_backend(pos, hint)?;
        let ablk = Arc::new(blk);
        // read only cache, no write back
        let _ = self.lru.insert_and_get(pos, &ablk)?;
        Ok(Some(ablk))
    }
}


#[cfg(not(feature = "ro_cache_server"))]
pub struct ROCache {
    lru: Lru<u64, Block>,
    _capacity: usize,
    backend: Box<dyn ROStorage>,
}

impl ROCache {
    pub fn new(
        backend: Box<dyn ROStorage>,
        capacity: usize,
    ) -> Self {
        Self {
            lru: Lru::new(capacity),
            _capacity: capacity,
            backend,
        }
    }

    fn fetch_from_backend(&mut self, pos: u64, hint: CryptoHint) -> FsResult<Block> {
        let mut blk = self.backend.read_blk(pos)?;
        crypto_in(&mut blk, hint)?;
        Ok(blk)
    }

    fn cache_miss(&mut self, pos: u64, hint: CryptoHint) -> FsResult<Arc<Block>> {
        let blk = self.fetch_from_backend(pos, hint)?;
        let ablk = Arc::new(blk);
        // read only cache, no write back
        let _ = self.lru.insert_and_get(pos, &ablk)?;
        Ok(ablk)
    }

    pub fn get_blk_try(&mut self, pos: u64, cachable: bool) -> FsResult<Option<Arc<Block>>> {
        if cachable {
            self.lru.get(&pos)
        } else {
            Ok(None)
        }
    }

    pub fn get_blk_hint(
        &mut self, pos: u64, cachable: bool, hint: CryptoHint
    ) -> FsResult<Arc<Block>> {
        if cachable {
            match self.lru.get(&pos) {
                Ok(Some(ablk)) => Ok(ablk),
                Ok(None) => {
                    // cache miss, get from backend
                    self.cache_miss(pos, hint)
                }
                Err(e) => Err(e),
            }
        } else {
            self.fetch_from_backend(pos, hint).map(
                |blk| Arc::new(blk)
            )
        }
    }

    pub fn flush(&mut self) -> FsResult<()> {
        self.lru.flush_no_wb()
    }
}

pub fn rw_cache_cap_defaults(htree_len: usize) -> usize {
    let mut cap = htree_len / 10;
    if cap < 4 {
        cap = 4;
    } else if cap > 32 {
        cap = 32;
    }
    cap
}

pub type RWPayLoad = RwLock<Block>;
pub struct RWCache {
    lru: Lru<u64, RWPayLoad>,
    capacity: usize,
}

impl RWCache {
    pub fn new(
        capacity: usize,
    ) -> Self {
        Self {
            lru: Lru::new(capacity),
            capacity,
        }
    }

    pub fn get_cap(&self) -> usize {
        self.capacity
    }

    pub fn get_blk_try(&mut self, pos: u64) -> FsResult<Option<Arc<RWPayLoad>>> {
        self.lru.get(&pos)
    }

    pub fn insert_and_get(
        &mut self, pos: u64, blk: Block
    ) -> FsResult<(Arc<RWPayLoad>, Option<(u64, Block)>)> {
        let apay = Arc::new(RwLock::new(blk));
        self.lru.insert_and_get(pos, &apay).map(
            |wb| (apay, wb.map(
                |(k, v)| (k, v.into_inner())
            ))
        )
    }

    pub fn mark_dirty(&mut self, pos: u64) -> FsResult<()> {
        self.lru.mark_dirty(&pos)
    }

    #[allow(unused)]
    pub fn flush(&mut self) -> FsResult<Vec<(u64, Block)>> {
        self.lru.flush_wb().map(
            |l| {
                l.into_iter().map(
                    |(k, v)| (k, v.into_inner())
                ).collect()
            }
        )
    }

    pub fn flush_key(&mut self, pos: u64) -> FsResult<Option<Block>> {
        Ok(self.lru.try_pop_key(&pos, false)?.map(
            |payload| payload.into_inner()
        ))
    }

    pub fn flush_keys(&mut self) -> FsResult<Vec<u64>> {
        self.lru.flush_keys()
    }
}
