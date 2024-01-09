use std::sync::Arc;
use crate::storage::ROStorage;
use crate::*;
use crate::lru::Lru;
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::RwLock;
use std::thread;
use crate::crypto::*;


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
#[derive(Clone)]
pub struct ROCache {
    tx_to_server: Sender<ROCacheReq>,
    // server_handle: Option<JoinHandle<()>>,
}

pub const DEFAULT_CACHE_CAP: usize = 256;

struct ROCacheServer {
    rx: Receiver<ROCacheReq>,
    lru: Lru<u64, Block>,
    _capacity: usize,
    backend: Box<dyn ROStorage>,
}

// const DEFAULT_CHANNEL_SIZE: usize = 20;

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
        self.get_blk_impl(pos, cachable, Some(hint))?.ok_or(FsError::NotFound)
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
        }).map_err(|_| FsError::ChannelSendError)?;

        let ablk = rx.recv().map_err(|_| FsError::ChannelRecvError)??;

        Ok(ablk)
    }

    pub fn flush(&mut self) -> FsResult<()> {
        self.tx_to_server.send(ROCacheReq::Flush).map_err(|_| FsError::ChannelSendError)
    }

    pub fn abort(&mut self) -> FsResult<()> {
        self.tx_to_server.send(ROCacheReq::Abort).map_err(|_| FsError::ChannelSendError)
    }
}

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
                    // Err(FsError::CacheNeedHint)

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
                |(k, v)| (k, v.into_inner().unwrap())
            ))
        )
    }

    pub fn mark_dirty(&mut self, pos: u64) -> FsResult<()> {
        self.lru.mark_dirty(&pos)
    }

    pub fn flush(&mut self) -> FsResult<Vec<(u64, Block)>> {
        self.lru.flush_wb().map(
            |l| {
                l.into_iter().map(
                    |(k, v)| (k, v.into_inner().unwrap())
                ).collect()
            }
        )
    }
}
