use std::sync::Arc;
use crate::storage::ROStorage;
use crate::*;
use crate::lru::Lru;
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::RwLock;
use std::thread::{self, JoinHandle};
use crate::crypto::*;


#[derive(Clone)]
pub enum CacheMissHint {
    Encrypted(Key128, MAC128, u64), // key, mac, nonce
    IntegrityOnly(Hash256),
}

impl CacheMissHint {
    pub fn from_fsmode(fsmode: FSMode, nonce: u64) -> Self {
        match fsmode {
            FSMode::IntegrityOnly(hash) => CacheMissHint::IntegrityOnly(hash),
            FSMode::Encrypted(key, mac) => CacheMissHint::Encrypted(key, mac, nonce),
        }
    }

    pub fn is_encrypted(&self) -> bool {
        if let Self::Encrypted(_, _, _) = self {
            true
        } else {
            false
        }
    }

    pub fn from_key_entry(ke: KeyEntry, encrypted: bool, nonce: u64) -> Self {
        Self::from_fsmode(FSMode::from_key_entry(ke, encrypted), nonce)
    }
}

enum ROCacheReq {
    Get {
        pos: u64,
        cachable: bool,
        miss_hint: Option<CacheMissHint>,
        reply: Sender<FsResult<Option<Arc<Block>>>>,
    },
    Flush,
}

// superblock is not in cache, and stick to memory during runtime
#[derive(Clone)]
pub struct ROCache {
    tx_to_server: Sender<ROCacheReq>,
    // server_handle: Option<JoinHandle<()>>,
}

pub const DEFAULT_CACHE_CAP: usize = 2048;

struct ROCacheServer {
    rx: Receiver<ROCacheReq>,
    lru: Lru<u64, Block>,
    capacity: usize,
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
                    Ok(req) => server.process(req),
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
        &mut self, pos: u64, cachable: bool, hint: CacheMissHint
    ) -> FsResult<Arc<Block>> {
        self.get_blk_impl(pos, cachable, Some(hint))?.ok_or(FsError::NotFound)
    }

    fn get_blk_impl(
        &mut self, pos: u64, cachable: bool, hint: Option<CacheMissHint>
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
            capacity,
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
        }
    }

    fn fetch_from_backend(&mut self, pos: u64, hint: CacheMissHint) -> FsResult<Block> {
        let mut blk = self.backend.read_blk(pos)?;
        match hint {
            CacheMissHint::Encrypted(key, mac, nonce) => {
                aes_gcm_128_blk_dec(&mut blk, &key, &mac, nonce)?;
            }
            CacheMissHint::IntegrityOnly(hash) => {
                sha3_256_blk_check(&blk, &hash)?;
            }
        }
        Ok(blk)
    }

    fn cache_miss(&mut self, pos: u64, hint: CacheMissHint) -> FsResult<Option<Arc<Block>>> {
        let blk = self.fetch_from_backend(pos, hint)?;
        let ablk = Arc::new(blk);
        // read only cache, no write back
        let _ = self.lru.insert_and_get(pos, &ablk)?;
        Ok(Some(ablk))
    }
}


pub struct RWCache {
    tx_to_server: Sender<RWCacheReq>,
    // server_handle: Option<JoinHandle<()>>,
}

pub type RWPayLoad = RwLock<Block>;
struct RWCacheServer {
    rx: Receiver<RWCacheReq>,
    lru: Lru<u64, RWPayLoad>,
    capacity: usize,
}

enum RWCacheReq {
    Get {
        pos: u64,
        reply: Sender<FsResult<Option<Arc<RWPayLoad>>>>,
    },
    InsertGet {
        pos: u64,
        blk: Block,
        reply: Sender<FsResult<(Arc<RWPayLoad>, Option<(u64, Block)>)>>,
    },
    Flush {
        reply: Sender<FsResult<Vec<(u64, Block)>>>,
    }
}

impl RWCache {
    pub fn new(
        capacity: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel();

        let mut server = RWCacheServer::new(capacity, rx);

        let handle = thread::spawn(move || {
            loop {
                match server.rx.recv() {
                    Ok(req) => server.process(req),
                    Err(e) => panic!("Cache server received an error: {:?}", e),
                }
            }
        });

        Self {
            tx_to_server: tx,
            // server_handle: Some(handle),
        }
    }

    pub fn get_blk_try(&mut self, pos: u64) -> FsResult<Option<Arc<RWPayLoad>>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(RWCacheReq::Get {
            pos,
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        let ret = rx.recv().map_err(|_| FsError::ChannelRecvError)??;

        Ok(ret)
    }

    pub fn insert_and_get(
        &mut self, pos: u64, blk: Block
    ) -> FsResult<(Arc<RWPayLoad>, Option<(u64, Block)>)> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(RWCacheReq::InsertGet {
            pos,
            blk,
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        let ret = rx.recv().map_err(|_| FsError::ChannelRecvError)??;

        Ok(ret)
    }

    pub fn flush(&mut self) -> FsResult<Vec<(u64, Block)>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(RWCacheReq::Flush {
            reply: tx,
        }).map_err(|_| FsError::ChannelSendError)?;

        let ret = rx.recv().map_err(|_| FsError::ChannelRecvError)??;

        Ok(ret)
    }
}

impl RWCacheServer {
    fn new(
        capacity: usize,
        rx: Receiver<RWCacheReq>,
    ) -> Self {
        Self {
            rx,
            capacity,
            lru: Lru::new(capacity),
        }
    }

    fn process(&mut self, req: RWCacheReq) {
        match req {
            RWCacheReq::Get { reply, pos } => {
                let send = self.lru.get(&pos);
                reply.send(send).unwrap();
            }
            RWCacheReq::InsertGet { pos, blk, reply } => {
                let apay = Arc::new(RwLock::new(blk));
                let send = self.lru.insert_and_get(pos, &apay).map(
                    |wb| (apay, wb.map(
                        |(k, v)| (k, v.into_inner().unwrap())
                    ))
                );
                reply.send(send).unwrap();
            }
            RWCacheReq::Flush { reply } => {
                let send = match self.lru.flush_wb() {
                    Ok(l) => {
                        Ok(l.into_iter().map(
                            |(k, v)| (k, v.into_inner().unwrap())
                        ).collect())
                    },
                    Err(e) => Err(e),
                };
                reply.send(send).unwrap();
            }
        }
    }
}
