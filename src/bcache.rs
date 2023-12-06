use std::sync::Arc;
use crate::storage::{ROStorage, RWStorage};
use crate::*;
use crate::blru::BlockLru;
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::RwLock;
use std::thread::{self, JoinHandle};
use crate::crypto::*;


#[derive(Clone)]
pub enum CacheLoadMeta {
    Encrypted(Key128, MAC128),
    IntegrityOnly(Hash256),
}

enum ROCacheReq {
    Get {
        pos: u64,
        cachable: bool,
        miss_hint: Option<CacheLoadMeta>,
        reply: Sender<FsResult<Option<Arc<Block>>>>,
    },
    Flush,
}

// superblock is not in cache, and stick to memory during runtime
pub struct ROCache {
    tx_to_server: Sender<ROCacheReq>,
    server_handle: Option<JoinHandle<()>>,
}

struct ROCacheServer {
    rx: Receiver<ROCacheReq>,
    lru: BlockLru<Block>,
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
            server_handle: Some(handle),
        }
    }

    pub fn get_blk(&mut self, pos: u64, cachable: bool) -> FsResult<Option<Arc<Block>>> {
        self.get_blk_impl(pos, cachable, None)
    }

    pub fn get_blk_hint(
        &mut self, pos: u64, cachable: bool, hint: CacheLoadMeta
    ) -> FsResult<Arc<Block>> {
        self.get_blk_impl(pos, cachable, Some(hint))?.ok_or(FsError::NotFound)
    }

    fn get_blk_impl(
        &mut self, pos: u64, cachable: bool, hint: Option<CacheLoadMeta>
    ) -> FsResult<Option<Arc<Block>>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(ROCacheReq::Get {
            pos,
            cachable,
            reply: tx,
            miss_hint: hint,
        }).map_err(|_| FsError::SendError)?;

        let ablk = rx.recv().map_err(|_| FsError::RecvError)??;

        Ok(ablk)
    }

    pub fn flush(&mut self) -> FsResult<()> {
        self.tx_to_server.send(ROCacheReq::Flush).map_err(|_| FsError::SendError)
    }
}

// impl Drop for ROCache {
//     fn drop(&mut self) {
//         if let Some(join_handle) = self.server_handle.take() {
//             join_handle.join();
//         }
//     }
// }

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
            lru: BlockLru::new(capacity),
        }
    }

    fn process(&mut self, req: ROCacheReq) {
        match req {
            ROCacheReq::Get {cachable, reply, pos, miss_hint } => {
                let send = if cachable {
                    match self.lru.get(pos) {
                        Ok(Some(ablk)) => {
                            Ok(Some(ablk))
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            if let Some(hint) = miss_hint {
                                self.cache_miss(pos, hint)
                            } else {
                                Err(FsError::CacheNeedHint)
                            }
                        }
                        Err(e) => Err(e),
                    }
                } else if let Some(hint) = miss_hint {
                    self.fetch_from_backend(pos, hint).map(
                        |blk| Some(Arc::new(blk))
                    )
                } else {
                    Err(FsError::CacheNeedHint)
                };
                reply.send(send).unwrap();
            }
            ROCacheReq::Flush => {
                self.flush();
            }
        }
    }

    fn flush(&mut self) {
        self.lru.flush_no_wb();
    }

    fn fetch_from_backend(&mut self, pos: u64, hint: CacheLoadMeta) -> FsResult<Block> {
        let mut blk = self.backend.read_blk(pos)?;
        match hint {
            CacheLoadMeta::Encrypted(key, mac) => {
                aes_gcm_128_blk_dec(&mut blk, &key, &mac, pos)?;
            }
            CacheLoadMeta::IntegrityOnly(hash) => {
                let result = sha3_256_blk(&blk)?;
                if result != hash {
                    return Err(FsError::IntegrityCheckError);
                }
            }
        }
        Ok(blk)
    }

    fn cache_miss(&mut self, pos: u64, hint: CacheLoadMeta) -> FsResult<Option<Arc<Block>>> {
        let blk = self.fetch_from_backend(pos, hint)?;
        let ablk = Arc::new(blk);
        // read only cache, no write back
        let _ = self.lru.insert_and_get(pos, &ablk)?;
        Ok(Some(ablk))
    }
}


pub struct RWCache {
    tx_to_server: Sender<RWCacheReq>,
    server_handle: Option<JoinHandle<()>>,
}

type RWPayLoad = RwLock<Block>;
struct RWCacheServer {
    rx: Receiver<RWCacheReq>,
    lru: BlockLru<RWPayLoad>,
    capacity: usize,
    backend: Box<dyn RWStorage>,
}

enum RWCacheReq {
    Get {
        pos: u64,
        cachable: bool,
        reply: Sender<FsResult<Arc<RWPayLoad>>>,
    },
    Put {
        pos: u64,
        cachable: bool,
        dirty: Option<Arc<RWPayLoad>>,
        reply: Sender<FsResult<()>>,
    },
}

impl RWCache {
    pub fn new(
        backend: Box<dyn RWStorage>,
        capacity: usize,
    ) -> Self {
        let (tx, rx) = mpsc::channel();

        let mut server = RWCacheServer::new(backend, capacity, rx);

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
            server_handle: Some(handle),
        }
    }

    pub fn get_blk(
        &mut self, pos: u64, write: bool, cachable: bool
    ) -> FsResult<Arc<RWPayLoad>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(RWCacheReq::Get {
            pos,
            cachable,
            reply: tx,
        }).map_err(|_| FsError::SendError)?;

        let ablk = rx.recv().map_err(|_| FsError::RecvError)??;

        Ok(ablk)
    }

    pub fn put_blk(
        &mut self, pos: u64, write: bool, cachable: bool,
        dirty: Option<Arc<RWPayLoad>>,
    ) -> FsResult<()> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(RWCacheReq::Put {
            pos,
            cachable,
            dirty,
            reply: tx,
        }).map_err(|_| FsError::SendError)?;

        let ablk = rx.recv().map_err(|_| FsError::RecvError)??;

        Ok(ablk)
    }
}

impl RWCacheServer {
    fn new(
        backend: Box<dyn RWStorage>,
        capacity: usize,
        rx: Receiver<RWCacheReq>,
    ) -> Self {
        Self {
            rx,
            backend,
            capacity,
            lru: BlockLru::new(capacity),
        }
    }

    fn process(&mut self, req: RWCacheReq) {
        match req {
            RWCacheReq::Get { pos, cachable, reply } => {
                let send = if cachable {
                    match self.lru.get(pos) {
                        Ok(Some(ablk)) => {
                            Ok(ablk)
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            self.cache_miss(pos)
                        }
                        Err(e) => Err(e),
                    }
                } else {
                    // read from backend directly since not cachable
                    self.backend.read_blk(pos).map(
                        |blk| Arc::new(RwLock::new(blk))
                    )
                };
                reply.send(send).unwrap();
            }
            RWCacheReq::Put { pos, cachable, dirty, reply } => {
                let mut send = Ok(());
                if cachable {
                    if let Some(_) = dirty {
                        send = self.lru.mark_dirty(pos)
                    }
                } else if let Some(ablk) = dirty {
                    send = self.backend_dirty(pos, ablk)
                }
                reply.send(send).unwrap();
            }
        }
    }

    fn backend_dirty(&mut self, pos: u64, ablk: Arc<RWPayLoad>) -> FsResult<()> {
        let lockblk = Arc::into_inner(ablk).ok_or_else(
            || FsError::UnknownError
        )?;
        let blk = lockblk.into_inner().map_err(
            |_| FsError::UnknownError
        )?;
        self.backend.write_blk(pos, &blk)
    }

    fn cache_miss(&mut self, pos: u64) -> FsResult<Arc<RWPayLoad>> {
        let blk = self.backend.read_blk(pos)?;
        let ablk = Arc::new(RwLock::new(blk));
        if let Some((pos, lockblk)) = self.lru.insert_and_get(pos, &ablk)? {
            let blk = lockblk.into_inner().map_err(
                |_| FsError::UnknownError
            )?;
            self.backend.write_blk(pos, &blk)?;
        }
        Ok(ablk)
    }
}
