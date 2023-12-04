use std::sync::Arc;
use crate::storage::{ROStorage, RWStorage, RODirectStorage, RWDirectStorage};
use crate::storage::{ToBlock, ToBlockMut};
use crate::*;
use crate::blru::{BlockLru, LruPayload};
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::ops::{Deref, DerefMut};


enum ROCacheReq {
    Get {
        pos: u64,
        cachable: bool,
        reply: Sender<FsResult<Arc<dyn ToBlock + Send + Sync>>>,
    },
    Put {
        pos: u64,
        cachable: bool,
    }
}

// superblock is not in cache, and stick to memory during runtime
pub struct ROCache {
    tx_to_server: Sender<ROCacheReq>,
    server_handle: Option<JoinHandle<()>>,
}

struct ROCacheServer {
    rx: Receiver<ROCacheReq>,
    lru: BlockLru,
    capacity: usize,
    backend: Box<dyn RODirectStorage>,
}

// const DEFAULT_CHANNEL_SIZE: usize = 20;

struct CacheReadGuard(LruPayload);

impl ToBlock for CacheReadGuard {
    // type Target<'a> = RwLockReadGuard<'a, Block>;
    fn to_blk<'a>(&'a self) -> Box<dyn Deref<Target = Block> + 'a> {
        Box::new(self.0.read().unwrap())
    }
}

impl ROCache {
    pub fn new(
        backend: Box<dyn RODirectStorage>,
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
        backend: Box<dyn RODirectStorage>,
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
            ROCacheReq::Get { pos, cachable, reply } => {
                if cachable {
                    match self.lru.get(pos) {
                        Ok(Some(ablk)) => {
                            reply.send(Ok(Arc::new(CacheReadGuard(ablk)))).unwrap();
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            match self.cache_miss(pos) {
                                Ok(ablk) =>
                                reply.send(Ok(Arc::new(CacheReadGuard(ablk)))).unwrap(),
                                Err(e) => reply.send(Err(e)).unwrap(),
                            }
                        }
                        Err(e) => reply.send(Err(e)).unwrap(),
                    }
                } else {
                    reply.send(self.backend.get_blk_read(pos, cachable)).unwrap();
                }
            }
            ROCacheReq::Put { pos, cachable } => {
                if !cachable {
                    self.backend.get_blk_read(pos, cachable).unwrap();
                }
            }
        }
    }

    fn cache_miss(&mut self, pos: u64) -> FsResult<LruPayload> {
        let blk = self.backend.read_direct(pos)?;
        let ablk = Arc::new(RwLock::new(blk));
        // read only cache, no write back
        let _ = self.lru.insert_and_get(pos, &ablk)?;
        Ok(ablk)
    }
}

impl ROStorage for ROCache {
    fn get_blk_read<'a>(
        &mut self, pos: u64, cachable: bool
    ) -> FsResult<Arc<dyn ToBlock + Send + Sync>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(ROCacheReq::Get {
            pos,
            cachable,
            reply: tx,
        }).map_err(|_| FsError::SendError)?;

        let ablk = rx.recv().map_err(|_| FsError::RecvError)??;

        // Ok(Arc::new(CacheReadGuard::new(ablk)?))
        // Ok(Arc::new(ablk.read().map_err(|_| FsError::LockError)?))
        Ok(ablk)
    }

    fn put_blk_read(&mut self, pos: u64, cachable: bool) -> FsResult<()> {
        self.tx_to_server.send(ROCacheReq::Put {
            pos,
            cachable,
        }).map_err(|_| FsError::SendError)?;

        Ok(())
    }
}

pub struct RWCache {
    tx_to_server: Sender<RWCacheReq>,
    server_handle: Option<JoinHandle<()>>,
}

struct RWCacheServer {
    rx: Receiver<RWCacheReq>,
    lru: BlockLru,
    capacity: usize,
    backend: Box<dyn RWDirectStorage>,
}

enum RWCacheReq {
    GetRead {
        pos: u64,
        cachable: bool,
        reply: Sender<FsResult<Arc<dyn ToBlock + Send + Sync>>>,
    },
    GetWrite {
        pos: u64,
        cachable: bool,
        reply: Sender<FsResult<Arc<dyn ToBlockMut + Send + Sync>>>,
    },
    PutRead {
        pos: u64,
        cachable: bool,
    },
    PutWrite {
        pos: u64,
        cachable: bool,
    },
}

struct CacheWriteGuard(LruPayload);

impl ToBlockMut for CacheWriteGuard {
    // type Target<'a> = RwLockReadGuard<'a, Block>;
    fn to_blk_mut<'a>(&'a mut self) -> Box<dyn DerefMut<Target = Block> + 'a> {
        Box::new(self.0.write().unwrap())
    }
}

impl RWCache {
    pub fn new(
        backend: Box<dyn RWDirectStorage>,
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
}

impl ROStorage for RWCache {
    fn get_blk_read<'a>(
        &mut self, pos: u64, cachable: bool
    ) -> FsResult<Arc<dyn ToBlock + Send + Sync>> {
        unimplemented!();
    }

    fn put_blk_read(&mut self, pos: u64, cachable: bool) -> FsResult<()> {
        unimplemented!();
    }
}

impl RWStorage for RWCache {
    fn get_blk_write(
        &mut self, pos: u64, _cachable: bool
    ) -> FsResult<Arc<dyn ToBlockMut + Send + Sync>> {
        unimplemented!();
    }

    fn put_blk_write(&mut self, pos: u64, cachable: bool) -> FsResult<()> {
        unimplemented!();
    }
}

impl RWCacheServer {
    fn new(
        backend: Box<dyn RWDirectStorage>,
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
            RWCacheReq::GetRead { pos, cachable, reply } => {
                if cachable {
                    match self.lru.get(pos) {
                        Ok(Some(ablk)) => {
                            reply.send(Ok(Arc::new(CacheReadGuard(ablk)))).unwrap();
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            match self.cache_miss(pos) {
                                Ok(ablk) =>
                                reply.send(Ok(Arc::new(CacheReadGuard(ablk)))).unwrap(),
                                Err(e) => reply.send(Err(e)).unwrap(),
                            }
                        }
                        Err(e) => reply.send(Err(e)).unwrap(),
                    }
                } else {
                    reply.send(self.backend.get_blk_read(pos, cachable)).unwrap();
                }
            }
            RWCacheReq::PutRead { pos, cachable } => {
                if !cachable {
                    self.backend.get_blk_read(pos, cachable).unwrap();
                }
            }
            RWCacheReq::GetWrite { pos, cachable, reply } => {
                if cachable {
                    match self.lru.get(pos) {
                        Ok(Some(ablk)) => {
                            reply.send(Ok(Arc::new(CacheWriteGuard(ablk)))).unwrap();
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            match self.cache_miss(pos) {
                                Ok(ablk) =>
                                reply.send(Ok(Arc::new(CacheWriteGuard(ablk)))).unwrap(),
                                Err(e) => reply.send(Err(e)).unwrap(),
                            }
                        }
                        Err(e) => reply.send(Err(e)).unwrap(),
                    }
                } else {
                    reply.send(self.backend.get_blk_write(pos, cachable)).unwrap();
                }
            }
            RWCacheReq::PutWrite { pos, cachable } => {
                if !cachable {
                    self.backend.get_blk_read(pos, cachable).unwrap();
                }
            }
        }
    }

    fn cache_miss(&mut self, pos: u64) -> FsResult<LruPayload> {
        let blk = self.backend.read_direct(pos)?;
        let ablk = Arc::new(RwLock::new(blk));
        if let Some((pos, blk)) = self.lru.insert_and_get(pos, &ablk)? {
            self.backend.write_direct(pos, &blk)?;
        }
        Ok(ablk)
    }
}
