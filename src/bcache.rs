use std::sync::Arc;
use crate::storage::{ROStorage, RWStorage, RODirectStorage, RWDirectStorage};
use crate::storage::{ToBlock, ToBlockMut};
use crate::*;
use crate::blru::{BlockLru, LruPayload};
use std::sync::mpsc::{self, Sender, Receiver};
use std::sync::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use std::thread::{self, JoinHandle};
use std::ops::{Deref, DerefMut};


enum CacheReq {
    Get {
        pos: u64,
        write: bool,
        cachable: bool,
        reply: Sender<FsResult<LruPayload>>,
    },
    Put {
        pos: u64,
        cachable: bool,
        write: bool,
    }
}

// superblock is not in cache, and stick to memory during runtime
pub struct ROCache {
    tx_to_server: Sender<CacheReq>,
    server_handle: Option<JoinHandle<()>>,
}

struct ROCacheServer {
    rx: Receiver<CacheReq>,
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
        rx: Receiver<CacheReq>,
    ) -> Self {
        Self {
            rx,
            backend,
            capacity,
            lru: BlockLru::new(capacity),
        }
    }

    fn process(&mut self, req: CacheReq) {
        match req {
            CacheReq::Get { pos, write, cachable, reply } => {
                if write {
                    reply.send(Err(FsError::PermissionDenied)).unwrap();
                } else if cachable {
                    match self.lru.get(pos) {
                        Ok(Some(ablk)) => {
                            reply.send(Ok(ablk)).unwrap();
                        }
                        Ok(None) => {
                            // cache miss, get from backend
                            reply.send(self.cache_miss(pos)).unwrap();
                        }
                        Err(e) => reply.send(Err(e)).unwrap(),
                    }
                } else {
                    self.backend.get_blk_read(pos, cachable).unwrap();
                }
            }
            CacheReq::Put { pos, cachable, write } => {
                if !write && !cachable {
                    self.backend.get_blk_read(pos, cachable).unwrap();
                }
            }
        }
    }

    fn cache_miss(&mut self, pos: u64) -> FsResult<LruPayload> {
        let blk = self.backend.read_direct(pos)?;
        let ablk = Arc::new(RwLock::new(blk));
        let _ = self.lru.insert_and_get(pos, &ablk)?;
        Ok(ablk)
    }
}

impl ROStorage for ROCache {
    fn get_blk_read<'a>(
        &mut self, pos: u64, cachable: bool
    ) -> FsResult<Arc<dyn ToBlock>> {
        let (tx, rx) = mpsc::channel();
        self.tx_to_server.send(CacheReq::Get {
            pos,
            cachable,
            write: false,
            reply: tx,
        }).map_err(|_| FsError::SendError)?;

        let ablk = rx.recv().map_err(|_| FsError::RecvError)??;

        // Ok(Arc::new(CacheReadGuard::new(ablk)?))
        // Ok(Arc::new(ablk.read().map_err(|_| FsError::LockError)?))
        Ok(Arc::new(CacheReadGuard(ablk)))
    }

    fn put_blk_read(&mut self, pos: u64, cachable: bool) -> FsResult<()> {
        self.tx_to_server.send(CacheReq::Put {
            pos,
            cachable,
            write: false,
        }).map_err(|_| FsError::SendError)?;

        Ok(())
    }
}

pub struct RWCache {
    backend: Arc<dyn RWStorage>,
}

impl RWCache {
    pub fn new(capacity: usize, backend: Arc<dyn RWStorage>) -> Self {
        Self {
            backend,
        }
    }
}

impl ROStorage for RWCache {
    fn get_blk_read<'a>(
        &mut self, pos: u64, cachable: bool
    ) -> FsResult<Arc<dyn ToBlock>> {
        unimplemented!();
    }

    fn put_blk_read(&mut self, pos: u64, cachable: bool) -> FsResult<()> {
        unimplemented!();
    }
}

impl RWStorage for RWCache {
    fn get_blk_write(
        &mut self, pos: u64, _cachable: bool
    ) -> FsResult<Arc<dyn DerefMut<Target = Block>>> {
        unimplemented!();
    }

    fn put_blk_write(&mut self, pos: u64, cachable: bool) -> FsResult<()> {
        unimplemented!();
    }
}
