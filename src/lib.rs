pub mod vfs;
pub mod overlay;
pub mod ro;
pub mod rw;
pub(crate) mod bcache;
pub(crate) mod htree;
pub(crate) mod storage;
pub(crate) mod crypto;
pub(crate) mod lru;
pub mod error;
pub use error::*;
pub use bcache::DEFAULT_CACHE_CAP;
use crypto::*;
use std::mem::{self, size_of};
pub use log::{warn, info, debug};


pub const MAX_LOOP_CNT: u64 = 10000;

pub const BLK_SZ: usize = 4096;
pub type Block = [u8; 4096];

pub const ROOT_INODE_ID: u64 = 1;

#[derive(Clone, Debug)]
pub enum FSMode {
    Encrypted(Key128, MAC128),
    IntegrityOnly(Hash256),
}

impl FSMode {
    pub fn new_zero(encrypted: bool) -> Self {
        Self::from_key_entry([0u8; 32], encrypted)
    }

    pub fn from_key_entry(ke: KeyEntry, encrypted: bool) -> Self {
        if encrypted {
            let (key, mac): (Key128, MAC128) = unsafe {
                mem::transmute(ke)
            };
            Self::Encrypted(key, mac)
        } else {
            Self::IntegrityOnly(ke as Hash256)
        }
    }

    pub fn new_with_key(key: Option<Key128>) -> Self {
        if let Some(key) = key {
            Self::Encrypted(key, [0u8; size_of::<MAC128>()])
        } else {
            Self::IntegrityOnly([0u8; size_of::<Hash256>()])
        }
    }

    pub fn is_encrypted(&self) -> bool {
        if let Self::Encrypted(_, _) = self {
            true
        } else {
            false
        }
    }

    pub fn into_key_entry(self) -> KeyEntry {
        match self {
            Self::Encrypted(key, mac) => {
                unsafe {
                    mem::transmute((key, mac))
                }
            }
            Self::IntegrityOnly(hash) => hash,
        }
    }

    pub fn get_key(&self) -> Option<Key128> {
        match self {
            Self::Encrypted(key, _) => Some(key.clone()),
            Self::IntegrityOnly(_) => None,
        }
    }

    pub fn is_empty(&self) -> bool {
        match self {
            Self::Encrypted(key, mac)
                => *key == [0u8; size_of::<Key128>()]
                    && *mac == [0u8; size_of::<MAC128>()],
            Self::IntegrityOnly(hash)
                => *hash == [0u8; size_of::<Hash256>()],
        }
    }
}

macro_rules! read_from_blob {
    ($T: ty) => {
        impl AsMut<[u8]> for $T {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                let ptr = self as *mut $T as *mut u8;
                unsafe { std::slice::from_raw_parts_mut(ptr, std::mem::size_of::<$T>()) }
            }
        }
    };
}
pub(crate) use read_from_blob;

macro_rules! write_to_blob {
    ($T: ty) => {
        impl AsRef<[u8]> for $T {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                let ptr = self as *const $T as *const u8;
                unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<$T>()) }
            }
        }
    };
}
pub(crate) use write_to_blob;

#[macro_export]
macro_rules! rw_as_blob {
    ($T: ty) => {
        crate::read_from_blob!($T);
        crate::write_to_blob!($T);
    };
}

#[macro_export]
macro_rules! mutex_lock {
    ($mu: expr) => {
        $mu.lock().map_err(|_| FsError::MutexError)?
    };
}

#[macro_export]
macro_rules! rwlock_read {
    ($mu: expr) => {
        $mu.read().map_err(|_| FsError::RwLockError)?
    };
}

#[macro_export]
macro_rules! rwlock_write {
    ($mu: expr) => {
        $mu.write().map_err(|_| FsError::RwLockError)?
    };
}

#[macro_export]
macro_rules! io_try {
    ($e: expr) => {
        $e.map_err(|e| Into::<FsError>::into(e))?
    };
}

#[macro_export]
macro_rules! blk2byte {
    ($e: expr) => {
        (BLK_SZ * $e as usize) as u64
    };
}
