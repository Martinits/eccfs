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
use std::mem;


pub const MAX_LOOP_CNT: u64 = 10001;

pub const BLK_SZ: u64 = 4096;
pub type Block = [u8; 4096];

pub const ROOT_INODE_ID: u64 = 1;

#[derive(Clone)]
pub enum FSMode {
    Encrypted(Key128, MAC128),
    IntegrityOnly(Hash256),
}

impl FSMode {
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

    pub fn is_encrypted(&self) -> bool {
        if let Self::Encrypted(_, _) = self {
            true
        } else {
            false
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
