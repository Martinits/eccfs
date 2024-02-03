#![feature(int_roundings)]

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
use self::crypto::*;
use std::mem::{self, size_of};
pub use log::{warn, info, debug};


pub const MAX_LOOP_CNT: u64 = 10000;

pub const BLK_SZ: usize = 4096;
pub type Block = [u8; 4096];

pub const ROOT_INODE_ID: u64 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Clone)]
pub enum CryptoHint {
    Encrypted(Key128, MAC128, u64), // key, mac, nonce
    IntegrityOnly(Hash256),
}

impl CryptoHint {
    pub fn from_fsmode(fsmode: FSMode, nonce: u64) -> Self {
        match fsmode {
            FSMode::IntegrityOnly(hash) => CryptoHint::IntegrityOnly(hash),
            FSMode::Encrypted(key, mac) => CryptoHint::Encrypted(key, mac, nonce),
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
        $mu.lock().map_err(|_| new_error!(FsError::MutexError))?
    };
}

#[macro_export]
macro_rules! rwlock_read {
    ($mu: expr) => {
        $mu.read().map_err(|_| new_error!(FsError::RwLockError))?
    };
}

#[macro_export]
macro_rules! rwlock_write {
    ($mu: expr) => {
        $mu.write().map_err(|_| new_error!(FsError::RwLockError))?
    };
}

pub mod io_wrapper {
    use std::io::prelude::*;
    use std::io::SeekFrom;
    use crate::*;
    use std::mem::size_of;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::FileExt;

    pub fn write_vec_as_bytes<T>(f: &mut File, v: &Vec<T>) -> FsResult<()> {
        io_try!(f.write_all(
            unsafe {
                std::slice::from_raw_parts(
                    v.as_ptr() as *const u8,
                    v.len() * size_of::<T>()
                )
            }
        ));
        Ok(())
    }

    pub fn write_file_at(f: &mut File, seek: u64, b: &[u8]) -> FsResult<()> {
        if io_try!(f.write_at(b, seek)) != b.len() {
            return Err(new_error!(FsError::UnexpectedEof));
        }
        Ok(())
    }

    pub fn read_file_at(f: &mut File, seek: u64, b: &mut [u8]) -> FsResult<usize> {
        Ok(io_try!(f.read_at(b, seek)))
    }

    pub fn get_file_pos(f: &mut File) -> FsResult<u64> {
        Ok(io_try!(f.seek(SeekFrom::Current(0))))
    }

    pub fn round_file_up_to_blk(f: &mut File) -> FsResult<u64> {
        let len = io_try!(f.seek(SeekFrom::End(0))).next_multiple_of(BLK_SZ as u64);
        io_try!(f.set_len(len));
        Ok(len / BLK_SZ as u64)
    }

    pub fn get_file_sz(f: &mut File) -> FsResult<u64> {
        let org_pos = get_file_pos(f)?;
        let len = io_try!(f.seek(SeekFrom::End(0)));
        io_try!(f.seek(SeekFrom::Start(org_pos)));
        Ok(len)
    }

    #[macro_export]
    macro_rules! io_try {
        ($e: expr) => {
            $e.map_err(|e| new_error!(FsError::IOError(e)))?
        };
    }
}
pub use io_wrapper::*;

#[macro_export]
macro_rules! blk2byte {
    ($e: expr) => {
        (BLK_SZ * $e as usize) as u64
    };
}
