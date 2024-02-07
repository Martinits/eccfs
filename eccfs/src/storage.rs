use crate::*;

#[cfg(feature = "std")]
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom},
    path::Path,
};
#[cfg(feature = "std")]
use std::sync::Mutex;
#[cfg(feature = "std")]
use std::os::unix::fs::FileExt;

extern crate alloc;
use alloc::sync::Arc;

pub trait ROStorage: Send + Sync {
    fn read_blk(&self, pos: u64) -> FsResult<Block> {
        let mut blk = [0u8; BLK_SZ] as Block;
        self.read_blk_to(pos, &mut blk)?;
        Ok(blk)
    }

    fn read_blk_to(&self, pos: u64, to: &mut Block) -> FsResult<()>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn write_blk(&self, pos: u64, from: &Block) -> FsResult<()>;
    fn get_len(&self) -> FsResult<u64>;
    fn set_len(&self, nr_blk: u64) -> FsResult<()>;
}

// for rw storage only, it should remember the fs_dir path
pub trait Device: Send + Sync {
    fn open_rw_storage(&self, path: &str) -> FsResult<Arc<dyn RWStorage>>;
    fn create_rw_storage(&self, path: &str) -> FsResult<Arc<dyn RWStorage>>;
    fn remove_storage(&self, path: &str) -> FsResult<()>;
    fn get_storage_len(&self, path: &str) -> FsResult<u64>;
    fn nr_storage(&self) -> FsResult<usize>;
}

#[cfg(feature = "std")]
pub struct FileStorage {
    f: Mutex<File>,
    writable: bool,
}

#[cfg(feature = "std")]
impl FileStorage {
    #[allow(unused)]
    pub fn new(path: &Path, writable: bool) -> FsResult<Self> {
        let f = io_try!(OpenOptions::new().read(true).write(writable).open(path));

        Ok(Self {
            f: Mutex::new(f),
            writable,
        })
    }
}

#[cfg(feature = "std")]
impl ROStorage for FileStorage {
    fn read_blk_to(&self, pos: u64, to: &mut Block) -> FsResult<()> {
        io_try!(mutex_lock!(self.f).read_exact_at(to, blk2byte!(pos)));
        Ok(())
    }
}

#[cfg(feature = "std")]
impl RWStorage for FileStorage {
    fn write_blk(&self, pos: u64, from: &Block) -> FsResult<()> {
        if !self.writable {
            return Err(new_error!(FsError::PermissionDenied));
        }

        let cur_len = self.get_len()?;
        let offset = blk2byte!(pos);

        // if offset >= cur_len {
        //     debug!("bad: write pos {} cur_len {}", pos, cur_len);
        // }
        assert!(offset < cur_len);

        Ok(io_try!(mutex_lock!(self.f).write_all_at(from, offset)))
    }

    fn set_len(&self, nr_blk: u64) -> FsResult<()> {
        let len = blk2byte!(nr_blk);
        io_try!(mutex_lock!(self.f).set_len(len));
        Ok(())
    }

    fn get_len(&self) -> FsResult<u64> {
        Ok(io_try!(mutex_lock!(self.f).seek(SeekFrom::End(0))))
    }
}
