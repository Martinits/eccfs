use crate::*;

#[cfg(feature = "std_file")]
use std::{
    fs::{File, OpenOptions},
    io::{prelude::*, SeekFrom},
    path::Path,
};

extern crate alloc;
use alloc::sync::Arc;

pub trait ROStorage: Send + Sync {
    fn read_blk(&self, pos: u64) -> FsResult<Block>;
    fn read_blk_to(&self, pos: u64, to: &mut Block) -> FsResult<()>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn write_blk(&self, pos: u64, from: &Block) -> FsResult<()>;
    fn get_len(&self) -> FsResult<u64>;
    fn set_len(&self, nr_blk: u64) -> FsResult<()>;
}

// for rw storage, it should remember the fs_dir path
// for ro storage, remember ro image path only
pub trait Device: Send + Sync {
    fn create_ro_storage(&self, path: &str) -> FsResult<Arc<dyn ROStorage>>;
    fn open_rw_storage(&self, path: &str) -> FsResult<Arc<dyn RWStorage>>;
    fn create_rw_storage(&self, path: &str) -> FsResult<Arc<dyn RWStorage>>;
    fn remove_storage(&self, path: &str) -> FsResult<()>;
    fn get_storage_len(&self, path: &str) -> FsResult<u64>;
    fn nr_storage(&self) -> FsResult<usize>;
}

#[cfg(feature = "std_file")]
pub struct FileStorage {
    // path: String,
    handle: File,
    writable: bool,
}

#[cfg(feature = "std_file")]
impl FileStorage {
    pub fn new(path: &Path, writable: bool) -> FsResult<Self> {
        let handle = io_try!(OpenOptions::new().read(true).write(writable).open(path));

        Ok(Self {
            handle,
            // path: path.to_str().unwrap().to_string(),
            writable,
        })
    }

    pub fn get_len(&mut self) -> FsResult<u64> {
        get_file_sz(&mut self.handle)
    }
}

#[cfg(feature = "std_file")]
impl ROStorage for FileStorage {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block> {
        let mut blk = [0u8; BLK_SZ] as Block;
        self.read_blk_to(pos, &mut blk)?;
        Ok(blk)
    }

    fn read_blk_to(&mut self, pos: u64, to: &mut Block) -> FsResult<()> {
        let cur_len = io_try!(self.handle.seek(SeekFrom::End(0)));
        assert!(blk2byte!(pos) < cur_len);
        let position = io_try!(self.handle.seek(SeekFrom::Start(blk2byte!(pos))));
        if position != blk2byte!(pos) {
            Err(new_error!(FsError::UnexpectedEof))
        } else {
            io_try!(self.handle.read_exact(to));
            Ok(())
        }
    }
}

#[cfg(feature = "std_file")]
impl RWStorage for FileStorage {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()> {
        if !self.writable {
            return Err(new_error!(FsError::PermissionDenied));
        }
        let cur_len = io_try!(self.handle.seek(SeekFrom::End(0)));

        // if blk2byte!(pos) >= cur_len {
        //     debug!("bad: write pos {} cur_len {}", pos, cur_len);
        // }
        assert!(blk2byte!(pos) < cur_len);

        let position = io_try!(self.handle.seek(SeekFrom::Start(blk2byte!(pos))));
        if position != blk2byte!(pos) {
            Err(new_error!(FsError::UnexpectedEof))
        } else {
            Ok(io_try!(self.handle.write_all(from)))
        }
    }

    fn set_len(&mut self, nr_blk: u64) -> FsResult<()> {
        // debug!("storage set len to {}", nr_blk);
        let len = blk2byte!(nr_blk);
        io_try!(self.handle.set_len(len));
        Ok(())
    }
}
