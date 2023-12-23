use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use crate::*;
use std::path::Path;

pub trait ROStorage: Send + Sync {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()>;
}

pub struct FileStorage {
    // path: String,
    handle: File,
    writable: bool,
}

impl FileStorage {
    pub fn new(path: &Path, writable: bool) -> FsResult<Self> {
        let handle = io_try!(OpenOptions::new().read(true).write(writable).open(path));

        Ok(Self {
            handle,
            // path: path.to_str().unwrap().to_string(),
            writable,
        })
    }
}

impl ROStorage for FileStorage {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block> {
        let position = io_try!(self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64)));
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            let mut blk = [0u8; BLK_SZ] as Block;
            io_try!(self.handle.read_exact(&mut blk));
            Ok(blk)
        }
    }
}

impl RWStorage for FileStorage {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()> {
        let position = io_try!(self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64)));
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            Ok(io_try!(self.handle.write_all(from)))
        }
    }
}

pub struct DeviceStorage {
    path: String,
    writable: bool,
}

impl ROStorage for DeviceStorage {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block> {
        unimplemented!();
    }
}

impl RWStorage for DeviceStorage {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()> {
        unimplemented!();
    }
}
