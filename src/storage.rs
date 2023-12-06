use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{ErrorKind, SeekFrom};
use crate::*;

pub trait ROStorage: Send + Sync {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()>;
}

pub struct FileStorage {
    path: String,
    handle: File,
    writable: bool,
}

impl FileStorage {
    pub fn new(path: &String, writable: bool) -> FsResult<Self> {
        let handle = OpenOptions::new().read(true).write(writable)
            .open(path).map_err( |e| {
                Into::<FsError>::into(e.kind() as u32)
            })?;

        Ok(Self {
            handle,
            path: path.clone(),
            writable,
        })
    }
}

impl ROStorage for FileStorage {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block> {
        let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
            .map_err( |e| Into::<FsError>::into(e) )?;
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            let mut blk = [0u8; BLK_SZ as usize] as Block;
            self.handle.read_exact(&mut blk).map_err(
                |e| Into::<FsError>::into(e)
            )?;
            Ok(blk)
        }
    }
}

impl RWStorage for FileStorage {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()> {
        let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
            .map_err( |e| Into::<FsError>::into(e) )?;
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            Ok(self.handle.write_all(from).map_err(
                |e| Into::<FsError>::into(e)
            )?)
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
