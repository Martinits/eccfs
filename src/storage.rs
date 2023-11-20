use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::{ErrorKind, SeekFrom};
use crate::*;

pub trait ROStorage: Send + Sync {
    fn read_blk(&mut self, pos: u64, to: &mut [u8], cachable: bool) -> FsResult<()>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn write_blk(&mut self, pos: u64, from: &[u8], cachable: bool) -> FsResult<()>;
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
    fn read_blk(&mut self, pos: u64, to: &mut [u8], _cachable: bool) -> FsResult<()> {
        assert_eq!(to.len(), BLK_SZ);

        let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
            .map_err( |e| Into::<FsError>::into(e) )?;
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            Ok(self.handle.read_exact(to).map_err(
                |e| Into::<FsError>::into(e)
            )?)
        }
    }
}

impl RWStorage for FileStorage {
    fn write_blk(&mut self, pos: u64, from: &[u8], _cachable: bool) -> FsResult<()> {
        assert_eq!(from.len(), BLK_SZ);

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
    fn read_blk(&mut self, pos: u64, to: &mut [u8], _cachable: bool) -> FsResult<()> {
        unimplemented!();
    }
}

impl RWStorage for DeviceStorage {
    fn write_blk(&mut self, pos: u64, from: &[u8], _cachable: bool) -> FsResult<()> {
        unimplemented!();
    }
}

// pub trait ROImage: Send + Sync {
//     fn open(self, path: &Path, start: u64, length: u64);
//
//     fn read_blk(self, pos: u64);
//
//     fn close(self);
// }
//
// pub trait RWImage: ROImage + Send + Sync {
//     fn create(self, path: &Path);
//
//     fn write_blk(self, pos: u64);
//
//     fn remove(self);
// }
