use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use crate::*;
use std::path::Path;

pub trait ROStorage: Send + Sync {
    fn read_blk(&mut self, pos: u64) -> FsResult<Block>;
    fn read_blk_to(&mut self, pos: u64, to: &mut Block) -> FsResult<()>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()>;
    fn set_len(&mut self, nr_blk: u64) -> FsResult<()>;
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

    pub fn get_len(&mut self) -> FsResult<u64> {
        get_file_sz(&mut self.handle)
    }
}

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
            Err(FsError::UnexpectedEof)
        } else {
            io_try!(self.handle.read_exact(to));
            Ok(())
        }
    }
}

impl RWStorage for FileStorage {
    fn write_blk(&mut self, pos: u64, from: &Block) -> FsResult<()> {
        if !self.writable {
            return Err(FsError::PermissionDenied);
        }
        let cur_len = io_try!(self.handle.seek(SeekFrom::End(0)));

        assert!(blk2byte!(pos) < cur_len);

        let position = io_try!(self.handle.seek(SeekFrom::Start(blk2byte!(pos))));
        if position != blk2byte!(pos) {
            Err(FsError::UnexpectedEof)
        } else {
            Ok(io_try!(self.handle.write_all(from)))
        }
    }

    fn set_len(&mut self, nr_blk: u64) -> FsResult<()> {
        let len = blk2byte!(nr_blk);
        io_try!(self.handle.set_len(len));
        Ok(())
    }
}
