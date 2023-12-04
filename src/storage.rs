use std::fs::{File, OpenOptions};
use std::io::prelude::*;
use std::io::SeekFrom;
use crate::*;
use std::sync::Arc;
use std::collections::HashMap;
use std::ops::{Deref, DerefMut};

pub trait ToBlock {
    // type Target<'a>: 'a + Deref<Target = Block> where Self: 'a;
    fn to_blk<'a>(&'a self) -> Box<dyn Deref<Target = Block> + 'a>;
}

pub trait ToBlockMut {
    fn to_blk_mut(&mut self) -> Arc<dyn DerefMut<Target = Block>>;
}

pub trait ROStorage: Send + Sync {
    fn get_blk_read<'a>(&mut self, pos: u64, cachable: bool)
        -> FsResult<Arc<dyn ToBlock>>;

    fn put_blk_read(&mut self, pos: u64, cachable: bool) -> FsResult<()>;
}

pub trait RWStorage: ROStorage + Send + Sync {
    fn get_blk_write(&mut self, pos: u64, cachable: bool)
        -> FsResult<Arc<dyn DerefMut<Target = Block>>>;

    fn put_blk_write(&mut self, pos: u64, cachable: bool) -> FsResult<()>;
}

pub trait DirectRead: Send + Sync {
    fn read_direct(&mut self, pos: u64) -> FsResult<Block>;
}

pub trait DirectWrite: Send + Sync {
    fn write_direct(&mut self, pos: u64, blk: &dyn Deref<Target = Block>) -> FsResult<()>;
}

pub trait RODirectStorage: ROStorage + DirectRead {}
pub trait RWDirectStorage: RWStorage + DirectWrite + DirectRead {}

pub struct FileStorage {
    path: String,
    handle: File,
    write_list: Option<HashMap<u64, Arc<Box<Block>>>>,
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
            write_list: if writable {
                Some(HashMap::new())
            } else {
                None
            }
        })
    }
}

struct FileStorageGuard(Block);

impl ToBlock for FileStorageGuard {
    fn to_blk<'a>(&'a self) -> Box<dyn Deref<Target = Block> + 'a> {
        Box::new(&self.0)
    }
}

impl ROStorage for FileStorage {
    fn get_blk_read<'a>(
        &mut self, pos: u64, _cachable: bool
    ) -> FsResult<Arc<dyn ToBlock>> {
        let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
            .map_err( |e| Into::<FsError>::into(e) )?;
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            let mut blk = [0u8; BLK_SZ] as Block;
            self.handle.read_exact(&mut blk).map_err(
                |e| Into::<FsError>::into(e)
            )?;
            Ok(Arc::new(FileStorageGuard(blk)))
        }
    }

    fn put_blk_read(&mut self, _pos: u64, _cachable: bool) -> FsResult<()> {
        Ok(())
    }
}

impl RWStorage for FileStorage {
    fn get_blk_write(
        &mut self, pos: u64, _cachable: bool
    ) -> FsResult<Arc<dyn DerefMut<Target = Block>>> {
        if let Some(ref mut hash) = self.write_list {
            let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
                .map_err( |e| Into::<FsError>::into(e) )?;
            if position != pos * BLK_SZ as u64 {
                Err(FsError::NotSeekable)
            } else {
                let mut blk = [0u8; BLK_SZ] as Block;
                self.handle.read_exact(blk.as_mut()).map_err(
                    |e| Into::<FsError>::into(e)
                )?;
                let ablk = Arc::new(Box::new(blk));
                if let None = hash.insert(pos, ablk.clone()) {
                    Ok(ablk)
                } else {
                    Err(FsError::AlreadyExists)
                }
            }
        } else {
            Err(FsError::UnknownError)
        }
    }

    fn put_blk_write(&mut self, pos: u64, _cachable: bool) -> FsResult<()> {
        if let Some(ref mut hash) = self.write_list {
            let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
                .map_err( |e| Into::<FsError>::into(e) )?;
            if position != pos * BLK_SZ as u64 {
                Err(FsError::NotSeekable)
            } else {
                if let Some(ablk) = hash.remove(&pos) {
                    self.handle.write_all(ablk.as_ref().as_ref()).map_err(
                        |e| Into::<FsError>::into(e)
                    )
                } else {
                    Err(FsError::NotFound)
                }
            }
        } else {
            Err(FsError::UnknownError)
        }
    }
}

impl DirectRead for FileStorage {
    fn read_direct(&mut self, pos: u64) -> FsResult<Block> {
        let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
            .map_err( |e| Into::<FsError>::into(e) )?;
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            let mut blk = [0u8; BLK_SZ] as Block;
            self.handle.read_exact(blk.as_mut()).map_err(
                |e| Into::<FsError>::into(e)
            )?;
            Ok(blk)
        }
    }
}

impl DirectWrite for FileStorage {
    fn write_direct(
        &mut self, pos: u64, blk: &dyn Deref<Target = Block>
    ) -> FsResult<()> {
        let position = self.handle.seek(SeekFrom::Start(pos * BLK_SZ as u64))
            .map_err( |e| Into::<FsError>::into(e) )?;
        if position != pos * BLK_SZ as u64 {
            Err(FsError::NotSeekable)
        } else {
            self.handle.write_all(blk.as_ref()).map_err(
                |e| Into::<FsError>::into(e)
            )?;
            Ok(())
        }
    }
}

pub struct DeviceStorage {
    path: String,
    writable: bool,
}

impl ROStorage for DeviceStorage {
    fn get_blk_read<'a>(
        &mut self, pos: u64, _cachable: bool
    ) -> FsResult<Arc<dyn ToBlock>> {
        unimplemented!();
    }
    fn put_blk_read(&mut self, _pos: u64, _cachable: bool) -> FsResult<()> {
        Ok(())
    }
}

impl RWStorage for DeviceStorage {
    fn get_blk_write(
        &mut self, pos: u64, _cachable: bool
    ) -> FsResult<Arc<dyn DerefMut<Target = Block>>> {
        unimplemented!();
    }
    fn put_blk_write(&mut self, _pos: u64, _cachable: bool) -> FsResult<()> {
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
