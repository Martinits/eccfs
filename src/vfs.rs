use std::fmt;
use std::result::Result;
use std::sync::Arc;
use crate::*;

pub trait FileSystem: Sync + Send {
    fn sync(&self) -> FsResult<()>;

    fn root_inode(&self) -> Arc<dyn Inode>;

    // fn info(&self) -> FsInfo;
}

#[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
pub struct Timespec {
    pub sec: i64,
    pub nsec: i64,
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileType {
    Reg,
    Dir,
    Lnk,
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Metadata {
    /// Inode number
    pub inode: usize,
    /// Size in bytes
    pub size: usize,
    /// Size in blocks
    pub blocks: usize,
    /// Time of last access
    pub atime: Timespec,
    /// Time of last modification
    pub mtime: Timespec,
    /// Time of last change
    pub ctime: Timespec,
    /// Type of file
    pub ftype: FileType,
    /// Permission
    pub mode: u16,
    /// Number of hard links
    pub nlinks: usize,
    /// User ID
    pub uid: usize,
    /// Group ID
    pub gid: usize,
}

#[derive(Debug)]
pub enum FallocateMode {
    AllocKeepSize,
    AllocUnshareRange,
    PunchHoleKeepSize,
    ZeroRange,
    ZeroRangeKeepSize,
    CollapseRange,
    InsertRange,
}

pub trait Inode: Sync + Send {
    fn read_at(&self, offset: usize, buf: &mut [u8]) -> FsResult<usize>;

    fn write_at(&self, offset: usize, buf: &[u8]) -> FsResult<usize>;

    fn metadata(&self) -> FsResult<Metadata>;

    fn set_metadata(&self, metadata: &Metadata) -> FsResult<()>;

    fn fallocate(&self, mode: &FallocateMode, offset: usize, len: usize) -> FsResult<()>;

    fn sync_all(&self) -> FsResult<()>;

    fn sync_data(&self) -> FsResult<()>;

    fn create(&self, name: &str, ftype: FileType, mode: u16) -> FsResult<Arc<dyn Inode>>;

    fn link(&self, name: &str, other: &Arc<dyn Inode>) -> FsResult<()>;

    fn unlink(&self, name: &str) -> FsResult<()>;

    /// Move Inode `self/old_name` to `target/new_name`.
    /// If `target` equals `self`, do rename.
    fn movei(&self, old_name: &str, target: &Arc<dyn Inode>, new_name: &str) -> FsResult<()>;

    /// Find the Inode `name` in the directory
    fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>>;

    /// Get the name of directory entry
    fn get_entry(&self, id: usize) -> FsResult<String>;

    /// Get all directory entries as a Vec
    fn list(&self) -> FsResult<Vec<String>> {
        let info = self.metadata()?;
        if info.ftype != FileType::Dir {
            return Err(FsError::NotDir);
        }
        Ok((0..)
            .map(|i| self.get_entry(i))
            .take_while(|result| result.is_ok())
            .filter_map(|result| result.ok())
            .collect())
    }
}
