use std::sync::Arc;
use crate::*;
use std::ffi::OsStr;
use std::time::SystemTime;
use std::path::Path;

/// for ROFS, 16bit block offset + 48bit block position
pub type InodeID = u64;

#[derive(Debug, Default)]
pub struct FsInfo {
    /// File system type
    pub magic: usize,
    /// File system block size
    pub bsize: usize,
    /// Fundamental file system block size
    pub frsize: usize,
    /// Total number of blocks on file system in units of `frsize`
    pub blocks: usize,
    /// Total number of free blocks
    pub bfree: usize,
    /// Number of free blocks available to non-privileged process
    pub bavail: usize,
    /// Total number of file serial numbers
    pub files: usize,
    /// Total number of free file serial numbers
    pub ffree: usize,
    /// Maximum filename length
    pub namemax: usize,
}

pub trait FileSystem: Sync + Send {
    /// init fs
    fn init(&self) -> FsResult<()>;

    /// destroy this fs,  called before all worklaods are finished for this fs
    fn destroy(&self) -> FsResult<()>;

    /// get fs stat info in superblock
    fn finfo(&self) -> FsResult<FsInfo>;

    /// sync all filesystem, including metadata and user data
    fn fsync(&self) -> FsResult<()>;

    /// read content of inode
    fn iread(&self, inode: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize>;

    /// write content of inode
    fn iwrite(&self, inode: InodeID, offset: usize, from: &[u8]) -> FsResult<usize>;

    /// get metadata of inode
    fn get_meta(&self, inode: InodeID) -> FsResult<Metadata>;

    /// set metadata of inode
    fn set_meta(&self, inode: InodeID, set_md: SetMetadata) -> FsResult<()>;

    /// read symlink only if inode is a SymLink
    fn iread_link(&self, inode: InodeID) -> FsResult<String>;

    /// sync metadata of this inode
    fn isync_meta(&self, inode: InodeID) -> FsResult<()>;

    /// sync user data of this inode
    fn isync_data(&self, inode: InodeID) -> FsResult<()>;

    /// create inode
    fn create(&self, inode: InodeID, name: &OsStr, ftype: FileType, perm: u16) -> FsResult<InodeID>;

    /// create hard link
    fn link(&self, newparent: InodeID, newname: &OsStr, linkto: InodeID) -> FsResult<InodeID>;

    /// remove a link to inode
    fn unlink(&self, inode: InodeID, name: &OsStr) -> FsResult<()>;

    /// create symlink
    fn symlink(&self, inode: InodeID, name: &OsStr, to: &Path) -> FsResult<InodeID>;

    /// move `inode/name` to `to/newname`
    fn rename(&self, inode: InodeID, name: &OsStr, to: InodeID, newname: &OsStr) -> FsResult<()>;

    /// lookup name in inode only if inode is a dir
    fn lookup(&self, inode: InodeID, name: &OsStr) -> FsResult<Option<InodeID>>;

    /// list all entries in inode only if it's a dir
    fn listdir(&self, inode: InodeID) -> FsResult<Vec<(InodeID, String, FileType)>>;

    /// fallocate
    fn fallocate(&self, inode: InodeID, mode: FallocateMode, offset: usize, len: usize) -> FsResult<()>;
}

// #[derive(Default, Copy, Clone, PartialEq, Eq, PartialOrd, Ord, Debug, Hash)]
// pub struct Timespec {
//     pub sec: i64,
//     pub nsec: i64,
// }

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileType {
    Reg,
    Dir,
    Lnk,
}

impl Into<fuser::FileType> for FileType {
    fn into(self) -> fuser::FileType {
        match self {
            FileType::Reg => fuser::FileType::RegularFile,
            FileType::Dir => fuser::FileType::Directory,
            FileType::Lnk => fuser::FileType::Symlink,
        }
    }
}

#[derive(Debug, Eq, PartialEq, Clone)]
pub struct Metadata {
    /// Inode number
    pub iid: u64,
    /// Size in bytes
    pub size: u64,
    /// Size in blocks
    pub blocks: u64,
    /// Time of last access
    pub atime: SystemTime,
    /// Time of last modification
    pub mtime: SystemTime,
    /// Time of last change
    pub ctime: SystemTime,
    /// Type of file
    pub ftype: FileType,
    /// Permission
    pub mode: u16,
    /// Number of hard links
    pub nlinks: u16,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

impl Into<fuser::FileAttr> for Metadata {
    fn into(self) -> fuser::FileAttr {
        fuser::FileAttr {
            ino: self.iid,
            size: self.size,
            blocks: self.blocks,
            atime: self.atime,
            ctime: self.ctime,
            mtime: self.mtime,
            // BAD: mtime is the oldest time among the three, use it as crtime
            crtime: self.mtime,
            kind: self.ftype.into(),
            perm: self.mode,
            nlink: self.nlinks as u32,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLK_SZ as u32,
            flags: 0,
        }
    }
}

pub enum SetMetadata {
    Size(u64),
    Atime(SystemTime),
    Ctime(SystemTime),
    Mtime(SystemTime),
    Type(FileType),
    Permission(u16),
    Uid(u32),
    Gid(u32),
}

#[derive(Debug)]
pub enum FallocateMode {
    Alloc,
    AllocKeepSize,
    ZeroRange,
    ZeroRangeKeepSize,
}

// pub trait Inode: Sync + Send {
//     fn read_at(&self, offset: usize, buf: &mut [u8]) -> FsResult<usize>;
//
//     fn write_at(&self, offset: usize, buf: &[u8]) -> FsResult<usize>;
//
//     fn metadata(&self) -> FsResult<Metadata>;
//
//     fn set_metadata(&self, metadata: &Metadata) -> FsResult<()>;
//
//     fn fallocate(&self, mode: &FallocateMode, offset: usize, len: usize) -> FsResult<()>;
//
//     fn sync_all(&self) -> FsResult<()>;
//
//     fn sync_data(&self) -> FsResult<()>;
//
//     fn create(&self, name: &str, ftype: FileType, mode: u16) -> FsResult<Arc<dyn Inode>>;
//
//     fn link(&self, name: &str, other: &Arc<dyn Inode>) -> FsResult<()>;
//
//     fn unlink(&self, name: &str) -> FsResult<()>;
//
//     /// Move Inode `self/old_name` to `target/new_name`.
//     /// If `target` equals `self`, do rename.
//     fn movei(&self, old_name: &str, target: &Arc<dyn Inode>, new_name: &str) -> FsResult<()>;
//
//     /// Find the Inode `name` in the directory
//     fn lookup(&self, name: &str) -> FsResult<Arc<dyn Inode>>;
//
//     /// Get the name of directory entry
//     fn get_entry(&self, id: usize) -> FsResult<String>;
//
//     /// Get all directory entries as a Vec
//     fn list(&self) -> FsResult<Vec<String>> {
//         let info = self.metadata()?;
//         if info.ftype != FileType::Dir {
//             return Err(FsError::NotADirectory);
//         }
//         Ok((0..)
//             .map(|i| self.get_entry(i))
//             .take_while(|result| result.is_ok())
//             .filter_map(|result| result.ok())
//             .collect())
//     }
// }

pub fn check_access(
    file_uid: u32,
    file_gid: u32,
    file_mode: u16,
    uid: u32,
    gid: u32,
    mut access_mask: i32,
) -> bool {
    // F_OK tests for existence of file
    if access_mask == libc::F_OK {
        return true;
    }
    let file_mode = i32::from(file_mode);

    // root is allowed to read & write anything
    if uid == 0 {
        // root only allowed to exec if one of the X bits is set
        access_mask &= libc::X_OK;
        access_mask -= access_mask & (file_mode >> 6);
        access_mask -= access_mask & (file_mode >> 3);
        access_mask -= access_mask & file_mode;
        return access_mask == 0;
    }

    if uid == file_uid {
        access_mask -= access_mask & (file_mode >> 6);
    } else if gid == file_gid {
        access_mask -= access_mask & (file_mode >> 3);
    } else {
        access_mask -= access_mask & file_mode;
    }

    return access_mask == 0;
}
