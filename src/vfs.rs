use crate::*;
use std::ffi::OsStr;
use std::time::SystemTime;
use std::path::Path;
use bitflags::bitflags;

/// for ROFS, 16bit block offset + 48bit block position
pub type InodeID = u64;

#[derive(Debug, Default)]
pub struct FsInfo {
    /// File system type
    pub magic: u64,
    /// File system block size
    pub bsize: usize,
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
    /// Fundamental file system block size
    pub frsize: usize,
}

pub trait FileSystem: Sync + Send {
    /// init fs
    fn init(&self) -> FsResult<()> {
        Ok(())
    }

    /// destroy this fs, called before all worklaods are finished for this fs
    fn destroy(&mut self) -> FsResult<FSMode> {
        Err(FsError::Unsupported)
    }

    /// get fs stat info in superblock
    fn finfo(&self) -> FsResult<FsInfo> {
        Err(FsError::Unsupported)
    }

    /// sync all filesystem, including metadata and user data
    fn fsync(&mut self) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    /// read content of inode
    fn iread(&self, _iid: InodeID, _offset: usize, _to: &mut [u8]) -> FsResult<usize> {
        Err(FsError::Unsupported)
    }

    /// write content of inode
    fn iwrite(&self, _iid: InodeID, _offset: usize, _from: &[u8]) -> FsResult<usize> {
        Err(FsError::Unsupported)
    }

    /// get metadata of inode
    fn get_meta(&self, _iid: InodeID) -> FsResult<Metadata> {
        Err(FsError::Unsupported)
    }

    /// set metadata of inode
    fn set_meta(&self, _iid: InodeID, _set_md: SetMetadata) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    /// read symlink only if inode is a SymLink
    fn iread_link(&self, _iid: InodeID) -> FsResult<String> {
        Err(FsError::Unsupported)
    }

    /// sync metadata of this inode
    fn isync_meta(&self, _iid: InodeID) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    /// sync user data of this inode
    fn isync_data(&self, _iid: InodeID) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    /// create inode
    fn create(
        &self,
        _iid: InodeID,
        _name: &OsStr,
        _ftype: FileType,
        _perm: u16,
    ) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    /// create hard link
    fn link(&self, _newparent: InodeID, _newname: &OsStr, _linkto: InodeID) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    /// remove a link to inode
    fn unlink(&self, _iid: InodeID, _name: &OsStr) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    /// create symlink
    fn symlink(&self, _iid: InodeID, _name: &OsStr, _to: &Path) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    /// move `inode/name` to `to/newname`
    fn rename(&self, _iid: InodeID, _name: &OsStr, _to: InodeID, _newname: &OsStr) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    /// lookup name in inode only if inode is a dir
    fn lookup(&self, _iid: InodeID, _name: &OsStr) -> FsResult<Option<InodeID>> {
        Err(FsError::Unsupported)
    }

    /// list all entries in inode only if it's a dir
    fn listdir(
        &self,
        _iid: InodeID,
        _offset: usize
    ) -> FsResult<Vec<(InodeID, String, FileType)>> {
        Err(FsError::Unsupported)
    }

    /// fallocate
    fn fallocate(
        &self,
        _iid: InodeID,
        _mode: FallocateMode,
        _offset: usize,
        _len: usize,
    ) -> FsResult<()> {
        Err(FsError::Unsupported)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq)]
pub enum FileType {
    Reg,
    Dir,
    Lnk,
}

impl From<u16> for FileType {
    fn from(value: u16) -> Self {
        match value {
            0 => FileType::Reg,
            1 => FileType::Dir,
            2 => FileType::Lnk,
            _ => panic!("Unexpected FileType in raw data!"),
        }
    }
}

impl Into<u16> for FileType {
    fn into(self) -> u16 {
        match self {
            FileType::Reg => 0,
            FileType::Dir => 1,
            FileType::Lnk => 2,
        }
    }
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

bitflags! {
    pub struct FilePerm: u16 {
        const U_R = 0o0400;
        const U_W = 0o0200;
        const U_X = 0o0100;
        const G_R = 0o0040;
        const G_W = 0o0020;
        const G_X = 0o0010;
        const O_R = 0o0004;
        const O_W = 0o0002;
        const O_X = 0o0001;
    }
}

const PERM_MASK: u16 = 0o0777;

pub fn get_ftype_from_mode(mode: u16) -> FileType {
    FileType::from(mode >> 12)
}

pub fn get_perm_from_mode(mode: u16) -> FilePerm {
    FilePerm::from_bits(mode & PERM_MASK).unwrap()
}

pub fn get_mode(tp: FileType, perm: FilePerm) -> u16 {
    (Into::<u16>::into(tp) << 12) | (perm.bits() & PERM_MASK)
}

pub fn get_mode_from_libc_mode(libc_mode: u32) -> u16 {
    let tp = libc_mode & libc::S_IFMT;
    let tp: u16 = if tp == libc::S_IFREG {
        0
    } else if tp == libc::S_IFDIR {
        1
    } else if tp == libc::S_IFLNK {
        2
    } else {
        panic!("Unsupported file type!");
    };
    (tp << 12) | ((libc_mode & PERM_MASK as u32) as u16)
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
    pub perm: u16,
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
            perm: self.perm,
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
