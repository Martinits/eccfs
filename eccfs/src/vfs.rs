use crate::*;
use bitflags::bitflags;
use alloc::vec::Vec;
use alloc::string::String;

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
    fn destroy(&self) -> FsResult<FSMode> {
        self.fsync()
    }

    /// get fs stat info in superblock
    fn finfo(&self) -> FsResult<FsInfo> {
        Err(FsError::NotSupported)
    }

    /// sync all filesystem, including metadata and user data
    fn fsync(&self) -> FsResult<FSMode> {
        Err(FsError::NotSupported)
    }

    /// read content of inode
    fn iread(&self, _iid: InodeID, _offset: usize, _to: &mut [u8]) -> FsResult<usize> {
        Err(FsError::NotSupported)
    }

    /// write content of inode
    fn iwrite(&self, _iid: InodeID, _offset: usize, _from: &[u8]) -> FsResult<usize> {
        Err(FsError::NotSupported)
    }

    /// get metadata of inode
    fn get_meta(&self, _iid: InodeID) -> FsResult<Metadata> {
        Err(FsError::NotSupported)
    }

    /// set metadata of inode
    fn set_meta(&self, _iid: InodeID, _set_md: SetMetadata) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// read symlink only if inode is a SymLink
    fn iread_link(&self, _iid: InodeID) -> FsResult<String> {
        Err(FsError::NotSupported)
    }

    fn iset_link(&self, _iid: InodeID, _new_lnk: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// sync metadata of this inode
    fn isync_meta(&self, _iid: InodeID) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// sync user data of this inode
    fn isync_data(&self, _iid: InodeID) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// create inode
    fn create(
        &self,
        _parent: InodeID,
        _name: &str,
        _ftype: FileType,
        _uid: u32,
        _gid: u32,
        _perm: FilePerm,
    ) -> FsResult<InodeID> {
        Err(FsError::NotSupported)
    }

    /// create hard link
    fn link(&self, _parent: InodeID, _name: &str, _linkto: InodeID) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// remove a link to inode
    fn unlink(&self, _parent: InodeID, _name: &str) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// create symlink
    fn symlink(
        &self,
        _parent: InodeID,
        _name: &str,
        _to: &str,
        _uid: u32,
        _gid: u32,
    ) -> FsResult<InodeID> {
        Err(FsError::NotSupported)
    }

    /// move `inode/name` to `to/newname`
    fn rename(
        &self,
        _from: InodeID, _name: &str,
        _to: InodeID, _newname: &str
    ) -> FsResult<()> {
        Err(FsError::NotSupported)
    }

    /// lookup name in inode only if inode is a dir
    fn lookup(&self, _iid: InodeID, _name: &str) -> FsResult<Option<InodeID>> {
        Err(FsError::NotSupported)
    }

    /// list all entries in inode only if it's a dir
    fn listdir(
        &self,
        _iid: InodeID,
        _offset: usize,
        _num: usize, // 0 means as many as possible
    ) -> FsResult<Vec<(InodeID, String, FileType)>> {
        Err(FsError::NotSupported)
    }

    fn next_entry(
        &self,
        iid: InodeID,
        offset: usize,
    ) -> FsResult<Option<(InodeID, String, FileType)>> {
        let l = self.listdir(iid, offset, 1)?;
        if l.len() == 0 {
            Ok(None)
        } else {
            assert_eq!(l.len(), 1);
            Ok(Some(l[0].clone()))
        }
    }

    /// fallocate
    fn fallocate(
        &self,
        _iid: InodeID,
        _mode: FallocateMode,
        _offset: usize,
        _len: usize,
    ) -> FsResult<()> {
        Err(FsError::NotSupported)
    }
}

#[derive(Copy, Clone, Debug, Eq, PartialEq, Default)]
pub enum FileType {
    #[default] Reg,
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

#[cfg(feature = "fuse")]
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
    #[derive(Debug, Eq, PartialEq, Clone, Copy)]
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

pub const PERM_MASK: u16 = 0o0777;

pub fn get_ftype_from_mode(mode: u16) -> FileType {
    FileType::from(mode >> 12)
}

pub fn get_perm_from_mode(mode: u16) -> FilePerm {
    FilePerm::from_bits(mode & PERM_MASK).unwrap()
}

pub fn get_mode(tp: FileType, perm: &FilePerm) -> u16 {
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
    pub atime: u32,
    /// Time of last modification
    pub mtime: u32,
    /// Time of last change
    pub ctime: u32,
    /// Type of file
    pub ftype: FileType,
    /// Permission
    pub perm: FilePerm,
    /// Number of hard links
    pub nlinks: u16,
    /// User ID
    pub uid: u32,
    /// Group ID
    pub gid: u32,
}

#[cfg(feature = "fuse")]
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
            perm: self.perm.bits(),
            nlink: self.nlinks as u32,
            uid: self.uid,
            gid: self.gid,
            rdev: 0,
            blksize: BLK_SZ as u32,
            flags: 0,
        }
    }
}

#[derive(Clone)]
pub enum SetMetadata {
    Size(usize),
    Atime(u32),
    Ctime(u32),
    Mtime(u32),
    Type(FileType),
    Permission(FilePerm),
    Uid(u32),
    Gid(u32),
}

pub trait TimeSource: Send + Sync {
    fn now(&self) -> u32;
}

#[derive(Debug)]
pub enum FallocateMode {
    Alloc,
    // AllocKeepSize,
    ZeroRange,
    // ZeroRangeKeepSize,
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
