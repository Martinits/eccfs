use crate::*;

pub const INODE_SZ: usize = 128;
pub const INODE_PER_BLK: usize = BLK_SZ / INODE_SZ;

pub const ZERO_INODE: [u8; INODE_SZ] = [0u8; INODE_SZ];

#[repr(C)]
#[derive(Default)]
pub struct DInodeBase {
    /// mode bits, 4 bits for FTYPE and 12 for UGO RWX permissions(only use 9 bits)
    /// FTYPE: 0 - reg, 1 - dir, 2 - lnk
    pub mode: u16,

    /// number of hard links
    pub nlinks: u16,

    /// uid
    pub uid: u32,

    /// gid
    pub gid: u32,

    /// access time
    pub atime: u32,

    /// create time
    pub ctime: u32,

    /// modiied time
    pub mtime: u32,

    /// file size(regular file)
    /// dir-entry data total size (dir)
    /// name length (symbolic link)
    pub size: u64,
}
rw_as_blob!(DInodeBase);

// di_base(32)
// data 96 Bytes
// = 128 Bytes
pub const REG_INLINE_DATA_MAX: usize = 96;

#[repr(C)]
#[derive(Default)]
pub struct DInodeReg {
    pub base: DInodeBase,

    /// data file key entry
    pub data_file_ke: [u8; 32],

    /// data file name by hash of iid
    pub data_file: [u8; 32],

    /// total blocks of data section, i.e. the Hash Tree
    pub _padding: [u8; 32],
}
rw_as_blob!(DInodeReg);

#[repr(C)]
pub struct DInodeRegInline {
    pub base: DInodeBase,

    /// data
    pub data: [u8; REG_INLINE_DATA_MAX],
}
rw_as_blob!(DInodeRegInline);

pub const DIRENT_SZ: usize = 256;
pub const DIRENT_PER_BLK: usize = BLK_SZ / DIRENT_SZ;
pub const DIRENT_NAME_MAX: usize = DIRENT_SZ - 12;

#[repr(C)]
#[derive(Clone, Debug)]
pub struct DiskDirEntry {
    /// inode number, aligned by 128B
    pub ipos: u64,
    pub tp: u16,
    /// name length
    pub len: u16,
    // name
    pub name: [u8; DIRENT_NAME_MAX],
}
rw_as_blob!(DiskDirEntry);

#[repr(C)]
pub struct DInodeDir {
    pub base: DInodeBase,

    /// data file key entry
    pub data_file_ke: [u8; 32],

    /// data file name by hash of iid
    pub data_file: [u8; 32],

    pub _padding: [u8; 32],
}
rw_as_blob!(DInodeDir);

pub const LNK_INLINE_MAX: usize = INODE_SZ - size_of::<DInodeBase>();

#[repr(C)]
pub struct DInodeLnkInline {
    pub base: DInodeBase,

    /// name
    pub name: [u8; LNK_INLINE_MAX],
}
rw_as_blob!(DInodeLnkInline);


#[repr(C)]
pub struct DInodeLnk{
    pub base: DInodeBase,

    /// name file(one block) key entry
    pub name_file_ke: [u8; 32],

    /// data file name by hash of iid
    pub data_file: [u8; 32],

    pub _padding: [u8; 32],
}
rw_as_blob!(DInodeLnk);

pub const LNK_NAME_MAX: usize = BLK_SZ;

pub const LNK_DATA_FILE_BLK_POS: u64 = 0;
