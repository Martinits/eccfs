use crate::*;

pub const INODE_SZ: usize = 128;
pub const INODE_PER_BLK: usize = BLK_SZ / INODE_SZ;

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
    /// dir-entry num(dir), without . and ..
    /// name length(symbolic link)
    pub size: u64,
}
rw_as_blob!(DInodeBase);

// di_base(32)
// data 96 Bytes
// = 128 Bytes
pub const DI_REG_INLINE_DATA_MAX: u64 = 96;

#[repr(C)]
#[derive(Default)]
pub struct DInodeReg {
    pub base: DInodeBase,

    /// 128bit key + 128bit MAC for encrypted mode
    /// 256bit HASH for integrity only mode
    pub key_entry: [u8; 32],

    /// file root node sha256 as data file name(in hex)
    /// same as key_entry in IntegrityOnly Mode
    pub data_file: [u8; 32],

    /// total blocks of data section, i.e. the Hash Tree
    pub _padding: [u8; 32],
}
rw_as_blob!(DInodeReg);

#[repr(C)]
#[derive(Default, Clone, Debug)]
pub struct DirEntryBase {
    /// inode number, aligned by 128B
    pub ipos: u64,
    /// total length of this entry
    pub len: u16,
    pub tp: u16,
    // name is here, with length of "len" - 12, bu with a min space of 4B
}
rw_as_blob!(DirEntryBase);

#[repr(C)]
pub struct DInodeDirInline {
    pub base: DInodeBase,

    /// inline dir entries
    pub de_list: [u8; 96],

}
rw_as_blob!(DInodeDirInline);

#[repr(C)]
pub struct DInodeDir {
    pub base: DInodeBase,

    /// data file hash
    pub data_file: [u8; 32],

    pub _padding: [u8; 64],
}
rw_as_blob!(DInodeDir);

#[repr(C)]
pub struct DInodeLnk {
    pub base: DInodeBase,

    /// name, must be <= 96B
    pub name: [u8; 96],
}
rw_as_blob!(DInodeLnk);

pub const LNK_NAME_MAX: u64 = 96;
