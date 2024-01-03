use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::time::{SystemTime, Duration};
use std::mem::size_of;
use crate::htree::*;
use crate::bcache::*;
use std::ffi::OsStr;
use crate::crypto::half_md4;
use super::*;


struct DirEntry {
    ipos: u64,
    len: u16,
    tp: FileType,
    name: String,
}

enum InodeExt {
    Reg {
        data_file_name: KeyEntry,
        data_len: u64,
        data: RWHashTree,
    },
    RegInline {
        data: Vec<u8>,
    },
    Dir {
        data_file_name: KeyEntry,
        data_len: u64,
        data: RWHashTree,
    },
    DirInline {
        de_list: Vec<DirEntry>, // include . and ..
    },
    Lnk(String),
}

pub struct Inode {
    iid: InodeID,
    tp: FileType,
    perm: FilePerm,
    nlinks: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    ctime: SystemTime,
    mtime: SystemTime,
    size: usize, // with . and ..
    ext: InodeExt,
}
