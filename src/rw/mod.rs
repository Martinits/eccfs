pub mod superblock;
pub mod inode;
pub mod disk;
pub mod builder;

use crate::vfs::*;
use std::sync::{Arc, RwLock, Mutex};
use std::path::Path;
use crate::*;
use std::ffi::OsStr;
use superblock::*;
use crate::htree::*;
use inode::*;
use crate::bcache::*;
use crate::storage::*;
use crate::lru::*;
use disk::*;
use std::mem::size_of;
use crate::crypto::half_md4;


pub const RWFS_MAGIC: u64 = 0x0045434352574653; // ECCRWFS
pub const NAME_MAX: u64 = u16::MAX as u64;

pub struct RWFS {
    mode: FSMode,
    sb: RwLock<SuperBlock>,
    inode_tbl: Mutex<RWHashTree>,
    dirent_tbl: Option<Mutex<RWHashTree>>,
    path_tbl: Option<Mutex<RWHashTree>>,
    icac: Option<Mutex<ChannelLru<InodeID, Inode>>>,
    de_cac: Option<Mutex<ChannelLru<String, InodeID>>>,
}
