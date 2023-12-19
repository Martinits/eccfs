use crate::*;
use crate::crypto::*;
use super::*;


pub const SUPERBLOCK_POS: u64 = 0;

#[repr(C)]
struct DHashTreeMeta {
    start: u64,
    end: u64,
    key: KeyEntry,
}

#[derive(Default)]
pub struct SuperBlock {
    pub inode_tbl_key: KeyEntry,
    pub dirent_tbl_key: KeyEntry,
    pub path_tbl_key: KeyEntry,
    pub inode_tbl_start: u64,
    pub inode_tbl_len: u64,
    pub dirent_tbl_start: u64,
    pub dirent_tbl_len: u64,
    pub path_tbl_start: u64,
    pub path_tbl_len: u64,
    pub encrypted: bool,
    // runtime meta
    dirty: bool,
    /// File system type
    pub magic: usize,
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

#[repr(C)]
#[derive(Clone)]
struct DSuperBlock {
    inode_tbl_key: KeyEntry,
    dirent_tbl_key: KeyEntry,
    path_tbl_key: KeyEntry,
    inode_tbl_start: u64,
    inode_tbl_len: u64,
    dirent_tbl_start: u64,
    dirent_tbl_len: u64,
    path_tbl_start: u64,
    path_tbl_len: u64,
    blocks: u64,
    encrypted: bool,
}
rw_as_blob!(DSuperBlock);

impl Into<SuperBlock> for DSuperBlock {
    fn into(self) -> SuperBlock {
        let DSuperBlock {
            inode_tbl_key,
            dirent_tbl_key,
            path_tbl_key,
            inode_tbl_start,
            inode_tbl_len,
            dirent_tbl_start,
            dirent_tbl_len,
            path_tbl_start,
            path_tbl_len,
            blocks,
            encrypted,
        } = self;

        SuperBlock {
            inode_tbl_key,
            dirent_tbl_key,
            path_tbl_key,
            inode_tbl_start,
            inode_tbl_len,
            dirent_tbl_start,
            dirent_tbl_len,
            path_tbl_start,
            path_tbl_len,
            blocks: blocks as usize,
            encrypted,
            dirty: false,
            ..Default::default()
        }
    }
}

impl SuperBlock {
    pub fn new(mode: FSMode, mut raw_blk: Block) -> FsResult<Self> {
        // check crypto
        match &mode {
            FSMode::Encrypted(ref key, ref mac) => {
                aes_gcm_128_blk_dec(&mut raw_blk, key, mac, SUPERBLOCK_POS)?;
            }
            FSMode::IntegrityOnly(ref hash) => {
                sha3_256_blk_check(&raw_blk, hash)?;
            }
        }

        let dsb = raw_blk.as_ptr() as *const DSuperBlock;
        unsafe {
            Ok(dsb.as_ref().ok_or(FsError::UnknownError)?.clone().into())
        }
    }

    pub fn get_fsinfo(&self) -> FsResult<FsInfo> {
        Ok(FsInfo {
            magic: self.magic,
            bsize: self.bsize,
            blocks: self.blocks,
            bfree: self.bfree,
            bavail: self.bavail,
            files: self.files,
            ffree: self.ffree,
            frsize: self.frsize,
            namemax: self.namemax,
        })
    }
}
