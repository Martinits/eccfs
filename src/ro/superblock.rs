use crate::*;
use crate::crypto::*;
use super::*;


pub const SUPERBLOCK_POS: u64 = 0;

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
    pub file_sec_start: u64,
    pub encrypted: bool,
    /// File system type
    pub magic: u64,
    /// File system block size
    pub bsize: usize,
    /// Total number of blocks on file system in units of `frsize`
    pub blocks: usize,
    /// Total number of file serial numbers, i.e. nr of actual regular files
    pub files: usize,
    /// Maximum filename length, as for dirent structure, it's 65535 (max of u16)
    pub namemax: usize,
}

#[repr(C)]
#[derive(Clone)]
pub struct DSuperBlock {
    pub magic: u64,
    pub bsize: u64,
    pub files: u64,
    pub namemax: u64,
    pub inode_tbl_key: KeyEntry,
    pub dirent_tbl_key: KeyEntry,
    pub path_tbl_key: KeyEntry,
    pub inode_tbl_start: u64,
    pub inode_tbl_len: u64,
    pub dirent_tbl_start: u64,
    pub dirent_tbl_len: u64,
    pub path_tbl_start: u64,
    pub path_tbl_len: u64,
    pub file_sec_start: u64,
    pub blocks: u64,
    pub encrypted: bool,
}
rw_as_blob!(DSuperBlock);

impl Into<SuperBlock> for DSuperBlock {
    fn into(self) -> SuperBlock {
        let DSuperBlock {
            magic,
            bsize,
            files,
            namemax,
            inode_tbl_key,
            dirent_tbl_key,
            path_tbl_key,
            inode_tbl_start,
            inode_tbl_len,
            dirent_tbl_start,
            dirent_tbl_len,
            path_tbl_start,
            path_tbl_len,
            file_sec_start,
            blocks,
            encrypted,
        } = self;

        SuperBlock {
            magic,
            bsize: bsize as usize,
            files: files as usize,
            namemax: namemax as usize,
            inode_tbl_key,
            dirent_tbl_key,
            path_tbl_key,
            inode_tbl_start,
            inode_tbl_len,
            dirent_tbl_start,
            dirent_tbl_len,
            path_tbl_start,
            path_tbl_len,
            file_sec_start,
            blocks: blocks as usize,
            encrypted,
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

        let dsb = unsafe {
            (raw_blk.as_ptr() as *const DSuperBlock).as_ref().ok_or(FsError::UnknownError)?
        };

        // check constants
        if dsb.magic != super::ROFS_MAGIC
            || dsb.bsize != BLK_SZ as u64 || dsb.namemax != NAME_MAX {
            return Err(FsError::SuperBlockCheckFailed)
        } else {
            Ok(dsb.clone().into())
        }
    }

    pub fn get_fsinfo(&self) -> FsResult<FsInfo> {
        Ok(FsInfo {
            magic: self.magic,
            bsize: self.bsize,
            blocks: self.blocks,
            bfree: 0,
            bavail: 0,
            files: self.files,
            ffree: 0,
            frsize: self.bsize,
            namemax: self.namemax,
        })
    }
}
