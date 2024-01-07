use crate::*;
use crate::crypto::*;
use super::*;
use std::io::prelude::*;


pub const SUPERBLOCK_POS: u64 = 0;

#[derive(Default)]
pub struct SuperBlock {
    /// number of data files
    pub nr_data_file: usize,
    /// whether in encrypted mode
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
    /// ibitmap start, normally 1
    pub ibitmap_start: u64,
    /// ibitmap len in blk
    pub ibitmap_len: u64,
    /// ibitmap blocks ke
    pub ibitmap_ke: Vec<KeyEntry>,
    /// itbl data file hash name
    pub itbl_name: Hash256,
    /// length of itbl data file including htree contents
    pub itbl_len: u64,
    /// itbl htree key entry
    pub itbl_ke: KeyEntry,
}

#[repr(C)]
#[derive(Clone)]
pub struct DSuperBlockBase {
    pub nr_data_file: u64,
    pub magic: u64,
    pub bsize: u64,
    pub files: u64,
    pub namemax: u64,
    pub blocks: u64,
    pub encrypted: bool,
    pub ibitmap_start: u64,
    pub ibitmap_len: u64,
    pub itbl_name: Hash256,
    pub itbl_len: u64, // including htree
    pub itbl_ke: KeyEntry,
    // pub ibitmap_ke: [KeyEntry],
}
rw_as_blob!(DSuperBlockBase);

impl SuperBlock {
    pub fn new(raw_blk: Block) -> FsResult<Self> {
        let dsb_base = unsafe {
            (raw_blk.as_ptr() as *const DSuperBlockBase).as_ref().ok_or(FsError::UnknownError)?
        };

        // check constants
        if dsb_base.magic != super::RWFS_MAGIC
            || dsb_base.bsize != BLK_SZ as u64 || dsb_base.namemax != NAME_MAX {
            return Err(FsError::SuperBlockCheckFailed)
        }

        let ibitmap_ke = Vec::from(unsafe {
            std::slice::from_raw_parts(
                raw_blk[size_of::<DSuperBlockBase>()..].as_ptr() as *const KeyEntry,
                dsb_base.ibitmap_len as usize,
            )
        });

        Ok(SuperBlock {
            nr_data_file: dsb_base.nr_data_file as usize,
            encrypted: dsb_base.encrypted,
            magic: dsb_base.magic,
            bsize: dsb_base.bsize as usize,
            blocks: dsb_base.blocks as usize,
            files: dsb_base.files as usize,
            namemax: dsb_base.namemax as usize,
            ibitmap_start: dsb_base.ibitmap_start,
            ibitmap_len: dsb_base.ibitmap_len,
            itbl_name: dsb_base.itbl_name,
            itbl_len: dsb_base.itbl_len,
            itbl_ke: dsb_base.itbl_ke,
            ibitmap_ke,
        })
    }

    pub fn get_fsinfo(&self) -> FsResult<FsInfo> {
        Ok(FsInfo {
            magic: self.magic,
            bsize: self.bsize,
            blocks: self.blocks,
            bfree: self.get_bfree(),
            bavail: self.get_bfree(),
            files: self.files,
            ffree: usize::MAX - self.files,
            frsize: self.bsize,
            namemax: self.namemax,
        })
    }

    fn get_bfree(&self) -> usize {
        // because we use htrees, there's no max size of a file or a block group
        // so we just estimate it
        self.nr_data_file * 64
    }

    pub fn write(&self) -> FsResult<Block> {
        let mut raw_blk = [0u8; BLK_SZ];

        let dsb_base = unsafe {
            (raw_blk.as_ptr() as *mut DSuperBlockBase).as_mut().ok_or(FsError::UnknownError)?
        };

        dsb_base.nr_data_file = self.nr_data_file as u64;
        dsb_base.magic = self.magic;
        dsb_base.bsize = self.bsize as u64;
        dsb_base.files = self.files as u64;
        dsb_base.namemax = self.namemax as u64;
        dsb_base.blocks = self.blocks as u64;
        dsb_base.encrypted = self.encrypted;
        dsb_base.ibitmap_start = self.ibitmap_start;
        dsb_base.ibitmap_len = self.ibitmap_ke.len() as u64;
        dsb_base.itbl_name = self.itbl_name;
        dsb_base.itbl_len = self.itbl_len;

        let mut writer: &mut [u8] = &mut raw_blk[size_of::<DSuperBlockBase>()..];
        let bytes = self.ibitmap_ke.len() * size_of::<KeyEntry>();
        assert!(size_of::<DSuperBlockBase>() + bytes <= BLK_SZ);
        let written = io_try!(writer.write(
            unsafe {
                std::slice::from_raw_parts(
                    self.ibitmap_ke.as_ptr() as *const u8,
                    bytes,
                )
            }
        ));
        assert_eq!(written, bytes);

        Ok(raw_blk)
    }
}
