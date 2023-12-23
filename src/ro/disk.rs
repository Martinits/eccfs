use crate::rw_as_blob;
use std::mem::size_of;

pub const INODE_ALIGN: usize = 16;

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

    /// file size(regular file), dir-entry num(dir), or name length(symbolic link)
    pub size: u64,
}
rw_as_blob!(DInodeBase);

#[repr(C)]
#[derive(Default)]
pub struct DInodeReg {
    pub base: DInodeBase,

    /// 128bit key + 128bit MAC for encrypted mode
    /// 256bit HASH for integrity only mode
    pub crypto_blob: [u8; 32],

    /// first block of file data, i.e. the Hash Tree
    /// starting from File Section (recorded in superblock)
    pub data_start: u64,

    /// total blocks of data section, i.e. the Hash Tree
    pub data_len : u64,
}
rw_as_blob!(DInodeReg);

#[repr(C)]
#[derive(Clone)]
pub struct EntryIndex {
    /// entry hash
    pub hash: u64,

    /// start position in entry list
    pub position: u32,

    /// number of entry after this index
    pub group_len: u32,
}
rw_as_blob!(EntryIndex);

#[repr(C)]
#[derive(Default, Clone)]
pub struct DirEntry {
    pub hash: u64,
    pub ipos: u64,
    pub len: u16,
    pub tp: u16,
    pub name: [u8; 12],
}
rw_as_blob!(DirEntry);

pub const DE_MAX_INLINE_NAME: usize = 12;

#[repr(C)]
pub struct DInodeDirBase {
    pub base: DInodeBase,

    /// first block of dir entry list in dir entry table
    pub data_start: u32,

    /// number of entry index
    pub nr_idx: u32,

    /// padding
    pub _padding: u64,
}
rw_as_blob!(DInodeDirBase);

#[repr(C)]
pub struct DInodeDir {
    pub dir_base: DInodeDirBase,

    /// index list
    pub idx_list: [EntryIndex],
}
// rw_as_blob
impl AsRef<[u8]> for DInodeDir {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let ptr = self as *const DInodeDir as *const u8;
        unsafe {
            std::slice::from_raw_parts(ptr,
                size_of::<DInodeDirBase>()
                + self.dir_base.nr_idx as usize * size_of::<EntryIndex>()
            )
        }
    }
}
impl AsMut<[u8]> for DInodeDir {
    #[inline]
    fn as_mut(&mut self) -> &mut [u8] {
        let ptr = self as *mut DInodeDir as *mut u8;
        unsafe {
            std::slice::from_raw_parts_mut(ptr,
                size_of::<DInodeDirBase>()
                + self.dir_base.nr_idx as usize * size_of::<EntryIndex>()
            )
        }
    }
}

#[repr(C)]
pub struct DInodeLnk {
    pub base: DInodeBase,

    /// name
    pub name: [u8; 32],
}
rw_as_blob!(DInodeLnk);

pub const DI_LNK_MAX_INLINE_NAME: usize = 32;

mod test {
    use crate::ro::disk::*;
    use std::fs::OpenOptions;
    use std::io::prelude::*;
    #[test]
    fn rw_struct() {
        let mut a = DInodeReg {
            base: DInodeBase {
                size: 1,
                uid: 2,
                gid: 3,
                atime: 4,
                ctime: 5,
                mtime: 6,
                mode: 7,
                nlinks: 16,
            },
            crypto_blob: [8; 32],
            data_start: 64,
            data_len: 0,
        };

        let mut f = OpenOptions::new()
            .read(true)
            .write(true)
            .open("test.blob").unwrap();
        f.write_all(a.as_ref()).unwrap();

        let mut f = OpenOptions::new()
            .read(true)
            .write(false)
            .open("test.blob").unwrap();
        f.read_exact(a.as_mut()).unwrap();
        assert_eq!(a.base.size, 1);
        assert_eq!(a.base.uid, 2);
        assert_eq!(a.base.gid, 3);
        assert_eq!(a.base.atime, 4);
        assert_eq!(a.base.ctime, 5);
        assert_eq!(a.base.mtime, 6);
        assert_eq!(a.base.mode, 7);
        assert_eq!(a.base.nlinks, 16);
        assert_eq!(a.data_start, 64);
        assert_eq!(a.data_len, 0);
        assert_eq!(a.crypto_blob, [8; 32]);
    }
}
