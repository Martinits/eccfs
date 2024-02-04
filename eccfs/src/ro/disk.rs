use crate::rw_as_blob;
use core::mem::size_of;

pub const INODE_ALIGN: usize = 16;

#[repr(C)]
#[derive(Default)]
pub struct DInodeBase {
    /// mode bits, 4 bits for FTYPE and 12 for UGO RWX permissions(only use 9 bits)
    /// FTYPE: 0 - reg, 1 - dir, 2 - lnk
    pub mode: u16,

    /// number of hard links, including , and excluding ..
    /// for example, a normal inode with no other hard links has an "nlinks" of 1
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

    /// file size(regular file), if inline, actual size is size.next_multiple_of(INODE_ALIGN)
    /// dir-entry num(dir), without . and ..
    /// name length(symbolic link)
    pub size: u64,
}
rw_as_blob!(DInodeBase);

// di_base(32)
// data 480Bytes
// = 512Bytes
pub const DI_REG_INLINE_DATA_MAX: u64 = 480;

#[repr(C)]
#[derive(Default)]
pub struct DInodeReg {
    pub base: DInodeBase,

    /// 128bit key + 128bit MAC for encrypted mode
    /// 256bit HASH for integrity only mode
    pub key_entry: [u8; 32],

    /// first block of file data, i.e. the Hash Tree
    /// starting from File Section (recorded in superblock)
    pub data_start: u64,

    /// total blocks of data section, i.e. the Hash Tree
    pub data_len : u64,
}
rw_as_blob!(DInodeReg);

#[repr(C)]
#[derive(Clone, Debug)]
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
#[derive(Default, Clone, Debug)]
pub struct DirEntry {
    pub hash: u64,
    pub ipos: u64,
    pub len: u16,
    pub tp: u16,
    pub name: [u8; 12],
}
rw_as_blob!(DirEntry);

pub const DE_MAX_INLINE_NAME: usize = 12;

// di_base(32)
// dot&dotdot: 2*dir_entry(32)
// 13*dir_entry(32)
// = 512Bytes
pub const DE_INLINE_MAX: u64 = 13;

#[repr(C)]
pub struct DInodeDirBaseNoInline {
    pub base: DInodeBase,

    /// first entry position of dir entry list in dir entry table
    /// 16 bit block offset + 48 bit block pos
    pub de_list_start: u64,

    /// number of entry index
    pub nr_idx: u32,

    /// padding
    pub _padding: u32,
}
rw_as_blob!(DInodeDirBaseNoInline);

#[repr(C)]
pub struct DInodeDir {
    pub dir_base: DInodeDirBaseNoInline,

    /// index list
    pub idx_list: [EntryIndex],
}
// rw_as_blob
impl AsRef<[u8]> for DInodeDir {
    #[inline]
    fn as_ref(&self) -> &[u8] {
        let ptr = self as *const DInodeDir as *const u8;
        unsafe {
            core::slice::from_raw_parts(ptr,
                size_of::<DInodeDirBaseNoInline>()
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
            core::slice::from_raw_parts_mut(ptr,
                size_of::<DInodeDirBaseNoInline>()
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
    #[test]
    fn rw_struct() {
        use crate::ro::disk::*;
        use std::fs::OpenOptions;
        use std::io::prelude::*;

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
            key_entry: [8; 32],
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
        assert_eq!(a.key_entry, [8; 32]);
    }
}
