use crate::rw_as_blob;
use std::mem::size_of;

#[repr(C)]
struct DInodeBase {
    /// file size(regular file), dir-entry num(dir), or name length(symbolic link)
    size: u64,

    /// uid
    uid: u32,

    /// gid
    gid: u32,

    /// access time
    atime: u32,

    /// create time
    ctime: u32,

    /// modiied time
    mtime: u32,

    /// mode bits, same as kernel
    mode: u16,

    /// number of hard links
    nlinks: u16,
}
rw_as_blob!(DInodeBase);

#[repr(C)]
pub struct DInodeReg {
    base: DInodeBase,

    /// 128bit key + 128bit MAC for encrypted mode
    /// 256bit HASH for integrity only mode
    crypto_blob: [u8; 32],

    /// first block of file data (i.e. the Hash Tree)
    data_start: u64,

    /// padding
    _padding: u64,
}
rw_as_blob!(DInodeReg);

#[repr(C)]
struct EntryIndex {
    /// entry hash
    hash: u64,

    /// start position in entry list
    position: u32,

    /// number of entry after this index
    group_len: u32,
}
rw_as_blob!(EntryIndex);

#[repr(C)]
struct DInodeDirBase {
    base: DInodeBase,

    /// first block of dir entry list in dir entry table
    data_start: u32,

    /// number of entry index
    nr_idx: u32,

    /// padding
    _padding: u64,
}

#[repr(C)]
pub struct DInodeDir {
    dir_base: DInodeDirBase,

    /// index list
    idx_list: [EntryIndex],
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
pub struct DInodeSym {
    base: DInodeBase,

    /// name
    name: [u8; 32],
}
rw_as_blob!(DInodeSym);


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
            _padding: 0,
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
        assert_eq!(a._padding, 0);
        assert_eq!(a.crypto_blob, [8; 32]);
    }
}
