pub mod ro;
pub mod rw;
pub(crate) mod htree;
extern crate alloc;
pub(crate) use eccfs::*;

pub mod io_wrapper {
    use std::io::prelude::*;
    use std::io::SeekFrom;
    use crate::*;
    use core::mem::size_of;
    use std::fs::File;
    use std::io::Write;
    use std::os::unix::fs::FileExt;
    use alloc::vec::Vec;

    pub fn write_vec_as_bytes<T>(f: &mut File, v: &Vec<T>) -> FsResult<()> {
        io_try!(f.write_all(
            unsafe {
                std::slice::from_raw_parts(
                    v.as_ptr() as *const u8,
                    v.len() * size_of::<T>()
                )
            }
        ));
        Ok(())
    }

    pub fn write_file_at(f: &mut File, seek: u64, b: &[u8]) -> FsResult<()> {
        if io_try!(f.write_at(b, seek)) != b.len() {
            return Err(new_error!(FsError::UnexpectedEof));
        }
        Ok(())
    }

    pub fn read_file_at(f: &mut File, seek: u64, b: &mut [u8]) -> FsResult<usize> {
        Ok(io_try!(f.read_at(b, seek)))
    }

    pub fn get_file_pos(f: &mut File) -> FsResult<u64> {
        Ok(io_try!(f.seek(SeekFrom::Current(0))))
    }

    pub fn round_file_up_to_blk(f: &mut File) -> FsResult<u64> {
        let len = io_try!(f.seek(SeekFrom::End(0))).next_multiple_of(BLK_SZ as u64);
        io_try!(f.set_len(len));
        Ok(len / BLK_SZ as u64)
    }

    pub fn get_file_sz(f: &mut File) -> FsResult<u64> {
        let org_pos = get_file_pos(f)?;
        let len = io_try!(f.seek(SeekFrom::End(0)));
        io_try!(f.seek(SeekFrom::Start(org_pos)));
        Ok(len)
    }

    #[macro_export]
    macro_rules! io_try {
        ($e: expr) => {
            $e.map_err(|e| new_error!(FsError::IOError(e)))?
        };
    }
}
pub use io_wrapper::*;
