pub mod vfs;
pub mod overlay;
pub mod ro;
pub mod rw;
pub(crate) mod bcache;
pub(crate) mod htree;
pub(crate) mod storage;
pub(crate) mod crypto;

pub const BLK_SZ: usize = 4096;
pub type Block = [u8; 4096];

#[derive(Debug, Eq, PartialEq)]
pub enum FsError {
    NotSupported,     // E_UNIMP, or E_INVAL
    NotFile,          // E_ISDIR
    IsDir,            // E_ISDIR, used only in link
    NotDir,           // E_NOTDIR
    EntryNotFound,    // E_NOENT
    EntryExist,       // E_EXIST
    NotSameFs,        // E_XDEV
    InvalidParam,     // E_INVAL
    NoDeviceSpace, // E_NOSPC, but is defined and not used in the original ucore, which uses E_NO_MEM
    DirRemoved,    // E_NOENT, when the current dir was remove by a previous unlink
    DirNotEmpty,   // E_NOTEMPTY
    WrongFs,       // E_INVAL, when we find the content on disk is wrong when opening the device
    DeviceError(i32), // Device error contains the inner error number to report the error of device
    IOCTLError,
    NoDevice,
    Again,          // E_AGAIN, when no data is available, never happens in fs
    SymLoop,        // E_LOOP
    Busy,           // E_BUSY
    WrProtected,    // E_RDOFS
    NoIntegrity,    // E_RDOFS
    PermError,      // E_PERM
    NameTooLong,    // E_NAMETOOLONG
    FileTooBig,     // E_FBIG
    OpNotSupported, // E_OPNOTSUPP
    NotMountPoint,  // E_INVAL
    CryptoError,
    // IntegrityCheckError,
}
impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
pub type FsResult<T> = Result<T, FsError>;

macro_rules! read_from_blob {
    ($T: ty) => {
        impl AsMut<[u8]> for $T {
            #[inline]
            fn as_mut(&mut self) -> &mut [u8] {
                let ptr = self as *mut $T as *mut u8;
                unsafe { std::slice::from_raw_parts_mut(ptr, std::mem::size_of::<$T>()) }
            }
        }
    };
}
pub(crate) use read_from_blob;

macro_rules! write_to_blob {
    ($T: ty) => {
        impl AsRef<[u8]> for $T {
            #[inline]
            fn as_ref(&self) -> &[u8] {
                let ptr = self as *const $T as *const u8;
                unsafe { std::slice::from_raw_parts(ptr, std::mem::size_of::<$T>()) }
            }
        }
    };
}
pub(crate) use write_to_blob;

#[macro_export]
macro_rules! rw_as_blob {
    ($T: ty) => {
        crate::read_from_blob!($T);
        crate::write_to_blob!($T);
    };
}
