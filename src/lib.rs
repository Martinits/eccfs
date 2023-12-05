pub mod vfs;
pub mod overlay;
pub mod ro;
pub mod rw;
pub(crate) mod bcache;
pub(crate) mod htree;
pub(crate) mod storage;
pub(crate) mod crypto;
pub(crate) mod blru;


pub const BLK_SZ: usize = 4096;
pub type Block = [u8; 4096];


#[derive(Debug, Eq, PartialEq)]
pub enum FsError {
    // NotSupported,     // E_UNIMP, or E_INVAL
    // NotFile,          // E_ISDIR
    // IsDir,            // E_ISDIR, used only in link
    // NotDir,           // E_NOTDIR
    // EntryNotFound,    // E_NOENT
    // EntryExist,       // E_EXIST
    // NotSameFs,        // E_XDEV
    // InvalidParam,     // E_INVAL
    // NoDeviceSpace, // E_NOSPC, but is defined and not used in the original ucore, which uses E_NO_MEM
    // DirRemoved,    // E_NOENT, when the current dir was remove by a previous unlink
    // DirNotEmpty,   // E_NOTEMPTY
    // WrongFs,       // E_INVAL, when we find the content on disk is wrong when opening the device
    // DeviceError(i32), // Device error contains the inner error number to report the error of device
    // IOCTLError,
    // NoDevice,
    // Again,          // E_AGAIN, when no data is available, never happens in fs
    // SymLoop,        // E_LOOP
    // Busy,           // E_BUSY
    // WrProtected,    // E_RDOFS
    // NoIntegrity,    // E_RDOFS
    // PermError,      // E_PERM
    // NameTooLong,    // E_NAMETOOLONG
    // FileTooBig,     // E_FBIG
    // OpNotSupported, // E_OPNOTSUPP
    // NotMountPoint,  // E_INVAL

    // Same as std::io::ErrorKind
    NotFound,
    PermissionDenied,
    ConnectionRefused,
    ConnectionReset,
    HostUnreachable,
    NetworkUnreachable,
    ConnectionAborted,
    NotConnected,
    AddrInUse,
    AddrNotAvailable,
    NetworkDown,
    BrokenPipe,
    AlreadyExists,
    WouldBlock,
    NotADirectory,
    IsADirectory,
    DirectoryNotEmpty,
    ReadOnlyFilesystem,
    FilesystemLoop,
    StaleNetworkFileHandle,
    InvalidInput,
    InvalidData,
    TimedOut,
    WriteZero,
    StorageFull,
    NotSeekable,
    FilesystemQuotaExceeded,
    FileTooLarge,
    ResourceBusy,
    ExecutableFileBusy,
    Deadlock,
    CrossesDevices,
    TooManyLinks,
    InvalidFilename,
    ArgumentListTooLong,
    Interrupted,
    Unsupported,
    UnexpectedEof,
    OutOfMemory,
    // Errors specific to this crate
    CryptoError,
    // IntegrityCheckError,
    CacheIsFull,
    SendError,
    RecvError,
    LockError,
    UnknownError,
}
impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}
pub type FsResult<T> = Result<T, FsError>;

impl From<u32> for FsError {
    fn from(value: u32) -> Self {
        match value {
            1  => Self::NotFound,
            2  => Self::PermissionDenied,
            3  => Self::ConnectionRefused,
            4  => Self::ConnectionReset,
            5  => Self::HostUnreachable,
            6  => Self::NetworkUnreachable,
            7  => Self::ConnectionAborted,
            8  => Self::NotConnected,
            9  => Self::AddrInUse,
            10  => Self::AddrNotAvailable,
            11  => Self::NetworkDown,
            12  => Self::BrokenPipe,
            13  => Self::AlreadyExists,
            14  => Self::WouldBlock,
            15  => Self::NotADirectory,
            16  => Self::IsADirectory,
            17  => Self::DirectoryNotEmpty,
            18  => Self::ReadOnlyFilesystem,
            19  => Self::FilesystemLoop,
            20  => Self::StaleNetworkFileHandle,
            21  => Self::InvalidInput,
            22  => Self::InvalidData,
            23  => Self::TimedOut,
            24  => Self::WriteZero,
            25  => Self::StorageFull,
            26  => Self::NotSeekable,
            27  => Self::FilesystemQuotaExceeded,
            28  => Self::FileTooLarge,
            29  => Self::ResourceBusy,
            30  => Self::ExecutableFileBusy,
            31  => Self::Deadlock,
            32  => Self::CrossesDevices,
            33  => Self::TooManyLinks,
            34  => Self::InvalidFilename,
            35  => Self::ArgumentListTooLong,
            36  => Self::Interrupted,
            37  => Self::Unsupported,
            38  => Self::UnexpectedEof,
            39  => Self::OutOfMemory,
            _ => Self::UnknownError,
        }
    }
}

impl From<std::io::Error> for FsError {
    fn from(value: std::io::Error) -> Self {
        Into::<FsError>::into(value.kind() as u32)
    }
}


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
