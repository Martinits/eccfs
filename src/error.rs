#[derive(Debug, Eq, PartialEq)]
pub enum FsError {
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
    IntegrityCheckError,
    CacheIsFull,
    ChannelSendError,
    ChannelRecvError,
    RwLockError,
    CacheNeedHint,

    UnknownError,
}

impl std::fmt::Display for FsError {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(f, "{:?}", self)
    }
}

pub type FsResult<T> = Result<T, FsError>;

// used for transition from std::io::ErrorKind to FsError
impl From<u64> for FsError {
    fn from(value: u64) -> Self {
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
        Into::<FsError>::into(value.kind() as u64)
    }
}

use libc::c_int;
impl Into<c_int> for FsError {
    fn into(self) -> c_int {
        match self {
            FsError::NotFound => libc::ENOENT,
            FsError::PermissionDenied => libc::EACCES,
            FsError::ConnectionRefused => libc::ECONNREFUSED,
            FsError::ConnectionReset => libc::ECONNRESET,
            FsError::HostUnreachable => libc::EHOSTUNREACH,
            FsError::NetworkUnreachable => libc::ENETUNREACH,
            FsError::ConnectionAborted => libc::ECONNABORTED,
            FsError::NotConnected => libc::ENOTCONN,
            FsError::AddrInUse => libc::EADDRINUSE,
            FsError::AddrNotAvailable => libc::EADDRNOTAVAIL,
            FsError::NetworkDown => libc::ENETDOWN,
            FsError::BrokenPipe => libc::EPIPE,
            FsError::AlreadyExists => libc::EEXIST,
            FsError::WouldBlock => libc::EWOULDBLOCK,
            FsError::NotADirectory => libc::ENOTDIR,
            FsError::IsADirectory => libc::EISDIR,
            FsError::DirectoryNotEmpty => libc::ENOTEMPTY,
            FsError::ReadOnlyFilesystem => libc::EROFS,
            FsError::FilesystemLoop => libc::ELOOP,
            FsError::StaleNetworkFileHandle => libc::ESTALE,
            FsError::InvalidInput => libc::EINVAL,
            FsError::InvalidData => libc::EINVAL,
            FsError::TimedOut => libc::ETIMEDOUT,
            FsError::WriteZero => 256 as c_int,
            FsError::StorageFull => libc::ENOSPC,
            FsError::NotSeekable => libc::EINVAL,
            FsError::FilesystemQuotaExceeded => libc::EDQUOT,
            FsError::FileTooLarge => libc::EFBIG,
            FsError::ResourceBusy => libc::EBUSY,
            FsError::ExecutableFileBusy => libc::EBUSY,
            FsError::Deadlock => libc::EDEADLOCK,
            FsError::CrossesDevices => libc::EXDEV,
            FsError::TooManyLinks => libc::EMLINK,
            FsError::InvalidFilename => libc::EINVAL,
            FsError::ArgumentListTooLong => libc::E2BIG,
            FsError::Interrupted => 257 as c_int,
            FsError::Unsupported => libc::ENOSYS,
            FsError::UnexpectedEof => 258 as c_int,
            FsError::OutOfMemory => 259 as c_int,

            FsError::CryptoError => 260 as c_int,
            FsError::IntegrityCheckError => 261 as c_int,
            FsError::CacheIsFull => 262 as c_int,
            FsError::ChannelSendError => 263 as c_int,
            FsError::ChannelRecvError => 264 as c_int,
            FsError::RwLockError => 265 as c_int,
            FsError::CacheNeedHint => 266 as c_int,

            FsError::UnknownError => 511 as c_int,
        }
    }
}
