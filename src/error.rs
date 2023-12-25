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
    MutexError,
    CacheNeedHint,
    IncompatibleMetadata,
    SuperBlockCheckFailed,

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
            0   => Self::NotFound,
            1   => Self::PermissionDenied,
            2   => Self::ConnectionRefused,
            3   => Self::ConnectionReset,
            4   => Self::HostUnreachable,
            5   => Self::NetworkUnreachable,
            6   => Self::ConnectionAborted,
            7   => Self::NotConnected,
            8   => Self::AddrInUse,
            9   => Self::AddrNotAvailable,
            10  => Self::NetworkDown,
            11  => Self::BrokenPipe,
            12  => Self::AlreadyExists,
            13  => Self::WouldBlock,
            14  => Self::NotADirectory,
            15  => Self::IsADirectory,
            16  => Self::DirectoryNotEmpty,
            17  => Self::ReadOnlyFilesystem,
            18  => Self::FilesystemLoop,
            19  => Self::StaleNetworkFileHandle,
            20  => Self::InvalidInput,
            21  => Self::InvalidData,
            22  => Self::TimedOut,
            23  => Self::WriteZero,
            24  => Self::StorageFull,
            25  => Self::NotSeekable,
            26  => Self::FilesystemQuotaExceeded,
            27  => Self::FileTooLarge,
            28  => Self::ResourceBusy,
            29  => Self::ExecutableFileBusy,
            30  => Self::Deadlock,
            31  => Self::CrossesDevices,
            32  => Self::TooManyLinks,
            33  => Self::InvalidFilename,
            34  => Self::ArgumentListTooLong,
            35  => Self::Interrupted,
            36  => Self::Unsupported,
            37  => Self::UnexpectedEof,
            38  => Self::OutOfMemory,
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
            FsError::MutexError => 266 as c_int,
            FsError::CacheNeedHint => 267 as c_int,
            FsError::IncompatibleMetadata => 268 as c_int,
            FsError::SuperBlockCheckFailed => 269 as c_int,

            FsError::UnknownError => 511 as c_int,
        }
    }
}
