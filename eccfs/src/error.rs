#[cfg(not(feature = "std"))]
use thiserror_no_std::Error;
#[cfg(feature = "std")]
use thiserror::Error;

#[cfg(feature = "std")]
use std::io::ErrorKind;

#[derive(Debug, Error)]
pub enum FsError {
    #[cfg(feature = "std")]
    #[error("std::io error")]
    IOError(#[from] std::io::Error),

    #[cfg(not(feature = "std"))]
    #[error("std::io error")]
    IOError,

    #[error("directory is not empty")]
    DirectoryNotEmpty,

    #[error("data encoding is invalid")]
    InvalidData,

    #[error("parameter is invalid")]
    InvalidParameter,

    #[error("cannot find requested resource")]
    NotFound,

    #[error("requested resource is not a directory")]
    NotADirectory,

    #[error("requested resource is a directory")]
    IsADirectory,

    #[error("requested resource already exists")]
    AlreadyExists,

    #[error("operation is not granted for current config")]
    PermissionDenied,

    #[error("file or source is too short")]
    UnexpectedEof,

    #[error("operation or request not supported")]
    NotSupported,

    #[error("failed in crypto opreations by aes-gcm")]
    CryptoError,

    #[error("failed to check integrity of data by sha3-256")]
    IntegrityCheckError,

    #[error("cache is full")]
    CacheIsFull,

    #[cfg(any(feature = "channel_lru", feature = "ro_cache_server"))]
    #[error("failed to send into a mpsc channel")]
    ChannelSendError,

    #[cfg(any(feature = "channel_lru", feature = "ro_cache_server"))]
    #[error("failed to recv from a mpsc channel")]
    ChannelRecvError,

    #[error("failed to lock or unlock rwlock")]
    RwLockError,

    #[error("failed to lock or unlock mutex")]
    MutexError,

    #[error("no hint is provided when cache needs one")]
    CacheNeedHint,

    #[error("metadata in this fs are not compatible with each other")]
    IncompatibleMetadata,

    #[error("failed to check metadata in superblock")]
    SuperBlockCheckFailed,

    #[error("unknown error")]
    UnknownError,
}

pub type FsResult<T> = Result<T, FsError>;

use libc::c_int;
impl Into<c_int> for FsError {
    fn into(self) -> c_int {
        match self {
            #[cfg(feature = "std")]
            FsError::IOError(io_err) => {
                match io_err.kind() {
                    ErrorKind::NotFound => libc::ENOENT,
                    ErrorKind::PermissionDenied => libc::EACCES,
                    ErrorKind::ConnectionRefused => libc::ECONNREFUSED,
                    ErrorKind::ConnectionReset => libc::ECONNRESET,
                    ErrorKind::ConnectionAborted => libc::ECONNABORTED,
                    ErrorKind::NotConnected => libc::ENOTCONN,
                    ErrorKind::AddrInUse => libc::EADDRINUSE,
                    ErrorKind::AddrNotAvailable => libc::EADDRNOTAVAIL,
                    ErrorKind::BrokenPipe => libc::EPIPE,
                    ErrorKind::AlreadyExists => libc::EEXIST,
                    ErrorKind::WouldBlock => libc::EWOULDBLOCK,
                    ErrorKind::InvalidInput => libc::EINVAL,
                    ErrorKind::InvalidData => libc::EINVAL,
                    ErrorKind::TimedOut => libc::ETIMEDOUT,
                    ErrorKind::WriteZero => 256 as c_int,
                    ErrorKind::Interrupted => 257 as c_int,
                    ErrorKind::Unsupported => libc::ENOSYS,
                    ErrorKind::UnexpectedEof => 258 as c_int,
                    ErrorKind::OutOfMemory => 259 as c_int,
                    _ => 511 as c_int,
                }
            },
            #[cfg(not(feature = "std"))]
            FsError::IOError => libc::EIO,
            FsError::DirectoryNotEmpty => libc::ENOTEMPTY,
            FsError::InvalidData => libc::EINVAL,
            FsError::InvalidParameter => libc::EINVAL,
            FsError::NotFound => libc::ENOENT,
            FsError::NotADirectory => libc::ENOTDIR,
            FsError::IsADirectory => libc::EISDIR,
            FsError::AlreadyExists => libc::EEXIST,
            FsError::PermissionDenied => libc::EACCES,
            FsError::UnexpectedEof => 258 as c_int,
            FsError::NotSupported => libc::ENOSYS,
            FsError::CryptoError => 260 as c_int,
            FsError::IntegrityCheckError => 261 as c_int,
            FsError::CacheIsFull => 262 as c_int,
            #[cfg(any(feature = "channel_lru", feature = "ro_cache_server"))]
            FsError::ChannelSendError => 263 as c_int,
            #[cfg(any(feature = "channel_lru", feature = "ro_cache_server"))]
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

#[macro_export]
macro_rules! new_error{
    ($e: expr) => {
        if cfg!(debug_assertions) {
            panic!("Error: {:?}", $e);
        } else {
            $e
        }
    }
}

#[allow(unused)]
#[cfg(feature = "std")]
#[macro_export]
macro_rules! io_try {
    ($e: expr) => {
        $e.map_err(|e| FsError::IOError(e))?
    };
}

#[allow(unused)]
#[cfg(not(feature = "std"))]
#[macro_export]
macro_rules! io_try {
    ($e: expr) => {
        $e.map_err(|_| FsError::IOError)?
    };
}
