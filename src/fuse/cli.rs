use fuser::*;
use std::time::SystemTime;
use libc::c_int;
use std::ffi::{OsStr, OsString};
use std::path::Path;
use eccfs::*;
use eccfs::vfs::*;
use std::time::Duration;
use std::fs::File;
use std::io::prelude::*;

struct EccFs {
    fs: Box<dyn vfs::FileSystem>,
}

const DEFAULT_TTL: Duration = Duration::new(1, 0);

macro_rules! fuse_try {
    ($res:expr, $reply:expr) => {
        match $res {
            Ok(v) => v,
            Err(e) => {
                $reply.error(e.into());
                return;
            }
        }
    };
}

fn libc_mode_split(mode: u32) -> FsResult<(vfs::FileType, u16)> {
    let tp = match mode & libc::S_IFMT as u32 {
        libc::S_IFREG => vfs::FileType::Reg,
        libc::S_IFDIR => vfs::FileType::Dir,
        libc::S_IFLNK => vfs::FileType::Lnk,
        _ => return Err(new_error!(FsError::NotSupported)),
    };
    Ok((tp, (mode & 0x0777) as u16))
}

impl Filesystem for EccFs {
    fn init(&mut self, _req: &Request<'_>, _config: &mut KernelConfig) -> Result<(), c_int> {
        self.fs.init().map_err(
            |e| e.into()
        )
    }

    fn destroy(&mut self) {
        self.fs.destroy().unwrap();
    }

    fn lookup(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEntry) {
        if let Some(iid) = fuse_try!(self.fs.lookup(parent, name), reply) {
            let meta = fuse_try!(self.fs.get_meta(iid), reply);
            reply.entry(&DEFAULT_TTL, &meta.into(), 0);
        } else {
            debug!("lookup not found");
            reply.error(FsError::NotFound.into());
        }
    }

    fn getattr(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyAttr) {
        let meta = fuse_try!(self.fs.get_meta(ino), reply);
        reply.attr(&DEFAULT_TTL, &meta.into());
    }

    fn setattr(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        mode: Option<u32>,
        uid: Option<u32>,
        gid: Option<u32>,
        size: Option<u64>,
        atime: Option<TimeOrNow>,
        mtime: Option<TimeOrNow>,
        ctime: Option<SystemTime>,
        _fh: Option<u64>,
        _crtime: Option<SystemTime>,
        _chgtime: Option<SystemTime>,
        _bkuptime: Option<SystemTime>,
        _flags: Option<u32>,
        reply: ReplyAttr,
    ) {
        let mut set_list = Vec::new();
        if let Some(mode) = mode {
            let (_, perm) = fuse_try!(libc_mode_split(mode), reply);
            set_list.push(SetMetadata::Permission(perm));
        }
        if let Some(uid) = uid {
            set_list.push(SetMetadata::Uid(uid));
        }
        if let Some(gid) = gid {
            set_list.push(SetMetadata::Gid(gid));
        }
        if let Some(sz) = size {
            set_list.push(SetMetadata::Size(sz as usize));
        }
        if let Some(atime) = atime {
            let atime = match atime {
                TimeOrNow::SpecificTime(systime) => systime,
                TimeOrNow::Now => SystemTime::now(),
            };
            set_list.push(SetMetadata::Atime(atime));
        }
        if let Some(mtime) = mtime {
            let mtime = match mtime {
                TimeOrNow::SpecificTime(systime) => systime,
                TimeOrNow::Now => SystemTime::now(),
            };
            set_list.push(SetMetadata::Mtime(mtime));
        }
        if let Some(ctime) = ctime {
            set_list.push(SetMetadata::Ctime(ctime));
        }
        for set_md in set_list {
            fuse_try!(self.fs.set_meta(ino, set_md), reply);
        }
        let meta = fuse_try!(self.fs.get_meta(ino), reply);
        reply.attr(&DEFAULT_TTL, &meta.into());
    }

    fn readlink(&mut self, _req: &Request<'_>, ino: u64, reply: ReplyData) {
        let link_path = fuse_try!(self.fs.iread_link(ino), reply);
        reply.data(link_path.as_os_str().as_encoded_bytes());
    }

    fn mkdir(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        reply: ReplyEntry,
    ) {
        let (_, perm) = fuse_try!(libc_mode_split(mode), reply);
        let uid = req.uid();
        let gid = req.gid();
        let iid = fuse_try!(self.fs.create(
            parent, name, vfs::FileType::Dir,
            uid, gid, FilePerm::from_bits(perm).unwrap(),
        ), reply);
        let meta = fuse_try!(self.fs.get_meta(iid), reply);
        reply.entry(&DEFAULT_TTL, &meta.into(), 0);
    }

    fn unlink(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        fuse_try!(self.fs.unlink(parent, name), reply);
        reply.ok();
    }

    fn rmdir(&mut self, _req: &Request<'_>, parent: u64, name: &OsStr, reply: ReplyEmpty) {
        fuse_try!(self.fs.unlink(parent, name), reply);
        reply.ok();
    }

    fn symlink(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        link_name: &OsStr,
        target: &Path,
        reply: ReplyEntry,
    ) {
        let uid = req.uid();
        let gid = req.gid();
        let iid = fuse_try!(self.fs.symlink(
            parent, link_name, target,
            uid, gid,
        ), reply);
        let meta = fuse_try!(self.fs.get_meta(iid), reply);
        reply.entry(&DEFAULT_TTL, &meta.into(), 0);
    }

    fn rename(
        &mut self,
        _req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        newparent: u64,
        newname: &OsStr,
        _flags: u32,
        reply: ReplyEmpty,
    ) {
        fuse_try!(self.fs.rename(parent, name, newparent, newname), reply);
        reply.ok();
    }

    fn link(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        newparent: u64,
        newname: &OsStr,
        reply: ReplyEntry,
    ) {
        fuse_try!(self.fs.link(newparent, newname, ino), reply);
        let meta = fuse_try!(self.fs.get_meta(ino), reply);
        reply.entry(&DEFAULT_TTL, &meta.into(), 0);
    }

    fn read(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        size: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyData,
    ) {
        let mut buf = Vec::<u8>::with_capacity(size as usize);
        buf.resize(size as usize, 0);
        assert!(offset >= 0);
        let read = fuse_try!(self.fs.iread(ino, offset as usize, buf.as_mut_slice()), reply);
        buf.resize(read, 0);
        reply.data(buf.as_slice());
    }

    fn write(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        data: &[u8],
        _write_flags: u32,
        _flags: i32,
        _lock_owner: Option<u64>,
        reply: ReplyWrite,
    ) {
        assert!(offset >= 0);
        let written = fuse_try!(self.fs.iwrite(ino, offset as usize, data), reply);
        reply.written(written as u32);
    }

    fn flush(&mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        _lock_owner: u64,
        reply: ReplyEmpty,
    ) {
        fuse_try!(self.fs.isync_meta(ino), reply);
        fuse_try!(self.fs.isync_data(ino), reply);
        reply.ok();
    }

    fn fsync(&mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        datasync: bool,
        reply: ReplyEmpty,
    ) {
        fuse_try!(self.fs.isync_meta(ino), reply);
        if datasync {
            fuse_try!(self.fs.isync_meta(ino), reply);
        }
        reply.ok();
    }

    fn readdir(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        mut offset: i64,
        mut reply: ReplyDirectory,
    ) {
        assert!(offset >= 0);

        loop {
            if let Some((iid, name, ft)) = fuse_try!(self.fs.next_entry(
                ino, offset as usize
            ), reply) {
                offset += 1;
                if reply.add(
                    iid,
                    offset,
                    ft.into(),
                    OsString::from(name),
                ) {
                    debug!("Buffer full");
                    break;
                }
            } else {
                break;
            }
        }

        reply.ok();
    }

    fn statfs(&mut self, _req: &Request<'_>, _ino: u64, reply: ReplyStatfs) {
        let info = fuse_try!(self.fs.finfo(), reply);
        reply.statfs(
            info.blocks as u64,
            info.bfree as u64,
            info.bavail as u64,
            info.files as u64,
            info.ffree as u64,
            info.bsize as u32,
            info.namemax as u32,
            info.frsize as u32,
        );
    }

    fn access(&mut self, req: &Request<'_>, ino: u64, mask: i32, reply: ReplyEmpty) {
        let meta = fuse_try!(self.fs.get_meta(ino), reply);
        if check_access(meta.uid, meta.gid, meta.perm.bits(), req.uid(), req.gid(), mask) {
            debug!("Access Ok");
            reply.ok();
        } else {
            debug!("Access Denied");
            reply.error(libc::EACCES);
        }
    }

    fn create(
        &mut self,
        req: &Request<'_>,
        parent: u64,
        name: &OsStr,
        mode: u32,
        _umask: u32,
        _flags: i32,
        reply: ReplyCreate,
    ) {
        let (tp, perm) = fuse_try!(libc_mode_split(mode), reply);
        let uid = req.uid();
        let gid = req.gid();
        let iid = fuse_try!(self.fs.create(
            parent, name, tp,
            uid, gid, FilePerm::from_bits(perm).unwrap(),
        ), reply);
        let meta = fuse_try!(self.fs.get_meta(iid), reply);
        reply.created(&DEFAULT_TTL, &meta.into(), 0, 0, 0);
    }

    fn fallocate(
        &mut self,
        _req: &Request<'_>,
        ino: u64,
        _fh: u64,
        offset: i64,
        length: i64,
        mode: i32,
        reply: ReplyEmpty,
    ) {
        assert!(offset >= 0);
        assert!(length >= 0);

        // const LIBC_ZERO_KEEP_SZ: i32 = libc::FALLOC_FL_ZERO_RANGE | libc::FALLOC_FL_KEEP_SIZE;
        let mode = match mode {
            0 => FallocateMode::Alloc,
            // libc::FALLOC_FL_KEEP_SIZE => FallocateMode::AllocKeepSize,
            libc::FALLOC_FL_ZERO_RANGE => FallocateMode::ZeroRange,
            // LIBC_ZERO_KEEP_SZ =>
            //     FallocateMode::ZeroRangeKeepSize,
            _ => {
                reply.error(libc::ENOSYS);
                return;
            }
        };
        fuse_try!(self.fs.fallocate(ino, mode, offset as usize, length as usize), reply);
        reply.ok();
    }
}

fn mount_ro(mode: FSMode, target: String) -> FsResult<()> {
    debug!("Mounting {}", target);

    let path = format!("test/{}.roimage", target);
    let mount = Path::new("test/mnt");
    let rofs = ro::ROFS::new(
        Path::new(&path),
        mode.clone(),
        128,
        64,
        0,
    )?;

    fuser::mount2(
        EccFs {
            fs: Box::new(rofs),
        },
        mount,
        &vec![
            MountOption::AllowOther,
            MountOption::AutoUnmount,
            MountOption::RO,
        ]
    ).unwrap();

    Ok(())
}

fn mount_rw(mode: FSMode, target: String) -> FsResult<()> {
    debug!("Mounting {}", target);

    let path = format!("test/{}.rwimage", target);
    let mount = Path::new("test/mnt");
    let rwfs = rw::RWFS::new(
        false,
        Path::new(&path),
        mode,
        Some(128),
        0,
    )?;

    fuser::mount2(
        EccFs {
            fs: Box::new(rwfs),
        },
        mount,
        &vec![
            MountOption::AllowOther,
            MountOption::AutoUnmount,
        ]
    ).unwrap();

    Ok(())
}

fn main() -> FsResult<()> {
    env_logger::builder()
        .filter_level(log::LevelFilter::Debug)
        .init();

    // read mode from file
    let mut f = File::open("test/mode").unwrap();
    let mut b = vec![0u8; std::mem::size_of::<FSMode>()];
    f.read_exact(&mut b).unwrap();
    let mode = unsafe {
        &*(b.as_ptr() as *const FSMode)
    };
    match mode {
        FSMode::IntegrityOnly(hash) => {
            let s = hex::encode_upper(hash);
            info!("Run in IntegrityOnly Mode:");
            info!("Hash: {}", s);
        }
        FSMode::Encrypted(key, mac) => {
            info!("Run in Encrypted Mode:");
            let k = hex::encode_upper(key);
            let m = hex::encode_upper(mac);
            info!("Key: {}", k);
            info!("Mac: {}", m);
        }
    }

    let args: Vec<String> = std::env::args().collect();
    assert!(args.len() >= 2);
    let target = args[1].clone();

    mount_rw(mode.clone(), target)?;

    Ok(())
}
