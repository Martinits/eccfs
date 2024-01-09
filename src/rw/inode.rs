use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::time::{SystemTime, Duration};
use std::mem::{size_of, size_of_val};
use crate::htree::*;
use std::ffi::OsStr;
use crate::crypto::half_md4;
use super::*;
use std::str::FromStr;
use std::fs::{File, OpenOptions};
use std::io::prelude::*;

pub struct DirEntry {
    pub ipos: u64,
    pub tp: FileType,
    pub name: String,
}

impl Into<DiskDirEntry> for DirEntry {
    fn into(self) -> DiskDirEntry {
        assert!(self.name.len() <= DIRENT_NAME_MAX);

        let mut name = [0u8; DIRENT_NAME_MAX];
        name[..self.name.len()].copy_from_slice(self.name.as_bytes());

        DiskDirEntry {
            ipos: self.ipos,
            tp: self.tp.into(),
            len: self.name.len() as u16,
            name,
        }
    }
}

impl From<DiskDirEntry> for DirEntry {
    fn from(value: DiskDirEntry) -> Self {
        Self {
            ipos: value.ipos,
            tp: value.tp.into(),
            name: String::from(std::str::from_utf8(
                &value.name[..value.len as usize]
            ).unwrap())
        }
    }
}

enum InodeExt {
    Reg {
        data_file_name: PathBuf,
        data: RWHashTree,
    },
    RegInline(Vec<u8>),
    Dir {
        data_file_name: PathBuf,
        data: RWHashTree,
    },
    Lnk(PathBuf),
}

pub const REG_INLINE_EXPAND_THRESHOLD: usize = BLK_SZ;

pub struct Inode {
    iid: InodeID,
    pub tp: FileType,
    perm: FilePerm,
    pub nlinks: u16,
    uid: u32,
    gid: u32,
    atime: SystemTime,
    ctime: SystemTime,
    mtime: SystemTime,
    size: usize, // with . and ..
    ext: InodeExt,
    encrypted: bool,
    fs_path: PathBuf,
}

pub type InodeBytes = [u8; INODE_SZ];

pub fn iid_to_htree_logi_pos(iid: InodeID) -> usize {
    iid as usize * INODE_SZ
}

fn iid_hash(iid: InodeID) -> FsResult<Hash256> {
    sha3_256_any(
        unsafe {
            std::slice::from_raw_parts(
                &iid as *const InodeID as *const u8,
                size_of::<InodeID>(),
            )
        },
    )
}

fn iid_hash_check(iid: InodeID, exp_hash: &Hash256) -> FsResult<()> {
    sha3_256_any_check(
        unsafe {
            std::slice::from_raw_parts(
                &iid as *const InodeID as *const u8,
                size_of::<InodeID>(),
            )
        },
        exp_hash
    )
}

fn new_data_file(mut dir: PathBuf, iid : InodeID) -> FsResult<(PathBuf, Box<dyn RWStorage>)> {
    let hash = iid_hash(iid)?;
    let fname = hex::encode_upper(hash);
    assert_eq!(fname.len(), DATA_FILE_NAME_LEN);
    dir.push(fname.clone());

    {
        // try create new file
        let _ = io_try!(OpenOptions::new()
                            .create_new(true)
                            .read(true)
                            .write(true)
                            .open(&dir)
        );
    }

    Ok((fname.into(), Box::new(FileStorage::new(&dir, true)?)))
}

impl Inode {
    pub fn new_from_raw(
        raw: &InodeBytes,
        iid: InodeID,
        fs_path: &PathBuf,
        encrypted: bool,
    ) -> FsResult<Self> {
        let di_base = unsafe {
            &*(raw.as_ptr() as *const DInodeBase)
        };
        let tp = get_ftype_from_mode(di_base.mode);
        let mut ret = Self {
            iid,
            tp,
            perm: get_perm_from_mode(di_base.mode),
            nlinks: di_base.nlinks,
            uid: di_base.uid,
            gid: di_base.gid,
            atime: SystemTime::UNIX_EPOCH + Duration::from_secs(di_base.atime as u64),
            ctime: SystemTime::UNIX_EPOCH + Duration::from_secs(di_base.ctime as u64),
            mtime: SystemTime::UNIX_EPOCH + Duration::from_secs(di_base.mtime as u64),
            size: di_base.size as usize,
            // just something to hold the place
            ext: InodeExt::Lnk(PathBuf::new()),
            encrypted,
            fs_path: fs_path.clone(),
        };

        ret.ext = match tp {
            FileType::Reg => {
                if di_base.size <= REG_INLINE_DATA_MAX as u64 {
                    // inline data
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeRegInline)
                    };
                    let d = Vec::from(
                        &di.data[..di_base.size as usize]
                    );
                    InodeExt::RegInline(d)
                } else {
                    // htree data
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeReg)
                    };
                    iid_hash_check(iid, &di.data_file)?;
                    let mut p = fs_path.clone();
                    let fname = hex::encode_upper(&di.data_file);
                    assert_eq!(fname.len(), DATA_FILE_NAME_LEN);
                    p.push(fname.clone());
                    let back = FileStorage::new(&p, true)?;
                    InodeExt::Reg {
                        data_file_name: fname.into(),
                        data: RWHashTree::new(
                            None,
                            Box::new(back),
                            di.base.size.div_ceil(BLK_SZ as u64),
                            Some(FSMode::from_key_entry(di.data_file_ke.clone(), encrypted)),
                            encrypted,
                        )
                    }
                }
            }
            FileType::Dir => {
                let di = unsafe {
                    &*(raw.as_ptr() as *const DInodeDir)
                };
                iid_hash_check(iid, &di.data_file)?;
                let mut p = fs_path.clone();
                let fname = hex::encode_upper(&di.data_file);
                assert_eq!(fname.len(), DATA_FILE_NAME_LEN);
                p.push(fname.clone());
                let back = FileStorage::new(&p, true)?;
                InodeExt::Dir {
                    data_file_name: fname.into(),
                    data: RWHashTree::new(
                        None,
                        Box::new(back),
                        di.base.size.div_ceil(BLK_SZ as u64),
                        Some(FSMode::from_key_entry(di.data_file_ke.clone(), encrypted)),
                        encrypted,
                    )
                }
            }
            FileType::Lnk => {
                let lnk_name = if di_base.size <= LNK_INLINE_MAX as u64 {
                    // inline link name
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeLnkInline)
                    };
                    PathBuf::from_str(
                        std::str::from_utf8(
                            &di.name[..di.base.size as usize]
                        ).unwrap()
                    ).unwrap()
                } else {
                    // single block file
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeLnk)
                    };
                    iid_hash_check(iid, &di.data_file)?;
                    sha3_256_any_check(
                        unsafe {
                            std::slice::from_raw_parts(
                                &iid as *const InodeID as *const u8,
                                size_of::<InodeID>(),
                            )
                        },
                        &di.data_file
                    )?;

                    // read data block
                    let mut p = fs_path.clone();
                    let fname = hex::encode_upper(&di.data_file);
                    assert_eq!(fname.len(), DATA_FILE_NAME_LEN);
                    p.push(fname);
                    let mut f = io_try!(File::open(p));
                    let mut blk = [0u8; BLK_SZ];
                    io_try!(f.read_exact(&mut blk));
                    crypto_in(
                        &mut blk,
                        CryptoHint::from_key_entry(
                            di.name_file_ke.clone(),
                            encrypted,
                            LNK_DATA_FILE_BLK_POS,
                        )
                    )?;
                    PathBuf::from_str(
                        std::str::from_utf8(
                            &blk[..di.base.size as usize]
                        ).unwrap()
                    ).unwrap()
                };
                InodeExt::Lnk(lnk_name)
            }
        };
        Ok(ret)
    }

    pub fn new(
        iid: InodeID,
        tp: FileType,
        uid: u32,
        gid: u32,
        perm: u16, // only last 9 bits conuts
        fs_path: &PathBuf,
        encrypted: bool,
    ) -> FsResult<Self> {
        Ok(Self {
            iid,
            tp,
            perm: FilePerm::from_bits(perm).unwrap(),
            nlinks: 1,
            uid,
            gid,
            atime: SystemTime::now(),
            ctime: SystemTime::now(),
            mtime: SystemTime::now(),
            size: 0,
            ext: match tp {
                FileType::Reg => InodeExt::RegInline(Vec::new()),
                FileType::Dir => {
                    let (data_file_name, backend) = new_data_file(fs_path.clone(), iid)?;
                    InodeExt::Dir {
                        data_file_name,
                        data: RWHashTree::new(
                            None,
                            backend,
                            0,
                            None,
                            encrypted,
                        )
                    }
                }
                FileType::Lnk => InodeExt::Lnk(PathBuf::new()),
            },
            encrypted,
            fs_path: fs_path.clone(),
        })
    }

    pub fn read_data(&mut self, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        if offset >= self.size {
            Err(FsError::InvalidInput)
        } else {
            let readable = (self.size - offset).min(to.len());
            match &mut self.ext {
                InodeExt::Reg { data, .. } => {
                    let read = data.read_exact(offset, &mut to[..readable])?;
                    Ok(read)
                }
                InodeExt::RegInline(data) => {
                    assert!(data.len() == self.size);
                    to[..readable].copy_from_slice(&data[offset..offset+readable]);
                    Ok(readable)
                }
                _ => Err(FsError::PermissionDenied),
            }
        }
    }

    pub fn write_data(&mut self, offset: usize, from: &[u8]) -> FsResult<usize> {
        self.possible_expand_to_htree(offset + from.len())?;

        match &mut self.ext {
            InodeExt::Reg { data, .. } => {
                let written = data.write_exact(offset, from)?;
                Ok(written)
            }
            InodeExt::RegInline(data) => {
                assert!(data.len() == self.size);
                let write_end = offset + from.len();
                data.resize(write_end, 0);
                data[offset..write_end].copy_from_slice(from);
                Ok(from.len())
            }
            _ => Err(FsError::PermissionDenied),
        }
    }

    fn possible_expand_to_htree(&mut self, write_end: usize) -> FsResult<()> {
        if let InodeExt::RegInline(_) = &self.ext {
            if write_end > REG_INLINE_EXPAND_THRESHOLD {
                self.expand_to_htree()?;
            }
        }
        Ok(())
    }

    fn expand_to_htree(&mut self) -> FsResult<()> {
        let (data_file_name, htree) = match &self.ext {
            InodeExt::RegInline(data) => {
                let (data_file_name, backend) = new_data_file(self.fs_path.clone(), self.iid)?;
                let mut htree = RWHashTree::new(
                    None,
                    backend,
                    0,
                    None,
                    self.encrypted,
                );
                assert_eq!(htree.write_exact(0, data)?, data.len());
                (data_file_name, htree)
            }
            _ => return Err(FsError::UnknownError),
        };

        self.ext = InodeExt::Reg {
            data_file_name,
            data: htree,
        };

        Ok(())
    }

    fn set_file_len(&mut self, new_sz: usize) -> FsResult<()> {
        self.possible_expand_to_htree(new_sz)?;

        match &mut self.ext {
            InodeExt::RegInline(data) => {
                data.resize(new_sz, 0);
            }
            InodeExt::Reg { data, .. } => {
                data.resize(new_sz.div_ceil(BLK_SZ) as u64)?;
            }
            _ => return Err(FsError::PermissionDenied),
        }
        self.size = new_sz as usize;
        Ok(())
    }

    pub fn get_meta(&self) -> FsResult<Metadata> {
        Ok(Metadata {
            iid: self.iid,
            size: match self.tp {
                FileType::Reg => self.size,
                FileType::Dir => self.size * size_of::<DirEntry>(),
                FileType::Lnk => 0,
            } as u64,
            blocks: if self.tp == FileType::Reg {
                self.size.div_ceil(BLK_SZ) as u64
            } else {
                0
            },
            atime: self.atime,
            ctime: self.ctime,
            mtime: self.mtime,
            ftype: self.tp,
            perm: self.perm.bits(),
            nlinks: self.nlinks,
            uid: self.uid,
            gid: self.gid,
        })
    }

    pub fn set_meta(&mut self, set_meta: SetMetadata) -> FsResult<()> {
        match set_meta {
            SetMetadata::Size(sz) => self.set_file_len(sz)?,
            SetMetadata::Atime(t) => self.atime = t,
            SetMetadata::Ctime(t) => self.ctime = t,
            SetMetadata::Mtime(t) => self.mtime = t,
            SetMetadata::Type(_) => return Err(FsError::PermissionDenied),
            SetMetadata::Permission(perm) => {
                self.perm = FilePerm::from_bits(perm).unwrap();
            }
            SetMetadata::Uid(uid) => self.uid = uid,
            SetMetadata::Gid(gid) => self.gid = gid,
        }
        Ok(())
    }

    pub fn get_link(&self) -> FsResult<PathBuf> {
        if let InodeExt::Lnk(lnk) = &self.ext {
            Ok(lnk.clone())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    pub fn set_link(&mut self, target: &Path) -> FsResult<()> {
        if let InodeExt::Lnk(p) = &mut self.ext {
            *p = target.into();
            Ok(())
        } else {
            Err(FsError::PermissionDenied)
        }
    }

    pub fn read_child(&mut self, offset: usize, num: usize) -> FsResult<Vec<DirEntry>> {
        match &mut self.ext {
            InodeExt::Dir { data, .. } => {
                let de_list: Vec<DiskDirEntry> = Vec::with_capacity(num);
                let len = num * DIRENT_SZ;
                let read = data.read_exact(
                    offset * DIRENT_SZ,
                    unsafe {
                        std::slice::from_raw_parts_mut(
                            de_list.as_ptr() as *mut u8,
                            len,
                        )
                    }
                )?;
                assert_eq!(len, read);
                Ok(de_list.into_iter().map(
                    |de| de.into()
                ).collect())
            }
            _ => Err(FsError::PermissionDenied),
        }
    }

    pub fn find_child(&mut self, name: &OsStr) -> FsResult<Option<InodeID>> {
        let mut done = 0;
        while done < self.size {
            // try read a block of de
            let round = DIRENT_PER_BLK.min(self.size - done);
            for de in self.read_child(done, round)? {
                if de.name.as_str() == name {
                    return Ok(Some(de.ipos));
                }
            }
            done += round;
        }
        Ok(None)
    }

    fn find_child_pos(&mut self, name: &OsStr) -> FsResult<Option<(usize, DirEntry)>> {
        let mut done = 0;
        while done < self.size {
            // try read a block of de
            let round = DIRENT_PER_BLK.min(self.size - done);
            for (i, de) in self.read_child(done, round)?.into_iter().enumerate() {
                if de.name.as_str() == name {
                    return Ok(Some((done + i, de)));
                }
            }
            done += round;
        }
        Ok(None)
    }

    pub fn add_child(&mut self, name: &OsStr, tp: FileType, iid: InodeID) -> FsResult<()> {
        if self.find_child(name)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        match &mut self.ext {
            InodeExt::Dir { data, .. } => {
                let dde: DiskDirEntry = DirEntry {
                    ipos: iid,
                    tp: tp.into(),
                    name: String::from(name.to_str().unwrap()),
                }.into();
                let written = data.write_exact(self.size * DIRENT_SZ, dde.as_ref())?;
                assert_eq!(written, size_of_val(&dde));
                self.size += 1;
                Ok(())
            }
            _ => Err(FsError::PermissionDenied),
        }
    }

    pub fn rename_child(&mut self, name: &OsStr, newname: &OsStr) -> FsResult<()> {
        if self.find_child(newname)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        if let Some((pos, mut de)) = self.find_child_pos(name)? {
            match &mut self.ext {
                InodeExt::Dir { data, .. } => {
                    de.name = String::from(newname.to_str().unwrap());
                    let dde: DiskDirEntry = de.into();
                    let written = data.write_exact(pos * DIRENT_SZ, dde.as_ref())?;
                    assert_eq!(written, DIRENT_SZ);
                    Ok(())
                }
                _ => Err(FsError::PermissionDenied),
            }
        } else {
            Err(FsError::NotFound)
        }
    }

    pub fn remove_child(&mut self, name: &OsStr) -> FsResult<(InodeID, FileType)> {
        if let Some((pos, de)) = self.find_child_pos(name)? {
            if let InodeExt::Dir { data, .. } = &mut self.ext {
                if pos != self.size - 1 {
                    // read last dde
                    let mut last_dde = [0u8; DIRENT_SZ];
                    let read = data.read_exact((self.size - 1) * DIRENT_SZ, &mut last_dde)?;
                    assert_eq!(read, DIRENT_SZ);

                    // write last dde to the removed place
                    let written = data.write_exact(pos * DIRENT_SZ, last_dde.as_ref())?;
                    assert_eq!(written, DIRENT_SZ);
                }
                self.size -= 1;
                Ok((de.ipos, de.tp))
            } else {
                Err(FsError::PermissionDenied)
            }
        } else {
            Err(FsError::NotFound)
        }
    }

    pub fn fallocate(&mut self, mode: FallocateMode, offset: usize, len: usize) -> FsResult<()> {
        // use htree pad_to
        // htree new method: zero_range
        unimplemented!();
    }

    pub fn sync_data(&mut self) -> FsResult<()> {
        // htree to inline, inline to tree, no REG_INLINE_EXPAND_THRESHOLD
        unimplemented!();
    }

    pub fn sync_meta(&self) -> FsResult<InodeBytes> {
        unimplemented!();
    }

    pub fn destroy(self) -> FsResult<InodeBytes> {
        unimplemented!();
    }

    pub fn remove_data_file(&self) -> FsResult<()> {
        // remove data file
        unimplemented!();
    }
}
