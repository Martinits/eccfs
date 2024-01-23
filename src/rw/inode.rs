use crate::*;
use crate::vfs::*;
use super::disk::*;
use std::time::{SystemTime, Duration};
use std::mem::{size_of, size_of_val};
use crate::htree::*;
use std::ffi::OsStr;
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
        htree_org_len: u64, // in blocks
        data: RWHashTree,
    },
    RegInline(Vec<u8>),
    Dir {
        data_file_name: PathBuf,
        htree_org_len: u64, // in blocks
        data: RWHashTree,
    },
    LnkInline(PathBuf),
    Lnk {
        lnk_name: PathBuf,
        data_file_name: PathBuf,
        name_file_ke: KeyEntry,
    },
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
    key_gen: KeyGen,
    sb_meta: Arc<RwLock<(usize, usize)>>,
}

pub fn iid_to_htree_logi_pos(iid: InodeID) -> usize {
    iid as usize * INODE_SZ
}

pub fn iid_hash(iid: InodeID) -> FsResult<Hash256> {
    sha3_256_any(
        unsafe {
            std::slice::from_raw_parts(
                &iid as *const InodeID as *const u8,
                size_of::<InodeID>(),
            )
        },
    )
}

pub fn iid_hash_name(iid: InodeID) -> FsResult<String> {
    let hash = iid_hash(iid)?;
    Ok(hex::encode_upper(&hash))
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

fn new_data_file(mut dir: PathBuf, iid: InodeID) -> FsResult<PathBuf> {
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

    Ok(fname.into())
}

fn new_data_storage(mut dir: PathBuf, iid : InodeID) -> FsResult<(PathBuf, Box<dyn RWStorage>)> {
    let fname = new_data_file(dir.clone(), iid)?;
    dir.push(fname.clone());

    Ok((fname, Box::new(FileStorage::new(&dir, true)?)))
}

impl Inode {
    pub fn new_from_raw(
        raw: &InodeBytes,
        iid: InodeID,
        fs_path: &PathBuf,
        encrypted: bool,
        sb_meta: Arc<RwLock<(usize, usize)>>,
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
            ext: InodeExt::LnkInline(PathBuf::new()),
            encrypted,
            fs_path: fs_path.clone(),
            key_gen: KeyGen::new(),
            sb_meta,
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

                    let mut back = FileStorage::new(&p, true)?;
                    assert_eq!(back.get_len()?, blk2byte!(di.len));
                    assert_eq!(
                        mht::get_phy_nr_blk(di.base.size.div_ceil(BLK_SZ as u64)),
                        blk2byte!(di.len)
                    );
                    InodeExt::Reg {
                        data_file_name: fname.into(),
                        htree_org_len: di.len,
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

                let mut back = FileStorage::new(&p, true)?;
                assert_eq!(back.get_len()?, blk2byte!(di.len));
                assert_eq!(
                    mht::get_phy_nr_blk(di.base.size.div_ceil(BLK_SZ as u64)),
                    blk2byte!(di.len)
                );
                InodeExt::Dir {
                    data_file_name: fname.into(),
                    htree_org_len: di.len,
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
                if di_base.size <= LNK_INLINE_MAX as u64 {
                    // inline link name
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeLnkInline)
                    };
                    let lnk_name = PathBuf::from_str(
                        std::str::from_utf8(
                            &di.name[..di.base.size as usize]
                        ).unwrap()
                    ).unwrap();
                    InodeExt::LnkInline(lnk_name)
                } else {
                    // single block file
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeLnk)
                    };
                    iid_hash_check(iid, &di.data_file)?;

                    // read data block
                    let mut p = fs_path.clone();
                    let fname = hex::encode_upper(&di.data_file);
                    assert_eq!(fname.len(), DATA_FILE_NAME_LEN);
                    p.push(fname.clone());

                    let mut f = io_try!(File::open(p));
                    assert_eq!(get_file_sz(&mut f)?, BLK_SZ as u64);
                    assert_eq!(di.len, 1);
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

                    let lnk_name = PathBuf::from_str(
                        std::str::from_utf8(
                            &blk[..di.base.size as usize]
                        ).unwrap()
                    ).unwrap();
                    InodeExt::Lnk {
                        lnk_name,
                        data_file_name: fname.into(),
                        name_file_ke: di.name_file_ke.clone(),
                    }
                }
            }
        };
        Ok(ret)
    }

    pub fn new(
        iid: InodeID,
        fiid: InodeID,
        tp: FileType,
        uid: u32,
        gid: u32,
        perm: FilePerm,
        fs_path: &PathBuf,
        encrypted: bool,
        sb_meta: Arc<RwLock<(usize, usize)>>,
    ) -> FsResult<Self> {
        let mut inode = Self {
            iid,
            tp,
            perm,
            nlinks: 1,
            uid,
            gid,
            atime: SystemTime::now(),
            ctime: SystemTime::now(),
            mtime: SystemTime::now(),
            size: 0,
            ext: InodeExt::LnkInline(PathBuf::new()),
            encrypted,
            fs_path: fs_path.clone(),
            key_gen: KeyGen::new(),
            sb_meta,
        };
        inode.ext = match tp {
            FileType::Reg => InodeExt::RegInline(Vec::new()),
            FileType::Dir => {
                let (data_file_name, backend) = new_data_storage(fs_path.clone(), iid)?;
                let mut data = RWHashTree::new(
                    None,
                    backend,
                    0,
                    None,
                    encrypted,
                );
                // write . and .. dirent
                let mut dot = DiskDirEntry {
                    ipos: iid,
                    tp: tp.into(),
                    len: 1,
                    name: [0u8; DIRENT_NAME_MAX],
                };
                dot.name[..1].copy_from_slice(".".as_bytes());
                let mut dotdot = DiskDirEntry {
                    ipos: fiid,
                    tp: tp.into(),
                    len: 2,
                    name: [0u8; DIRENT_NAME_MAX],
                };
                dotdot.name[..1].copy_from_slice("..".as_bytes());
                let dde = vec![dot, dotdot];
                data.write_exact(0,
                    unsafe {
                        std::slice::from_raw_parts(
                            dde.as_ptr() as *const u8,
                            dde.len() * DIRENT_SZ,
                        )
                    }
                )?;
                inode.size = 2 * DIRENT_SZ;

                assert_eq!(mht::get_phy_nr_blk(data.length), 2);
                nf_nb_change(&inode.sb_meta, 1, 2)?;

                InodeExt::Dir {
                    data_file_name,
                    htree_org_len: 2,
                    data,
                }
            }
            FileType::Lnk => InodeExt::LnkInline(PathBuf::new()),
        };

        Ok(inode)
    }

    pub fn read_data(&mut self, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        if offset >= self.size {
            Err(FsError::InvalidParameter)
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
                self.reg_expand_to_htree()?;
            }
        }
        Ok(())
    }

    fn reg_expand_to_htree(&mut self) -> FsResult<()> {
        let (data_file_name, htree) = match &self.ext {
            InodeExt::RegInline(data) => {
                let (data_file_name, backend) = new_data_storage(self.fs_path.clone(), self.iid)?;
                let mut htree = RWHashTree::new(
                    None,
                    backend,
                    0,
                    None,
                    self.encrypted,
                );
                assert_eq!(htree.write_exact(0, data)?, data.len());

                nf_nb_change(&self.sb_meta, 1, mht::get_phy_nr_blk(htree.length) as isize)?;

                (data_file_name, htree)
            }
            _ => return Err(FsError::UnknownError),
        };

        self.ext = InodeExt::Reg {
            data_file_name,
            htree_org_len: mht::get_phy_nr_blk(htree.length),
            data: htree,
        };

        Ok(())
    }

    fn reg_shrink_to_inline(&mut self) -> FsResult<()> {
        let (d, file_to_remove) = match &mut self.ext {
            InodeExt::Reg { data_file_name, data, .. } =>{
                assert!(self.size <= REG_INLINE_DATA_MAX);

                let mut d = vec![0u8; self.size];
                assert_eq!(data.read_exact(0, &mut d)?, self.size);

                (d, data_file_name.clone())
            }
            _ => return Err(FsError::UnknownError),
        };

        self.remove_fs_file(&file_to_remove)?;

        self.ext = InodeExt::RegInline(d);

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
                FileType::Dir => self.size,
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
            perm: self.perm,
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
        match &self.ext {
            InodeExt::LnkInline(lnk) => Ok(lnk.clone()),
            InodeExt::Lnk { lnk_name, .. } => Ok(lnk_name.clone()),
            _ => Err(FsError::PermissionDenied),
        }
    }

    pub fn set_link(&mut self, target: &Path) -> FsResult<()> {
        match &mut self.ext {
            InodeExt::LnkInline(lnk) => *lnk = target.into(),
            InodeExt::Lnk { lnk_name, .. } => *lnk_name = target.into(),
            _ => return Err(FsError::PermissionDenied),
        }
        Ok(())
    }

    pub fn read_child(
        &mut self, offset: usize, num: usize, // 0 means as many as possible
    ) -> FsResult<Vec<DirEntry>> {
        match &mut self.ext {
            InodeExt::Dir { data, .. } => {
                let num = if num == 0 {
                    self.size / DIRENT_SZ - offset
                } else {
                    num.min(self.size / DIRENT_SZ - offset)
                };
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
                let written = data.write_exact(self.size, dde.as_ref())?;
                assert_eq!(written, size_of_val(&dde));
                self.size += DIRENT_SZ;
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
                if pos * DIRENT_SZ != self.size - DIRENT_SZ {
                    // read last dde
                    let mut last_dde = [0u8; DIRENT_SZ];
                    let read = data.read_exact(self.size - DIRENT_SZ, &mut last_dde)?;
                    assert_eq!(read, DIRENT_SZ);

                    // write last dde to the removed place
                    let written = data.write_exact(pos * DIRENT_SZ, last_dde.as_ref())?;
                    assert_eq!(written, DIRENT_SZ);
                }
                self.size -= DIRENT_SZ;
                Ok((de.ipos, de.tp))
            } else {
                Err(FsError::PermissionDenied)
            }
        } else {
            Err(FsError::NotFound)
        }
    }

    pub fn fallocate(&mut self, mode: FallocateMode, offset: usize, len: usize) -> FsResult<()> {
        let end = offset + len;
        self.possible_expand_to_htree(end)?;

        if let FallocateMode::Alloc = mode {
            match &mut self.ext {
                InodeExt::Reg { data, .. } => {
                    data.resize(end.div_ceil(BLK_SZ) as u64)?;
                }
                InodeExt::RegInline(d) => {
                    d.resize(end, 0);
                }
                _ => return Err(FsError::PermissionDenied),
            }
        } else {
            // zero range
            match &mut self.ext {
                InodeExt::Reg { data, .. } => {
                    data.zero_range(offset, len)?;
                }
                InodeExt::RegInline(d) => {
                    d[offset..end].fill(0);
                }
                _ => return Err(FsError::PermissionDenied),
            }
        }
        self.size = self.size.min(end);
        Ok(())
    }

    fn write_lnk_file(f: &Path, lnk_name: &Path, encrypted: Option<Key128>) -> FsResult<FSMode> {
        let mut store = FileStorage::new(f, true)?;
        store.set_len(1)?;

        let mut blk = [0u8; BLK_SZ];
        let b = lnk_name.as_os_str().as_encoded_bytes();
        blk[..b.len()].copy_from_slice(b);

        let mode = crypto_out(
            &mut blk,
            encrypted,
            0,
        )?;
        store.write_blk(0, &blk)?;

        Ok(mode)
    }

    // return file changes,  block changes
    pub fn sync_data(&mut self) -> FsResult<()> {
        // htree to inline, inline to tree, no REG_INLINE_EXPAND_THRESHOLD
        match &mut self.ext {
            InodeExt::Reg { .. } => {
                if self.size <= REG_INLINE_DATA_MAX {
                    self.reg_shrink_to_inline()?;
                }
            }
            InodeExt::RegInline(_) => {
                if self.size > REG_INLINE_DATA_MAX {
                    self.reg_expand_to_htree()?;
                }
            }
            _ => {},
        }

        let mut file_to_remove = None;
        match &mut self.ext {
            InodeExt::Reg { data, .. } | InodeExt::Dir { data, .. } => {
                data.flush()?.into_key_entry();
            }
            InodeExt::Lnk { lnk_name, data_file_name, name_file_ke } => {
                if lnk_name.as_os_str().as_encoded_bytes().len() <= LNK_INLINE_MAX {
                    file_to_remove = Some(data_file_name.clone());
                    self.ext = InodeExt::LnkInline(lnk_name.clone());
                } else {
                    *name_file_ke = Self::write_lnk_file(
                        &data_file_name,
                        lnk_name,
                        if self.encrypted {
                            Some(self.key_gen.gen_key(0)?)
                        } else {
                            None
                        },
                    )?.into_key_entry();
                }
            }
            InodeExt::LnkInline(lnk_name) => {
                if lnk_name.as_os_str().as_encoded_bytes().len() > LNK_INLINE_MAX {
                    let data_file_name = new_data_file(
                        self.fs_path.clone(), self.iid
                    )?;
                    let name_file_ke = Self::write_lnk_file(
                        &data_file_name,
                        lnk_name,
                        if self.encrypted {
                            Some(self.key_gen.gen_key(0)?)
                        } else {
                            None
                        },
                    )?.into_key_entry();

                    self.ext = InodeExt::Lnk {
                        lnk_name: lnk_name.clone(),
                        data_file_name,
                        name_file_ke,
                    };

                    nf_nb_change(&self.sb_meta, 1, 1)?;
                }
            }
            _ => {},
        };
        if let Some(f) = file_to_remove {
            self.remove_fs_file(&f)?;
        }
        Ok(())
    }

    pub fn sync_meta(&mut self) -> FsResult<InodeBytes> {
        let base = DInodeBase {
            mode: get_mode(self.tp, &self.perm),
            nlinks: self.nlinks,
            uid: self.uid,
            gid: self.gid,
            atime: self.atime.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
            ctime: self.ctime.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
            mtime: self.mtime.duration_since(SystemTime::UNIX_EPOCH).unwrap().as_secs() as u32,
            size: self.size as u64,
        };
        let mut ib = [0u8; INODE_SZ];
        match &mut self.ext {
            InodeExt::Reg { data_file_name, htree_org_len, data } => {
                let fname_ke = iid_hash(self.iid)?;
                let fname = hex::encode_upper(fname_ke);
                assert_eq!(fname.as_bytes(), data_file_name.as_os_str().as_encoded_bytes());

                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeReg)
                };
                inode.base = base;
                inode.data_file = fname_ke;
                inode.data_file_ke = data.get_cur_mode().into_key_entry();
                inode.len = mht::get_phy_nr_blk(data.length);
                nf_nb_change(&self.sb_meta, 0, inode.len as isize - *htree_org_len as isize)?;
            }
            InodeExt::RegInline(data) => {
                assert!(data.len() <= REG_INLINE_DATA_MAX);
                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeRegInline)
                };
                inode.base = base;
                inode.data[..data.len()].copy_from_slice(data);
            }
            InodeExt::Dir { data_file_name, htree_org_len, data } => {
                let fname_ke = iid_hash(self.iid)?;
                let fname = hex::encode_upper(fname_ke);
                assert_eq!(fname.as_bytes(), data_file_name.as_os_str().as_encoded_bytes());

                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeDir)
                };
                inode.base = base;
                inode.data_file = fname_ke;
                inode.data_file_ke = data.get_cur_mode().into_key_entry();
                inode.len = mht::get_phy_nr_blk(data.length);
                nf_nb_change(&self.sb_meta, 0, inode.len as isize - *htree_org_len as isize)?;
            }
            InodeExt::Lnk { lnk_name, data_file_name, name_file_ke } => {
                let fname_ke = iid_hash(self.iid)?;
                let fname = hex::encode_upper(fname_ke);
                assert_eq!(fname.as_bytes(), data_file_name.as_os_str().as_encoded_bytes());

                // check link name length
                let b = lnk_name.as_os_str().as_encoded_bytes();
                assert!(b.len() < LNK_NAME_MAX);

                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeLnk)
                };
                inode.base = base;
                inode.data_file = fname_ke;
                inode.name_file_ke = name_file_ke.clone();
                inode.len = 1;
            }
            InodeExt::LnkInline(lnk_name) => {
                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeLnkInline)
                };
                inode.base = base;
                let b = lnk_name.as_os_str().as_encoded_bytes();
                assert!(b.len() < LNK_INLINE_MAX);
                inode.name[..b.len()].copy_from_slice(b);
            }
        }
        Ok(ib)
    }

    pub fn destroy(mut self) -> FsResult<InodeBytes> {
        self.sync_data()?;
        self.sync_meta()
    }

    fn remove_fs_file(&self, fname: &Path) -> FsResult<()> {
        let mut p = self.fs_path.clone();
        p.push(fname);
        let nr_blk = io_try!(fs::metadata(&p)).len().div_ceil(BLK_SZ as u64);
        io_try!(fs::remove_file(p));
        nf_nb_change(&self.sb_meta, -1, -(nr_blk as isize))?;
        Ok(())
    }

    // return whether remove a data file and removed file blocks
    pub fn remove_data_file(self) -> FsResult<()> {
        let df_name = match &self.ext {
            InodeExt::Reg { data_file_name, .. } => data_file_name,
            InodeExt::Dir { data_file_name, .. } => data_file_name,
            InodeExt::Lnk { data_file_name, .. } => data_file_name,
            _ => return Ok(()),
        };
        self.remove_fs_file(&df_name)?;
        Ok(())
    }
}
