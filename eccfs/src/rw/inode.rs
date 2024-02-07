use crate::*;
use super::disk::*;
use core::mem::{size_of, size_of_val};
use crate::htree::*;
use super::*;
use alloc::string::String;
use core::slice;

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
            name: core::str::from_utf8(
                &value.name[..value.len as usize]
            ).unwrap().to_string(),
        }
    }
}

enum InodeExt {
    Reg {
        data_file_name: String,
        htree_org_len: u64, // in blocks
        data: RWHashTree,
    },
    RegInline(Vec<u8>),
    Dir {
        data_file_name: String,
        htree_org_len: u64, // in blocks
        data: RWHashTree,
    },
    LnkInline(String),
    Lnk {
        lnk_name: String,
        data_file_name: String,
        name_file_ke: KeyEntry,
        backend: Arc<dyn RWStorage>,
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
    atime: u32,
    ctime: u32,
    mtime: u32,
    size: usize, // with . and ..
    ext: InodeExt,
    encrypted: bool,
    key_gen: KeyGen,
    sb_meta: Arc<RwLock<(usize, usize)>>,
    device: Arc<dyn Device>,
}

pub fn iid_to_htree_logi_pos(iid: InodeID) -> usize {
    iid as usize * INODE_SZ
}

pub fn iid_hash(iid: InodeID) -> FsResult<Hash256> {
    sha3_256_any(
        unsafe {
            slice::from_raw_parts(
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
            slice::from_raw_parts(
                &iid as *const InodeID as *const u8,
                size_of::<InodeID>(),
            )
        },
        exp_hash
    )
}

impl Inode {
    pub fn new_from_raw(
        raw: &InodeBytes,
        iid: InodeID,
        encrypted: bool,
        sb_meta: Arc<RwLock<(usize, usize)>>,
        device: Arc<dyn Device>,
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
            atime: di_base.atime,
            ctime: di_base.ctime,
            mtime: di_base.mtime,
            size: di_base.size as usize,
            // just something to hold the place
            ext: InodeExt::LnkInline(String::new()),
            encrypted,
            #[cfg(not(feature = "std"))]
            key_gen: KeyGen::new(iid),
            #[cfg(feature = "std")]
            key_gen: KeyGen::new(),
            sb_meta,
            device: device.clone(),
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

                    let fname = hex::encode_upper(&di.data_file);
                    assert_eq!(fname.len(), DATA_FILE_NAME_LEN);

                    let back = device.open_rw_storage(&fname)?;
                    assert_eq!(back.get_len()?, blk2byte!(di.len));
                    assert_eq!(
                        mht::get_phy_nr_blk(di.base.size.div_ceil(BLK_SZ as u64)),
                        di.len
                    );
                    InodeExt::Reg {
                        data_file_name: fname.into(),
                        htree_org_len: di.len,
                        data: RWHashTree::new(
                            None,
                            back,
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

                let fname = hex::encode_upper(&di.data_file);
                assert_eq!(fname.len(), DATA_FILE_NAME_LEN);

                let back = device.open_rw_storage(&fname)?;
                assert_eq!(back.get_len()?, blk2byte!(di.len));
                assert_eq!(
                    mht::get_phy_nr_blk(di.base.size.div_ceil(BLK_SZ as u64)),
                    di.len
                );
                InodeExt::Dir {
                    data_file_name: fname.into(),
                    htree_org_len: di.len,
                    data: RWHashTree::new(
                        None,
                        back,
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
                    let lnk_name = core::str::from_utf8(
                        &di.name[..di.base.size as usize]
                    ).unwrap().to_string();
                    InodeExt::LnkInline(lnk_name)
                } else {
                    // single block file
                    let di = unsafe {
                        &*(raw.as_ptr() as *const DInodeLnk)
                    };
                    iid_hash_check(iid, &di.data_file)?;

                    // read data block
                    let fname = hex::encode_upper(&di.data_file);
                    assert_eq!(fname.len(), DATA_FILE_NAME_LEN);

                    let backend = device.open_rw_storage(&fname)?;
                    assert_eq!(backend.get_len()?, BLK_SZ as u64);
                    assert_eq!(di.len, 1);
                    let mut blk = backend.read_blk(0)?;
                    crypto_in(
                        &mut blk,
                        CryptoHint::from_key_entry(
                            di.name_file_ke.clone(),
                            encrypted,
                            LNK_DATA_FILE_BLK_POS,
                        )
                    )?;

                    let lnk_name = core::str::from_utf8(
                        &blk[..di.base.size as usize]
                    ).unwrap().to_string();
                    InodeExt::Lnk {
                        lnk_name,
                        data_file_name: fname.into(),
                        name_file_ke: di.name_file_ke.clone(),
                        backend,
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
        encrypted: bool,
        sb_meta: Arc<RwLock<(usize, usize)>>,
        device: Arc<dyn Device>,
        now: u32,
    ) -> FsResult<Self> {
        let mut inode = Self {
            iid,
            tp,
            perm,
            nlinks: 1,
            uid,
            gid,
            atime: now,
            ctime: now,
            mtime: now,
            size: 0,
            ext: InodeExt::LnkInline(String::new()),
            encrypted,
            #[cfg(not(feature = "std"))]
            key_gen: KeyGen::new(iid),
            #[cfg(feature = "std")]
            key_gen: KeyGen::new(),
            sb_meta,
            device,
        };
        inode.ext = match tp {
            FileType::Reg => InodeExt::RegInline(Vec::new()),
            FileType::Dir => {
                let (data_file_name, backend) = inode.new_storage()?;
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
                dotdot.name[..2].copy_from_slice("..".as_bytes());
                let mut dde = Vec::new();
                dde.push(dot);
                dde.push(dotdot);
                data.write_exact(0,
                    unsafe {
                        slice::from_raw_parts(
                            dde.as_ptr() as *const u8,
                            dde.len() * DIRENT_SZ,
                        )
                    }
                )?;
                inode.size = 2 * DIRENT_SZ;

                assert_eq!(mht::get_phy_nr_blk(data.logi_len), 2);
                nf_nb_change(&inode.sb_meta, 1, 2)?;

                InodeExt::Dir {
                    data_file_name,
                    htree_org_len: 2,
                    data,
                }
            }
            FileType::Lnk => InodeExt::LnkInline(String::new()),
        };

        Ok(inode)
    }

    fn new_storage(&self) -> FsResult<(String, Arc<dyn RWStorage>)> {
        let hash = iid_hash(self.iid)?;
        let fname = hex::encode_upper(hash);
        assert_eq!(fname.len(), DATA_FILE_NAME_LEN);

        let storage = self.device.create_rw_storage(&fname)?;
        Ok((fname, storage))
    }

    pub fn read_data(&mut self, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        if offset >= self.size {
            Err(new_error!(FsError::InvalidParameter))
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
                _ => Err(new_error!(FsError::PermissionDenied)),
            }
        }
    }

    pub fn write_data(&mut self, offset: usize, from: &[u8]) -> FsResult<usize> {
        let write_end = offset + from.len();
        self.possible_expand_to_htree(write_end)?;

        let ret = match &mut self.ext {
            InodeExt::Reg { data, .. } => {
                Ok(data.write_exact(offset, from)?)
            }
            InodeExt::RegInline(data) => {
                assert!(data.len() == self.size);
                data.resize(write_end, 0);
                data[offset..write_end].copy_from_slice(from);
                Ok(from.len())
            }
            _ => Err(new_error!(FsError::PermissionDenied)),
        };
        self.size = self.size.max(write_end);
        ret
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
                let (data_file_name, backend) = self.new_storage()?;
                let mut htree = RWHashTree::new(
                    None,
                    backend,
                    0,
                    None,
                    self.encrypted,
                );
                assert_eq!(htree.write_exact(0, data)?, data.len());

                nf_nb_change(&self.sb_meta, 1, mht::get_phy_nr_blk(htree.logi_len) as isize)?;

                (data_file_name, htree)
            }
            _ => return Err(new_error!(FsError::UnknownError)),
        };

        self.ext = InodeExt::Reg {
            data_file_name,
            htree_org_len: mht::get_phy_nr_blk(htree.logi_len),
            data: htree,
        };

        Ok(())
    }

    fn reg_shrink_to_inline(&mut self) -> FsResult<()> {
        let (d, file_to_remove) = match &mut self.ext {
            InodeExt::Reg { data_file_name, data, .. } =>{
                assert!(self.size <= REG_INLINE_DATA_MAX);

                let mut d = Vec::new();
                d.resize(self.size, 0u8);
                assert_eq!(data.read_exact(0, &mut d)?, self.size);

                (d, data_file_name.clone())
            }
            _ => return Err(new_error!(FsError::UnknownError)),
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
            _ => return Err(new_error!(FsError::PermissionDenied)),
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
            blocks: match self.tp {
                FileType::Reg | FileType::Dir => {
                    self.size.div_ceil(BLK_SZ) as u64
                }
                _ => 0,
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
            SetMetadata::Type(_) => return Err(new_error!(FsError::PermissionDenied)),
            SetMetadata::Permission(perm) => {
                self.perm = perm;
            }
            SetMetadata::Uid(uid) => self.uid = uid,
            SetMetadata::Gid(gid) => self.gid = gid,
        }
        Ok(())
    }

    pub fn get_link(&self) -> FsResult<String> {
        match &self.ext {
            InodeExt::LnkInline(lnk) => Ok(lnk.clone()),
            InodeExt::Lnk { lnk_name, .. } => Ok(lnk_name.clone()),
            _ => Err(new_error!(FsError::PermissionDenied)),
        }
    }

    pub fn set_link(&mut self, target: &str) -> FsResult<()> {
        match &mut self.ext {
            InodeExt::LnkInline(lnk) => *lnk = target.into(),
            InodeExt::Lnk { lnk_name, .. } => *lnk_name = target.into(),
            _ => return Err(new_error!(FsError::PermissionDenied)),
        }
        self.size = target.len();
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
                    // assert!(self.size / DIRENT_SZ >= offset);
                    if self.size / DIRENT_SZ < offset {
                        return Ok(Vec::new());
                    }
                    num.min(self.size / DIRENT_SZ - offset)
                };
                let mut de_list: Vec<DiskDirEntry> = Vec::with_capacity(num);
                unsafe {
                    de_list.set_len(num);
                }
                let len = num * DIRENT_SZ;
                let read = data.read_exact(
                    offset * DIRENT_SZ,
                    unsafe {
                        slice::from_raw_parts_mut(
                            de_list.as_mut_ptr() as *mut u8,
                            len,
                        )
                    }
                )?;
                assert_eq!(len, read);
                Ok(de_list.into_iter().map(
                    |de| de.into()
                ).collect())
            }
            _ => Err(new_error!(FsError::PermissionDenied)),
        }
    }

    pub fn find_child(&mut self, name: &str) -> FsResult<Option<InodeID>> {
        let mut done = 0;
        let nr_de = self.size / DIRENT_SZ;
        while done < nr_de {
            // try read a block of de
            let round = DIRENT_PER_BLK.min(nr_de - done);
            let des = self.read_child(done, round)?;
            let round = des.len();
            for de in des {
                if de.name.as_str() == name {
                    return Ok(Some(de.ipos));
                }
            }
            done += round;
        }
        Ok(None)
    }

    fn find_child_pos(&mut self, name: &str) -> FsResult<Option<(usize, DirEntry)>> {
        let mut done = 0;
        let nr_de = self.size / DIRENT_SZ;
        while done < nr_de {
            // try read a block of de
            let round = DIRENT_PER_BLK.min(nr_de - done);
            for (i, de) in self.read_child(done, round)?.into_iter().enumerate() {
                if de.name.as_str() == name {
                    return Ok(Some((done + i, de)));
                }
            }
            done += round;
        }
        Ok(None)
    }

    pub fn add_child(&mut self, name: &str, tp: FileType, iid: InodeID) -> FsResult<()> {
        if self.find_child(name)?.is_some() {
            return Err(new_error!(FsError::AlreadyExists));
        }

        match &mut self.ext {
            InodeExt::Dir { data, .. } => {
                let dde: DiskDirEntry = DirEntry {
                    ipos: iid,
                    tp: tp.into(),
                    name: name.to_string(),
                }.into();
                let written = data.write_exact(self.size, dde.as_ref())?;
                assert_eq!(written, size_of_val(&dde));
                self.size += DIRENT_SZ;
                Ok(())
            }
            _ => Err(new_error!(FsError::PermissionDenied)),
        }
    }

    pub fn rename_child(&mut self, name: &str, newname: &str) -> FsResult<()> {
        if self.find_child(newname)?.is_some() {
            return Err(new_error!(FsError::AlreadyExists));
        }

        if let Some((pos, mut de)) = self.find_child_pos(name)? {
            match &mut self.ext {
                InodeExt::Dir { data, .. } => {
                    de.name = newname.to_string();
                    let dde: DiskDirEntry = de.into();
                    let written = data.write_exact(pos * DIRENT_SZ, dde.as_ref())?;
                    assert_eq!(written, DIRENT_SZ);
                    Ok(())
                }
                _ => Err(new_error!(FsError::PermissionDenied)),
            }
        } else {
            Err(new_error!(FsError::NotFound))
        }
    }

    pub fn remove_child(&mut self, name: &str) -> FsResult<(InodeID, FileType)> {
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
                // resize htree
                data.resize(self.size.div_ceil(BLK_SZ) as u64)?;

                // debug!("iid {} remove child left size {}", self.iid, self.size / DIRENT_SZ);
                Ok((de.ipos, de.tp))
            } else {
                Err(new_error!(FsError::PermissionDenied))
            }
        } else {
            Err(FsError::NotFound)
        }
    }

    pub fn fallocate(
        &mut self, mode: FallocateMode, offset: usize, len: usize,
    ) -> FsResult<()> {
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
                _ => return Err(new_error!(FsError::PermissionDenied)),
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
                _ => return Err(new_error!(FsError::PermissionDenied)),
            }
        }
        self.size = self.size.max(end);
        Ok(())
    }

    fn write_lnk_file(
        store: &Arc<dyn RWStorage>,
        lnk_name: &str,
        encrypted: Option<Key128>,
    ) -> FsResult<FSMode> {
        store.set_len(1)?;

        let mut blk = [0u8; BLK_SZ];
        blk[..lnk_name.len()].copy_from_slice(lnk_name.as_bytes());

        let mode = crypto_out(
            &mut blk,
            encrypted,
            0,
        )?;
        store.write_blk(0, &blk)?;

        Ok(mode)
    }

    fn reg_force_shape(&mut self) ->FsResult<()> {
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
        Ok(())
    }

    // return file changes,  block changes
    pub fn sync_data(&mut self) -> FsResult<()> {
        self.reg_force_shape()?;

        let mut file_to_remove = None;
        match &mut self.ext {
            InodeExt::Reg { data, .. } | InodeExt::Dir { data, .. } => {
                data.flush()?.into_key_entry();
            }
            InodeExt::Lnk { lnk_name, data_file_name, name_file_ke, backend } => {
                if lnk_name.len() <= LNK_INLINE_MAX {
                    file_to_remove = Some(data_file_name.clone());
                    self.ext = InodeExt::LnkInline(lnk_name.clone());
                } else {
                    *name_file_ke = Self::write_lnk_file(
                        backend,
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
                // shape to single block storage file
                if lnk_name.len() > LNK_INLINE_MAX {
                    let lnk = lnk_name.clone();
                    let (data_file_name, mut backend) = self.new_storage()?;
                    let name_file_ke = Self::write_lnk_file(
                        &mut backend,
                        &lnk,
                        if self.encrypted {
                            Some(self.key_gen.gen_key(0)?)
                        } else {
                            None
                        },
                    )?.into_key_entry();

                    self.ext = InodeExt::Lnk {
                        lnk_name: lnk,
                        data_file_name,
                        name_file_ke,
                        backend,
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
        self.reg_force_shape()?;

        let base = DInodeBase {
            mode: get_mode(self.tp, &self.perm),
            nlinks: self.nlinks,
            uid: self.uid,
            gid: self.gid,
            atime: self.atime,
            ctime: self.ctime,
            mtime: self.mtime,
            size: self.size as u64,
        };
        let mut ib = [0u8; INODE_SZ];
        match &mut self.ext {
            InodeExt::Reg { data_file_name, htree_org_len, data } => {
                let fname_ke = iid_hash(self.iid)?;
                let fname = hex::encode_upper(fname_ke);
                assert_eq!(fname.as_bytes(), data_file_name.as_bytes());

                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeReg)
                };
                inode.base = base;
                inode.data_file = fname_ke;
                inode.data_file_ke = data.get_cur_mode().into_key_entry();
                inode.len = mht::get_phy_nr_blk(data.logi_len);
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
                assert_eq!(fname.as_bytes(), data_file_name.as_bytes());

                let inode = unsafe {
                    &mut *(ib.as_mut_ptr() as *mut DInodeDir)
                };
                inode.base = base;
                inode.data_file = fname_ke;
                inode.data_file_ke = data.get_cur_mode().into_key_entry();
                inode.len = mht::get_phy_nr_blk(data.logi_len);
                nf_nb_change(&self.sb_meta, 0, inode.len as isize - *htree_org_len as isize)?;
            }
            InodeExt::Lnk { lnk_name, data_file_name, name_file_ke, .. } => {
                let fname_ke = iid_hash(self.iid)?;
                let fname = hex::encode_upper(fname_ke);
                assert_eq!(fname.as_bytes(), data_file_name.as_bytes());

                // check link name length
                assert!(lnk_name.len() < LNK_NAME_MAX);

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
                assert!(lnk_name.len() < LNK_INLINE_MAX);
                inode.name[..lnk_name.len()].copy_from_slice(lnk_name.as_bytes());
            }
        }
        Ok(ib)
    }

    pub fn destroy(mut self) -> FsResult<InodeBytes> {
        // debug!("destroy inode {}", self.iid);
        self.sync_data()?;
        self.sync_meta()
    }

    fn remove_fs_file(&self, fname: &str) -> FsResult<()> {
        let nr_blk = self.device.get_storage_len(&fname)?.div_ceil(BLK_SZ as u64);
        self.device.remove_storage(&fname)?;

        nf_nb_change(&self.sb_meta, -1, -(nr_blk as isize))?;
        Ok(())
    }

    // called when an inode is flushed
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
