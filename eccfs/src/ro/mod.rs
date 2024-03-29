pub mod superblock;
pub mod inode;
pub mod disk;

use crate::vfs::*;
use spin::{RwLock, Mutex};
use crate::*;
use superblock::*;
use crate::htree::*;
use inode::*;
use crate::bcache::*;
use crate::storage::*;
use crate::lru::*;
use disk::*;
use core::mem::size_of;
use core::slice;
use crate::crypto::half_md4;
use alloc::vec::Vec;
use alloc::string::String;
use alloc::sync::Arc;
use alloc::string::ToString;


pub const ROFS_MAGIC: u64 = 0x00454343524F4653; // ECCROFS
pub const NAME_MAX: u64 = u16::MAX as u64;

pub struct ROFS {
    mode: FSMode,
    cache_data: bool,
    backend: Arc<Mutex<ROCache>>,
    sb: RwLock<SuperBlock>,
    inode_tbl: ROHashTree,
    dirent_tbl: Option<ROHashTree>,
    path_tbl: Option<ROHashTree>,
    icac: Option<Mutex<Lru<InodeID, Inode>>>,
    de_cac: Option<Mutex<Lru<String, InodeID>>>,
}

#[cfg(feature = "channel_lru")]
impl Drop for ROFS {
    fn drop(&mut self) {
        self.backend.abort().unwrap();
        if let Some(mu_icac) = &self.icac {
            mu_icac.lock().unwrap().abort().unwrap();
        }
        if let Some(mu_decac) = &self.de_cac {
            mu_decac.lock().unwrap().abort().unwrap();
        }
    }
}

pub const DEFAULT_ICAC_CAP: usize = 32;

impl ROFS {
    pub fn new(
        mode: FSMode,
        cache_data: usize,
        cache_inode: Option<usize>,
        cache_de: usize,
        storage: Arc<dyn ROStorage>
    ) -> FsResult<Self> {
        // read superblock
        let mut sb_blk = storage.read_blk(SUPERBLOCK_POS)?;
        // check crypto
        crypto_in(&mut sb_blk, CryptoHint::from_fsmode(mode.clone(), SUPERBLOCK_POS))?;
        let sb = SuperBlock::new(sb_blk)?;

        // start cache channel server
        let cac = ROCache::new(
            storage,
            if cache_data == 0 {
                DEFAULT_CACHE_CAP
            } else {
                cache_data
            }
        );
        let alock_cac = Arc::new(Mutex::new(cac));

        // get hash trees
        assert!(sb.inode_tbl_len != 0);
        let inode_tbl = ROHashTree::new(
            alock_cac.clone(),
            sb.inode_tbl_start,
            sb.inode_tbl_len,
            FSMode::from_key_entry(sb.inode_tbl_key, mode.is_encrypted()),
            cache_data != 0,
        );
        let dirent_tbl = if sb.dirent_tbl_len != 0 {
            Some(ROHashTree::new(
                alock_cac.clone(),
                sb.dirent_tbl_start,
                sb.dirent_tbl_len,
                FSMode::from_key_entry(sb.dirent_tbl_key, mode.is_encrypted()),
                cache_data != 0,
            ))
        } else {
            None
        };
        let path_tbl = if sb.path_tbl_len != 0 {
            Some(ROHashTree::new(
                alock_cac.clone(),
                sb.path_tbl_start,
                sb.path_tbl_len,
                FSMode::from_key_entry(sb.path_tbl_key, mode.is_encrypted()),
                cache_data != 0,
            ))
        } else {
            None
        };

        let icac = cache_inode.map(
            |sz| {
                Mutex::new(Lru::new( if sz == 0 { DEFAULT_ICAC_CAP } else { sz }))
            }
        );

        Ok(ROFS {
            mode,
            sb: RwLock::new(sb),
            backend: alock_cac.clone(),
            cache_data: cache_data != 0,
            inode_tbl,
            dirent_tbl,
            path_tbl,
            icac,
            de_cac: if cache_de != 0 {
                Some(Mutex::new(Lru::new(cache_de)))
            } else {
                None
            },
        })
    }

    fn fetch_inode(&self, iid: InodeID) -> FsResult<Inode> {
        let (bpos, offset) = pos64_split(iid);
        assert!(offset as usize % INODE_ALIGN == 0);

        // try read dinode_base to get inode type
        let mut raw = Vec::new();
        raw.resize(size_of::<DInodeBase>(), 0u8);
        let start = pos64_to_byte(bpos, offset) as usize;
        if self.inode_tbl.read_exact(start, &mut raw)? != raw.len() {
            return Err(new_error!(FsError::UnexpectedEof));
        }
        let di_base = unsafe {
            &*(raw.as_ptr() as *const DInodeBase)
        };
        let itp = get_ftype_from_mode(di_base.mode);

        // determine inode size from type
        let inode_size = match itp {
            FileType::Reg => {
                if di_base.size <= DI_REG_INLINE_DATA_MAX {
                    // inline file data
                    size_of::<DInodeBase>()
                        + (di_base.size as usize).next_multiple_of(INODE_ALIGN)
                } else {
                    size_of::<DInodeReg>()
                }
            },
            FileType::Dir => {
                if di_base.size <= DE_INLINE_MAX {
                    size_of::<DInodeBase>()
                        + (di_base.size as usize + 2) * size_of::<DirEntry>()
                } else {
                    raw.resize(size_of::<DInodeDirBaseNoInline>(), 0);
                    if self.inode_tbl.read_exact(start, &mut raw)? != raw.len() {
                        return Err(new_error!(FsError::UnexpectedEof));
                    }
                    let di_dir_base = unsafe {
                        &*(raw.as_ptr() as *const DInodeDirBaseNoInline)
                    };
                    size_of::<DInodeDirBaseNoInline>()
                        + di_dir_base.nr_idx as usize * size_of::<EntryIndex>()
                }
            }
            FileType::Lnk => size_of::<DInodeLnk>(),
        };
        assert!(inode_size % INODE_ALIGN == 0);

        // read whole inode
        raw.resize(inode_size, 0);
        if self.inode_tbl.read_exact(start, &mut raw)? != raw.len() {
            return Err(new_error!(FsError::UnexpectedEof));
        }

        Inode::new_from_raw(
            &raw,
            iid,
            itp,
            self.backend.clone(),
            self.sb.read().file_sec_start,
            self.sb.read().file_sec_len,
            self.mode.is_encrypted(),
            self.cache_data,
        )
    }

    fn get_inode(&self, iid: InodeID) -> FsResult<Arc<Inode>> {
        if let Some(mu_icac) = &self.icac {
            let mut icac = mu_icac.lock();
            if let Some(ainode) = icac.get(&iid)? {
                Ok(ainode)
            } else {
                // cache miss
                let ainode = Arc::new(self.fetch_inode(iid)?);
                icac.insert_and_get(iid, &ainode)?;
                Ok(ainode)
            }
        } else {
            // no icac
            let inode = self.fetch_inode(iid)?;
            Ok(Arc::new(inode))
        }
    }

    fn get_dir_ent_name(&self, de: &DirEntry) -> FsResult<String> {
        let DirEntry {len, name, ..} = de;
        let name = if *len as usize > name.len() {
            let pos = u64::from_le_bytes(name[..8].try_into().unwrap());
            let mut buf = Vec::new();
            buf.resize((*len) as usize, 0u8);

            let read = self.path_tbl.as_ref().unwrap()
                .read_exact(pos as usize, buf.as_mut_slice())?;
            if read != *len as usize {
                return Err(new_error!(FsError::InvalidData))
            }
            String::from_utf8(buf).map_err(|_| new_error!(FsError::InvalidData))?
        } else {
            core::str::from_utf8(
                name.split_at(*len as usize).0
            ).unwrap().to_string()
        };
        Ok(name.into())
    }

    fn find_de_in_list(
        &self,
        de_list: &[DirEntry],
        hash: u64,
        name: &str
    ) -> FsResult<Option<InodeID>> {
        for de in de_list.iter().filter(
            |de| de.hash == hash
        ) {
            let real_name = self.get_dir_ent_name(de)?;
            if real_name == name {
                return Ok(Some(de.ipos))
            }
        }
        Ok(None)
    }
}

impl FileSystem for ROFS {
    fn finfo(&self) -> FsResult<FsInfo> {
        self.sb.read().get_fsinfo()
    }

    fn fsync(&self) -> FsResult<FSMode> {
        if let Some(ref icac) = self.icac {
            assert_eq!(icac.lock().flush_wb()?.len(), 0);
        }

        if let Some(ref de_cac) = self.de_cac {
            assert_eq!(de_cac.lock().flush_wb()?.len(), 0);
        }

        self.backend.lock().flush()?;

        Ok(self.mode.clone())
    }

    fn iread(&self, iid: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        self.get_inode(iid)?.read_data(offset, to)
    }

    fn get_meta(&self, iid: InodeID) -> FsResult<Metadata> {
        self.get_inode(iid)?.get_meta()
    }

    fn iread_link(&self, iid: InodeID) -> FsResult<String> {
        match self.get_inode(iid)?.get_link()? {
            LnkName::Short(s) => Ok(s),
            LnkName::Long(pos, len) => {
                let mut buf = Vec::new();
                buf.resize(len, 0u8);
                let read = self.path_tbl.as_ref().unwrap()
                            .read_exact(pos as usize, buf.as_mut_slice())?;
                if read != len {
                    Err(new_error!(FsError::IncompatibleMetadata))
                } else {
                    let s = String::from_utf8(buf).map_err(|_| new_error!(FsError::InvalidData))?;
                    Ok(s.into())
                }
            }
        }
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        if let Some(ref icac) = self.icac {
            icac.lock().try_pop_key(&iid, false)?;
        }

        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &str) -> FsResult<Option<InodeID>> {
        // Currently we don't use de_cac
        // because in order to maintain a map from inode full_path to inodeid,
        // we need to store full path in struct Inode.
        // But we cannot know an inode's full path when get_inode,
        // unless a complete map from inodeid to name is maintained in memory,
        // which is too large to stick to memory.
        // This only influences SGX deployments, not FUSE,
        // because FUSE leverages kernel's dir entry cache.

        let hash = half_md4(name.as_bytes())?;
        match self.get_inode(iid)?.lookup_index(name)? {
            LookUpInfo::External(gstart, glen) => {
                let step = size_of::<DirEntry>();
                let mut pos = gstart / BLK_SZ as u64;
                let mut off = (gstart % BLK_SZ as u64) as u16;

                let mut done = 0;
                while done < glen {
                    let ablk = self.dirent_tbl.as_ref().unwrap().get_blk(pos)?;
                    let round = (glen - done).min((BLK_SZ - off as usize) / step);
                    let de_list = unsafe {
                        slice::from_raw_parts(
                            ablk[off as usize..].as_ptr() as *const DirEntry, round)
                    };
                    if let Some(iid) = self.find_de_in_list(de_list, hash, name)? {
                        return Ok(Some(iid));
                    }
                    done += round;
                    (pos, off) = pos64_add((pos, off), (step * round) as u64);
                }
                Ok(None)
            }
            LookUpInfo::Inline(de_list) => {
                Ok(self.find_de_in_list(de_list, hash, name)?)
            }
            LookUpInfo::NonExistent => Ok(None),
        }
    }

    fn listdir(
        &self, iid: InodeID, offset: usize, num: usize,
    ) -> FsResult<Vec<(InodeID, String, FileType)>> {
        match self.get_inode(iid)?.get_entry_list_info(offset, num)? {
            Some(DirEntryInfo::External(de_start, num)) => {
                let mut de_list = Vec::new();
                de_list.resize(num, DirEntry::default());
                let to = unsafe {
                    slice::from_raw_parts_mut(
                        de_list.as_mut_ptr() as *mut u8,
                        num * size_of::<DirEntry>(),
                    )
                };
                let read = self.dirent_tbl.as_ref().unwrap()
                            .read_exact(de_start as usize, to)?;

                if read != num * size_of::<DirEntry>() {
                    Err(new_error!(FsError::InvalidData))
                } else {
                    let mut ret = Vec::with_capacity(num);
                    for de in de_list.into_iter() {
                        let name = self.get_dir_ent_name(&de)?;

                        ret.push((de.ipos, name, FileType::from(de.tp)));
                    }
                    Ok(ret)
                }
            }
            Some(DirEntryInfo::Inline(de_list)) => {
                let mut ret = Vec::with_capacity(de_list.len());
                for de in de_list {
                    let name = self.get_dir_ent_name(de)?;
                    ret.push((de.ipos, name, FileType::from(de.tp)));
                }
                Ok(ret)
            }
            None => Ok(Vec::new())
        }
    }
}

pub fn pos64_split(pos: u64) -> (u64, u16) {
    (pos & 0x0ffffffffffff, (pos >> 48) as u16)
}

pub fn pos64_join(pos: u64, off: u16) -> u64 {
    pos | ((off as u64) << 48)
}

pub fn pos64_add((pos, off): (u64, u16), add: u64) -> (u64, u16) {
    let newoff = off as u64 + add;
    (pos + newoff / BLK_SZ as u64, (newoff % BLK_SZ as u64) as u16)
}

pub fn pos64_to_byte(pos: u64, off: u16) -> u64 {
    blk2byte!(pos) + off as u64
}
