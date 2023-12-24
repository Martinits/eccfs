pub mod superblock;
pub mod inode;
pub mod disk;
pub mod builder;

use crate::vfs::*;
use std::sync::{Arc, RwLock, Mutex};
use std::path::Path;
use crate::*;
use std::ffi::OsStr;
use superblock::*;
use crate::htree::*;
use inode::*;
use crate::bcache::*;
use crate::storage::*;
use crate::lru::*;
use disk::*;
use std::mem::size_of;
use crate::crypto::half_md4;


pub const ROFS_MAGIC: u64 = 0x00454343524F4653; // ECCROFS
pub const NAME_MAX: u64 = u16::MAX as u64;

pub struct ROFS {
    mode: FSMode,
    cache_data: bool,
    backend: ROCache,
    sb: RwLock<SuperBlock>,
    inode_tbl: ROHashTree,
    dirent_tbl: ROHashTree,
    path_tbl: ROHashTree,
    icac: Option<Mutex<ChannelLru<InodeID, Inode>>>,
    de_cac: Option<Mutex<ChannelLru<String, InodeID>>>,
}

impl ROFS {
    pub fn new(
        path: &Path,
        mode: FSMode,
        cache_data: Option<usize>,
        cache_inode: Option<usize>,
        cache_de: Option<usize>,
    ) -> FsResult<Self> {
        let mut storage = FileStorage::new(path, false)?;

        // read superblock
        let sb_blk = storage.read_blk(SUPERBLOCK_POS)?;
        let sb = SuperBlock::new(mode.clone(), sb_blk)?;

        // start cache channel server
        let cac = ROCache::new(
            Box::new(storage),
            cache_data.unwrap_or(DEFAULT_CACHE_CAP)
        );

        // get hash trees
        let inode_tbl = ROHashTree::new(
            cac.clone(),
            sb.inode_tbl_start,
            sb.inode_tbl_len,
            FSMode::from_key_entry(sb.inode_tbl_key, mode.is_encrypted()),
            cache_data.is_some(),
        );
        let dirent_tbl = ROHashTree::new(
            cac.clone(),
            sb.dirent_tbl_start,
            sb.dirent_tbl_len,
            FSMode::from_key_entry(sb.dirent_tbl_key, mode.is_encrypted()),
            cache_data.is_some(),
        );
        let path_tbl = ROHashTree::new(
            cac.clone(),
            sb.path_tbl_start,
            sb.path_tbl_len,
            FSMode::from_key_entry(sb.path_tbl_key, mode.is_encrypted()),
            cache_data.is_some(),
        );

        Ok(ROFS {
            mode,
            sb: RwLock::new(sb),
            backend: cac.clone(),
            cache_data: cache_data.is_some(),
            inode_tbl,
            dirent_tbl,
            path_tbl,
            icac: if let Some(cap) = cache_inode {
                Some(Mutex::new(ChannelLru::new(cap)))
            } else {
                None
            },
            de_cac: if let Some(cap) = cache_de {
                Some(Mutex::new(ChannelLru::new(cap)))
            } else {
                None
            },
        })
    }

    fn fetch_inode(&self, iid: InodeID) -> FsResult<Inode> {
        let (bpos, offset) = pos64_split(iid);
        assert!(offset as usize % INODE_ALIGN == 0);

        // try read dinode_base to get inode type
        let mut raw = vec![0u8; size_of::<DInodeBase>()];
        let start = bpos as usize * BLK_SZ + offset as usize;
        if self.inode_tbl.read_exact(start, &mut raw)? != raw.len() {
            return Err(FsError::UnexpectedEof);
        }
        let di_base = unsafe {
            &*(raw.as_ptr() as *const DInodeBase)
        };
        let itp = get_ftype_from_mode(di_base.mode);

        // determine inode size from type
        let inode_size = match itp {
            FileType::Reg => size_of::<DInodeReg>(),
            FileType::Dir => {
                raw.resize(size_of::<DInodeDirBase>(), 0);
                if self.inode_tbl.read_exact(start, &mut raw)? != raw.len() {
                    return Err(FsError::UnexpectedEof);
                }
                let di_dir_base = unsafe {
                    &*(raw.as_ptr() as *const DInodeDirBase)
                };
                size_of::<DInodeDirBase>()
                    + di_dir_base.nr_idx as usize * size_of::<EntryIndex>()
            }
            FileType::Lnk => size_of::<DInodeLnk>(),
        };
        assert!(inode_size % INODE_ALIGN == 0);

        // read whole inode
        raw.resize(inode_size, 0);
        if self.inode_tbl.read_exact(start, &mut raw)? != raw.len() {
            return Err(FsError::UnexpectedEof);
        }

        Inode::new_from_raw(
            &raw,
            iid,
            itp,
            self.backend.clone(),
            self.mode.is_encrypted(),
            self.cache_data,
        )
    }

    fn get_inode(&self, iid: InodeID) -> FsResult<Arc<Inode>> {
        if let Some(mu_icac) = &self.icac {
            let mut icac = mutex_lock!(mu_icac);
            if let Some(ainode) = icac.get(iid)? {
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
            let mut buf = vec![0u8; *len as usize];

            let read = self.path_tbl.read_exact(pos as usize, buf.as_mut_slice())?;
            if read != *len as usize {
                return Err(FsError::InvalidData)
            }
            String::from_utf8(buf).map_err(|_| FsError::InvalidData)?
        } else {
            std::str::from_utf8(
                name.split_at(*len as usize).0
            ).map_err(
                |_| FsError::InvalidData
            )?.into()
        };
        Ok(name)
    }
}

impl FileSystem for ROFS {
    fn finfo(&self) -> FsResult<FsInfo> {
        rwlock_read!(self.sb).get_fsinfo()
    }

    fn fsync(&mut self) -> FsResult<()> {
        if let Some(ref icac) = self.icac {
            mutex_lock!(icac).flush_all(false)?;
        }

        if let Some(ref de_cac) = self.de_cac {
            mutex_lock!(de_cac).flush_all(false)?;
        }

        self.backend.flush()?;

        Ok(())
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
                let mut buf = vec![0u8; len];
                let read = self.path_tbl.read_exact(pos as usize, buf.as_mut_slice())?;
                if read != len {
                    Err(FsError::IncompatibleMetadata)
                } else {
                    Ok(String::from_utf8(buf).map_err(|_| FsError::InvalidData)?)
                }
            }
        }
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        if let Some(ref icac) = self.icac {
            mutex_lock!(icac).flush_key(iid)?;
        }

        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        // Currently we don't use de_cac
        // because in order to maintain a map from inode full_path to inodeid,
        // we need to store full path in struct Inode.
        // But we cannot know an inode's full path when get_inode,
        // unless a complete map from inodeid to name is maintained in memory,
        // which is too large to stick to memory.
        // This only influences SGX deployments, not FUSE,
        // because FUSE leverages kernel's dir entry cache.
        if let Some((de_list_start, gstart, glen)) = self.get_inode(iid)?.lookup_index(name)? {
            let hash = half_md4(name.as_encoded_bytes())?;

            let step = size_of::<DirEntry>();
            let (mut pos, mut off) = pos64_add(
                pos64_split(de_list_start),
                (gstart * step) as u64
            );

            let mut done = 0;
            while done < glen {
                let ablk = self.dirent_tbl.get_blk(pos)?;
                let round = (glen - done).min((BLK_SZ - off as usize) / step);
                let ents = unsafe {
                    std::slice::from_raw_parts(
                        ablk[off as usize..].as_ptr() as *const DirEntry, round)
                };
                for ent in ents.iter().filter(
                    |ent| ent.hash == hash
                ) {
                    let real_name = self.get_dir_ent_name(ent)?;
                    if real_name.as_str() == name {
                        return Ok(Some(ent.ipos))
                    }
                }
                done += round;
                (pos, off) = pos64_add((pos, off as u16), (step * round) as u64);
            }
        }
        Ok(None)
    }

    fn listdir(&self, iid: InodeID) -> FsResult<Vec<(InodeID, String, FileType)>> {
        let (de_start, num) = self.get_inode(iid)?.get_entry_list_info()?;
        let (pos, off) = pos64_split(de_start);

        let mut list = vec![DirEntry::default(); num];
        let to = unsafe {
            std::slice::from_raw_parts_mut(
                list.as_mut_ptr() as *mut u8,
                num * size_of::<DirEntry>(),
            )
        };
        let read = self.dirent_tbl.read_exact(pos as usize * BLK_SZ + off as usize, to)?;

        if read != num * size_of::<DirEntry>() {
            Err(FsError::InvalidData)
        } else {
            let mut ret = Vec::with_capacity(num);
            for ent in list.into_iter() {
                let name = self.get_dir_ent_name(&ent)?;

                ret.push((ent.ipos, name, FileType::from(ent.tp)));
            }
            Ok(ret)
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
