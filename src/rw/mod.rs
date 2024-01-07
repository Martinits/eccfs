pub mod superblock;
pub mod inode;
pub mod disk;
pub mod builder;
pub mod bitmap;

use crate::vfs::*;
use std::sync::{Arc, RwLock, Mutex};
use std::path::{Path, PathBuf};
use crate::*;
use std::ffi::OsStr;
use superblock::*;
use crate::htree::*;
use inode::*;
use crate::storage::*;
use crate::lru::*;
use disk::*;
use std::mem::size_of;
use crate::crypto::half_md4;
use bitmap::*;
use std::fs;


pub const RWFS_MAGIC: u64 = 0x0045434352574653; // ECCRWFS
pub const NAME_MAX: u64 = u16::MAX as u64;
pub const SB_FILE_NAME: &str = "meta";

pub const RW_CACHE_CAP_DEFAULT_ITBL: usize = 4;

pub struct RWFS {
    regen_root_key: bool,
    path: PathBuf,
    mode: FSMode,
    sb: RwLock<SuperBlock>,
    ibitmap: Mutex<BitMap>,
    inode_tbl: Mutex<RWHashTree>,
    icac: Mutex<ChannelLru<InodeID, RwLock<Inode>>>,
    de_cac: Option<Mutex<ChannelLru<String, InodeID>>>,
    key_gen: KeyGen,
}

impl RWFS {
    pub fn new(
        regen_root_key: bool,
        path: &Path, // must be a dir
        mode: FSMode,
        icache_cap_hint: Option<usize>,
        cache_de: usize,
    ) -> FsResult<Self> {
        assert!(io_try!(fs::metadata(path)).is_dir());
        let mut pb = path.to_path_buf();
        pb.push(SB_FILE_NAME);

        let mut sb_file = FileStorage::new(&pb, true)?;

        // read superblock
        let mut sb_blk = sb_file.read_blk(SUPERBLOCK_POS)?;
        // check crypto
        match &mode {
            FSMode::Encrypted(key, mac) => {
                aes_gcm_128_blk_dec(&mut sb_blk, key, mac, SUPERBLOCK_POS)?;
            }
            FSMode::IntegrityOnly(hash) => {
                sha3_256_blk_check(&sb_blk, hash)?;
            }
        }
        let sb = SuperBlock::new(sb_blk)?;

        // read ibitmap
        if sb.ibitmap_len == 0 {
            // no possibilty that ibitmap is empty
            return Err(FsError::SuperBlockCheckFailed);
        }
        let mut ibitmap_blks = Vec::with_capacity(sb.ibitmap_len as usize);
        for (i, (blk, ke)) in ibitmap_blks.iter_mut().zip(sb.ibitmap_ke.iter()).enumerate() {
            let pos = i as u64 + sb.ibitmap_start;
            sb_file.read_blk_to(pos, blk)?;
            if mode.is_encrypted() {
                let key = ke[0..size_of::<Key128>()].try_into().unwrap();
                let mac = ke[size_of::<Key128>()..].try_into().unwrap();
                aes_gcm_128_blk_dec(blk, key, mac, pos)?;
            } else {
                sha3_256_blk_check(blk, ke)?;
            }
        }
        let ibitmap = BitMap::new(ibitmap_blks)?;

        // read itbl
        if sb.itbl_len == 0 {
            // no possibilty that itbl is empty
            return Err(FsError::SuperBlockCheckFailed);
        }
        let itbl_file_name = hex::encode_upper(&sb.itbl_name);
        assert_eq!(itbl_file_name.len(), 2 * size_of::<Hash256>());
        let itbl_storage = FileStorage::new(Path::new(&itbl_file_name), true)?;
        let inode_tbl = RWHashTree::new(
            Some(RW_CACHE_CAP_DEFAULT_ITBL),
            Box::new(itbl_storage),
            sb.itbl_len,
            Some(FSMode::from_key_entry(sb.itbl_ke, mode.is_encrypted())),
            mode.is_encrypted(),
        );

        Ok(RWFS {
            regen_root_key,
            path: path.to_path_buf(),
            mode,
            sb: RwLock::new(sb),
            ibitmap: Mutex::new(ibitmap),
            inode_tbl: Mutex::new(inode_tbl),
            icac: Mutex::new(ChannelLru::new(
                icache_cap_hint.unwrap_or(DEFAULT_CACHE_CAP)
            )),
            de_cac: if cache_de != 0 {
                Some(Mutex::new(ChannelLru::new(cache_de)))
            } else {
                None
            },
            key_gen: KeyGen::new(),
        })
    }

    fn fetch_inode(&self, iid: InodeID) -> FsResult<Inode> {
        let mut ib = [0u8; INODE_SZ];
        let read = mutex_lock!(&self.inode_tbl).read_exact(
            iid_to_htree_logi_pos(iid), &mut ib,
        )?;
        assert_eq!(read, INODE_SZ);
        Inode::new_from_raw(&ib, iid)
    }

    fn get_inode(&self, iid: InodeID, dirty: bool) -> FsResult<Arc<RwLock<Inode>>> {
        let mut icac = mutex_lock!(&self.icac);
        let ainode = if let Some(ainode) = icac.get(iid)? {
            ainode
        } else {
            // cache miss
            let ainode = Arc::new(RwLock::new(self.fetch_inode(iid)?));
            icac.insert_and_get(iid, &ainode)?;
            ainode
        };
        if dirty {
            icac.mark_dirty(iid)?;
        }
        Ok(ainode)
    }
}

impl FileSystem for RWFS {
    fn destroy(&mut self) -> FsResult<FSMode> {
        // sync data and meta
        self.fsync()?;

        let mut pb = self.path.clone();
        pb.push(SB_FILE_NAME);
        let mut sb_file = FileStorage::new(&pb, true)?;

        // write bitmap
        let mut ibitmap_blks = mutex_lock!(self.ibitmap).write()?;
        let mut ibitmap_ke = Vec::with_capacity(ibitmap_blks.len());
        sb_file.expand_len(1 + ibitmap_blks.len() as u64)?;
        for (i, blk) in ibitmap_blks.iter_mut().enumerate() {
            let pos = i as u64 + rwlock_read!(self.sb).ibitmap_start;
            let ke = if self.mode.is_encrypted() {
                let key = self.key_gen.gen_key(pos)?;
                let mac = aes_gcm_128_blk_enc(blk, &key, pos)?;
                FSMode::Encrypted(key, mac)
            } else {
                let hash = sha3_256_blk(blk)?;
                FSMode::IntegrityOnly(hash)
            }.into_key_entry();
            ibitmap_ke.push(ke);
            sb_file.write_blk(pos, blk)?;
        }
        {
            let mut lock = rwlock_write!(self.sb);
            lock.ibitmap_len = ibitmap_blks.len() as u64;
            lock.ibitmap_ke = ibitmap_ke;
        }

        // write superblock
        let mut sb_blk = rwlock_read!(self.sb).write()?;
        let mode = if self.mode.is_encrypted() {
            let key = if self.regen_root_key {
                self.key_gen.gen_key(SUPERBLOCK_POS)?
            } else {
                self.mode.get_key().unwrap()
            };
            let mac = aes_gcm_128_blk_enc(&mut sb_blk, &key, SUPERBLOCK_POS)?;
            FSMode::Encrypted(key, mac)
        } else {
            let hash = sha3_256_blk(&sb_blk)?;
            FSMode::IntegrityOnly(hash)
        };
        sb_file.write_blk(SUPERBLOCK_POS, &sb_blk)?;

        Ok(mode)
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        rwlock_read!(self.sb).get_fsinfo()
    }

    fn fsync(&mut self) -> FsResult<()> {
        if let Some(inode) = mutex_lock!(&self.icac).flush_all(true)? {
            for (iid, i) in inode {
                let inode = i.into_inner().unwrap();
                let ib = inode.destroy()?;
                mutex_lock!(self.inode_tbl).write_exact(
                    iid_to_htree_logi_pos(iid), &ib
                )?;
            }
        }

        if let Some(ref de_cac) = self.de_cac {
            mutex_lock!(de_cac).flush_all(false)?;
            // no write back, because de cache is not a write buffer
        }

        // flush itbl and store new ke into superblock
        let itbl_mode = mutex_lock!(self.inode_tbl).flush()?;
        rwlock_write!(self.sb).itbl_ke = itbl_mode.into_key_entry();

        Ok(())
    }

    fn iread(&self, iid: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        rwlock_write!(self.get_inode(iid, true)?).read_data(offset, to)
    }

    fn iwrite(&self, iid: InodeID, offset: usize, from: &[u8]) -> FsResult<usize> {
        rwlock_write!(self.get_inode(iid, true)?).write_data(offset, from)
    }

    fn get_meta(&self, iid: InodeID) -> FsResult<Metadata> {
        rwlock_read!(self.get_inode(iid, false)?).get_meta()
    }

    fn set_meta(&self, iid: InodeID, set_meta: SetMetadata) -> FsResult<()> {
        rwlock_write!(self.get_inode(iid, true)?).set_meta(set_meta)
    }

    fn iread_link(&self, iid: InodeID) -> FsResult<PathBuf> {
        rwlock_read!(self.get_inode(iid, false)?).get_link()
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        let mut icac = mutex_lock!(&self.icac);
        if let Some(ainode) = icac.get(iid)? {
            let ib = rwlock_read!(ainode).sync_meta()?;
            mutex_lock!(self.inode_tbl).write_exact(
                iid_to_htree_logi_pos(iid), &ib
            )?;
        }

        Ok(())
    }

    fn isync_data(&self, iid: InodeID) -> FsResult<()> {
        rwlock_write!(self.get_inode(iid, true)?).sync_data()
    }

    fn create(
        &self,
        parent: InodeID,
        name: &OsStr,
        ftype: FileType,
        perm: u16,
    ) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    fn link(&self, newparent: InodeID, newname: &OsStr, linkto: InodeID) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    fn unlink(&self, iid: InodeID, name: &OsStr) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    fn symlink(&self, iid: InodeID, name: &OsStr, to: &Path) -> FsResult<InodeID> {
        Err(FsError::Unsupported)
    }

    fn rename(&self, iid: InodeID, name: &OsStr, to: InodeID, newname: &OsStr) -> FsResult<()> {
        Err(FsError::Unsupported)
    }

    fn lookup(&self, iid: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        // Currently we don't use de_cac
        rwlock_write!(self.get_inode(iid, true)?).lookup(name)
    }

    fn listdir(
        &self, iid: InodeID, offset: usize
    ) -> FsResult<Vec<(InodeID, PathBuf, FileType)>> {
        // TODO:
        unimplemented!();
    }

    fn fallocate(
        &self,
        iid: InodeID,
        mode: FallocateMode,
        offset: usize,
        len: usize,
    ) -> FsResult<()> {
        Err(FsError::Unsupported)
    }
}
