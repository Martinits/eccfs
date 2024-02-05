pub mod superblock;
pub mod inode;
pub mod disk;
pub mod bitmap;

extern crate alloc;
use crate::vfs::*;
use crate::vfs::SetMetadata::*;
use alloc::sync::Arc;
use spin::{RwLock, Mutex};
use crate::*;
use superblock::*;
use crate::htree::*;
use inode::*;
use crate::storage::*;
use crate::lru::*;
use disk::*;
use core::mem::size_of;
use bitmap::*;
use alloc::vec::Vec;
use alloc::string::{String, ToString};


pub const RWFS_MAGIC: u64 = 0x0045434352574653; // ECCRWFS
pub const NAME_MAX: u64 = DIRENT_NAME_MAX as u64;
pub const SB_FILE_NAME: &str = "meta";

pub const RW_CACHE_CAP_DEFAULT_ITBL: usize = 4;

pub const DATA_FILE_NAME_LEN: usize = size_of::<Hash256>() * 2;

pub struct RWFS {
    regen_root_key: bool,
    mode: FSMode,
    sb: RwLock<SuperBlock>,
    ibitmap: Mutex<BitMap>,
    inode_tbl: Mutex<RWHashTree>,
    icac: Mutex<Lru<InodeID, RwLock<Inode>>>,
    de_cac: Option<Mutex<Lru<String, InodeID>>>,
    key_gen: Mutex<KeyGen>,
    sb_meta_for_inode: Arc<RwLock<(usize, usize)>>,
    device: Arc<dyn Device>,
    sb_storage: Arc<dyn RWStorage>,
    time_source: &'static dyn TimeSource,
}

#[cfg(feature = "channel_lru")]
impl Drop for RWFS {
    fn drop(&mut self) {
        self.icac.lock().unwrap().abort().unwrap();
        if let Some(mu_decac) = &self.de_cac {
            mu_decac.lock().unwrap().abort().unwrap();
        }
    }
}

impl RWFS {
    pub fn new(
        regen_root_key: bool,
        mode: FSMode,
        icache_cap_hint: Option<usize>,
        cache_de: usize,
        device: Arc<dyn Device>,
        time_source: &'static dyn TimeSource,
    ) -> FsResult<Self> {

        let sb_storage = device.open_rw_storage(SB_FILE_NAME)?;

        // read superblock
        let mut sb_blk = sb_storage.read_blk(SUPERBLOCK_POS)?;
        // check crypto
        crypto_in(&mut sb_blk, CryptoHint::from_fsmode(mode.clone(), SUPERBLOCK_POS))?;
        let sb = SuperBlock::new(sb_blk)?;

        // check sb file len
        if sb_storage.get_len()? != blk2byte!(sb.ibitmap_len + 1) {
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        // check nr_data_file
        if device.nr_storage()? != sb.nr_data_file {
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }

        // read ibitmap
        if sb.ibitmap_len == 0 {
            // no possibilty that ibitmap is empty
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        let mut ibitmap_blks = Vec::new();
        ibitmap_blks.resize(sb.ibitmap_len as usize, [0u8; BLK_SZ]);
        for (i, (blk, ke)) in ibitmap_blks.iter_mut().zip(sb.ibitmap_ke.iter()).enumerate() {
            let pos = i as u64 + sb.ibitmap_start;
            sb_storage.read_blk_to(pos, blk)?;
            crypto_in(
                blk,
                CryptoHint::from_key_entry(
                    ke.clone(), mode.is_encrypted(), pos
                )
            )?;
        }
        let ibitmap = BitMap::new(ibitmap_blks)?;

        // read itbl
        if sb.itbl_len == 0 {
            // no possibilty that itbl is empty
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        let itbl_file_name = hex::encode_upper(&sb.itbl_name);
        assert_eq!(itbl_file_name.len(), DATA_FILE_NAME_LEN);
        let itbl_storage = device.open_rw_storage(&itbl_file_name)?;
        if itbl_storage.get_len()? != blk2byte!(sb.itbl_len) {
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        let inode_tbl = RWHashTree::new(
            Some(RW_CACHE_CAP_DEFAULT_ITBL),
            itbl_storage,
            mht::get_logi_nr_blk(sb.itbl_len as u64),
            Some(FSMode::from_key_entry(sb.itbl_ke, mode.is_encrypted())),
            mode.is_encrypted(),
        );

        let sb_meta_for_inode = Arc::new(RwLock::new((sb.nr_data_file, sb.blocks)));

        Ok(RWFS {
            regen_root_key,
            mode,
            sb: RwLock::new(sb),
            ibitmap: Mutex::new(ibitmap),
            inode_tbl: Mutex::new(inode_tbl),
            icac: Mutex::new(Lru::new(
                icache_cap_hint.unwrap_or(DEFAULT_CACHE_CAP)
            )),
            de_cac: if cache_de != 0 {
                Some(Mutex::new(Lru::new(cache_de)))
            } else {
                None
            },
            key_gen: Mutex::new(KeyGen::new()),
            sb_meta_for_inode,
            device,
            sb_storage,
            time_source,
        })
    }

    fn fetch_inode(&self, iid: InodeID) -> FsResult<Inode> {
        let ib = self.read_itbl(iid)?;
        Inode::new_from_raw(
            &ib, iid, self.mode.is_encrypted(),
            self.sb_meta_for_inode.clone(), self.device.clone(),
        )
    }

    fn write_back_inode(&self, iid: InodeID, inode: Inode) -> FsResult<()> {
        let ib = inode.destroy()?;
        self.write_itbl(iid, &ib)
    }

    fn write_itbl(&self, iid: InodeID, ib: &InodeBytes) -> FsResult<()> {
        self.inode_tbl.lock().write_exact(
            iid_to_htree_logi_pos(iid), ib
        )?;
        Ok(())
    }

    fn read_itbl(&self, iid: InodeID) -> FsResult<InodeBytes> {
        let mut ib = [0u8; INODE_SZ];
        let read = self.inode_tbl.lock().read_exact(
            iid_to_htree_logi_pos(iid), &mut ib
        )?;
        assert_eq!(read, INODE_SZ);
        Ok(ib)
    }

    fn get_inode(&self, iid: InodeID, dirty: bool) -> FsResult<Arc<RwLock<Inode>>> {
        let mut icac = self.icac.lock();
        let ainode = if let Some(ainode) = icac.get(&iid)? {
            ainode
        } else {
            // cache miss
            let ainode = Arc::new(RwLock::new(self.fetch_inode(iid)?));
            if let Some((iid, rw_inode)) = icac.insert_and_get(iid, &ainode)? {
                // write back inode
                let inode = rw_inode.into_inner();
                self.write_back_inode(iid, inode)?;
            }
            ainode
        };
        if dirty {
            icac.mark_dirty(&iid)?;
        }
        Ok(ainode)
    }

    fn get_inode_try(&self, iid: InodeID, dirty: bool) -> FsResult<Option<Arc<RwLock<Inode>>>> {
        let mut icac = self.icac.lock();
        if let Some(ainode) = icac.get(&iid)? {
            if dirty {
                icac.mark_dirty(&iid)?;
            }
            Ok(Some(ainode))
        } else {
            Ok(None)
        }
    }

    fn insert_inode(&self, iid: InodeID, inode: Inode) -> FsResult<()> {
        let mut icac = self.icac.lock();
        let ainode = Arc::new(RwLock::new(inode));
        if let Some((iid, rw_inode)) = icac.insert_and_get(iid, &ainode)? {
            // write back inode
            let inode = rw_inode.into_inner();
            self.write_back_inode(iid, inode)?;
        }
        icac.mark_dirty(&iid)?;
        Ok(())
    }

    fn remove_inode(&self, iid: InodeID) -> FsResult<()> {
        // load inode, ensure its in cache
        let _ = self.get_inode(iid, false)?;

        let mut icac = self.icac.lock();
        let lock_inode = icac.try_pop_key(&iid, true)?.unwrap();
        let ino = lock_inode.into_inner();

        if ino.tp == FileType::Reg {
            self.sb.write().files -= 1;
        }

        // remove data file
        ino.remove_data_file()?;

        // zero that disk range and reset bitmap
        self.write_itbl(iid, &ZERO_INODE)?;

        Ok(())
    }
}

macro_rules! update_times {
    ($self:ident, $lock: expr, $($x:expr),* ) => {
        {
            let now = $self.time_source.now();
            $(
                $lock.set_meta($x(now))?;
            )*
        }
    };
}

impl FileSystem for RWFS {
    fn destroy(&self) -> FsResult<FSMode> {
        // sync data and meta
        self.fsync()?;

        // write bitmap
        let mut ibitmap_blks = self.ibitmap.lock().write()?;
        let mut ibitmap_ke = Vec::with_capacity(ibitmap_blks.len());
        self.sb_storage.set_len(1 + ibitmap_blks.len() as u64)?;
        for (i, blk) in ibitmap_blks.iter_mut().enumerate() {
            let pos = i as u64 + self.sb.read().ibitmap_start;
            let ke = crypto_out(blk,
                if self.mode.is_encrypted() {
                    Some(self.key_gen.lock().gen_key(pos)?)
                } else {
                    None
                },
                pos
            )?.into_key_entry();
            ibitmap_ke.push(ke);
            self.sb_storage.write_blk(pos, blk)?;
        }
        {
            let mut lock = self.sb.write();
            let new_ib_len = ibitmap_blks.len();
            nf_nb_change(
                &self.sb_meta_for_inode,
                0,
                new_ib_len as isize - lock.ibitmap_len as isize
            )?;
            lock.ibitmap_len = new_ib_len;
            lock.ibitmap_ke = ibitmap_ke;
        }

        // write sb_meta_for_inode back to superblock
        {
            let mut lock = self.sb.write();
            lock.nr_data_file = self.sb_meta_for_inode.read().0;
            lock.blocks = self.sb_meta_for_inode.read().1;
        }
        // write superblock
        let mut sb_blk = self.sb.read().write()?;
        let mode = crypto_out(&mut sb_blk,
            if self.mode.is_encrypted() {
                let key = if self.regen_root_key {
                    self.key_gen.lock().gen_key(SUPERBLOCK_POS)?
                } else {
                    self.mode.get_key().unwrap()
                };
                Some(key)
            } else {
                None
            },
            SUPERBLOCK_POS
        )?;
        self.sb_storage.write_blk(SUPERBLOCK_POS, &sb_blk)?;

        Ok(mode)
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        self.sb.read().get_fsinfo()
    }

    fn fsync(&self) -> FsResult<()> {
        for (iid, i) in self.icac.lock().flush_wb()? {
            let inode = i.into_inner();
            self.write_back_inode(iid, inode)?;
        }

        if let Some(ref de_cac) = self.de_cac {
            de_cac.lock().flush_wb()?;
            // no write back, because de cache is not a write buffer
        }

        // flush itbl and store new ke into superblock
        let itbl_mode = self.inode_tbl.lock().flush()?;
        let mut lock = self.sb.write();
        lock.itbl_ke = itbl_mode.into_key_entry();
        let new_itbl_len = mht::get_phy_nr_blk(self.inode_tbl.lock().logi_len) as usize;
        nf_nb_change(
            &self.sb_meta_for_inode,
            0,
            new_itbl_len as isize - lock.itbl_len as isize
        )?;
        lock.itbl_len = new_itbl_len;

        Ok(())
    }

    fn iread(&self, iid: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        let read = lock.read_data(offset, to)?;
        update_times!(self, lock, Atime);
        Ok(read)
    }

    fn iwrite(&self, iid: InodeID, offset: usize, from: &[u8]) -> FsResult<usize> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        let written = lock.write_data(offset, from)?;
        update_times!(self, lock, Atime, Ctime, Mtime);
        Ok(written)
    }

    fn get_meta(&self, iid: InodeID) -> FsResult<Metadata> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        let meta = lock.get_meta()?;
        update_times!(self, lock, Atime);
        Ok(meta)
    }

    fn set_meta(&self, iid: InodeID, set_meta: SetMetadata) -> FsResult<()> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        lock.set_meta(set_meta.clone())?;
        match set_meta {
            Atime(_) | Ctime(_) | Mtime(_) => {},
            _ => update_times!(self, lock, Atime, Ctime),
        }
        Ok(())
    }

    fn iread_link(&self, iid: InodeID) -> FsResult<String> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        let pb = lock.get_link()?;
        update_times!(self, lock, Atime);
        Ok(pb)
    }

    fn iset_link(&self, iid: InodeID, new_lnk: &str) -> FsResult<()> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        lock.set_link(new_lnk)?;
        update_times!(self, lock, Atime, Ctime, Mtime);
        Ok(())
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        if let Some(lock) = self.get_inode_try(iid, true)? {
            let ib = lock.write().sync_meta()?;
            self.write_itbl(iid, &ib)?;
            self.icac.lock().unmark_dirty(&iid)?;
        }
        Ok(())
    }

    fn isync_data(&self, iid: InodeID) -> FsResult<()> {
        if let Some(lock) = self.get_inode_try(iid, true)? {
            lock.write().sync_data()?;
        }
        Ok(())
    }

    fn create(
        &self,
        parent: InodeID,
        name: &str,
        ftype: FileType,
        uid: u32,
        gid: u32,
        perm: FilePerm,
    ) -> FsResult<InodeID> {
        let iid = self.ibitmap.lock().alloc()?;
        let inode = Inode::new(
            iid, parent, ftype, uid, gid, perm,
            self.mode.is_encrypted(),
            self.sb_meta_for_inode.clone(), self.device.clone(),
            self.time_source.now(),
        )?;

        let alock = self.get_inode(parent, true)?;
        let mut lock = alock.write();
        lock.add_child(name, ftype, iid)?;
        update_times!(self, lock, Atime, Ctime, Mtime);

        self.insert_inode(iid, inode)?;

        if ftype == FileType::Reg {
            self.sb.write().files += 1;
        }

        Ok(iid)
    }

    fn link(&self, parent: InodeID, name: &str, linkto: InodeID) -> FsResult<()> {
        let to = self.get_inode(linkto, true)?;
        let mut lock = to.write();

        // hard links not allowed for directories
        if lock.tp == FileType::Dir {
            return Err(FsError::PermissionDenied);
        }

        lock.nlinks += 1;
        update_times!(self, lock, Atime, Ctime);
        let tp = lock.tp;

        let alock = self.get_inode(parent, true)?;
        let mut lock = alock.write();
        lock.add_child(name, tp, linkto)?;

        Ok(())
    }

    fn unlink(&self, parent: InodeID, name: &str) -> FsResult<()> {
        let alock = self.get_inode(parent, true)?;
        let mut lock = alock.write();
        let (iid, _) = lock.remove_child(name)?;
        update_times!(self, lock, Atime, Ctime, Mtime);

        let do_remove = {
            let inode = self.get_inode(iid, true)?;
            let mut lock = inode.write();
            if lock.nlinks == 1 {
                true
            } else {
                lock.nlinks -= 1;
                update_times!(self, lock, Atime, Ctime);
                false
            }
        };

        if do_remove {
            // debug!("unlink do remove parent {} name {:?} iid {}", parent, name, iid);
            self.remove_inode(iid)?;
        }

        Ok(())
    }

    fn symlink(
        &self,
        parent: InodeID,
        name: &str,
        to: &str,
        uid: u32,
        gid: u32,
    ) -> FsResult<InodeID> {
        let iid = self.ibitmap.lock().alloc()?;
        // symlink permissions are always 0777 since on Linux they are not used anyway
        let mut inode = Inode::new(
            iid, parent, FileType::Lnk, uid, gid,
            FilePerm::from_bits(PERM_MASK).unwrap(),
            self.mode.is_encrypted(),
            self.sb_meta_for_inode.clone(), self.device.clone(),
            self.time_source.now(),
        )?;
        inode.set_link(to)?;

        let alock = self.get_inode(parent, true)?;
        let mut lock = alock.write();
        lock.add_child(name, FileType::Lnk, iid)?;
        update_times!(self, lock, Atime, Ctime, Mtime);

        self.insert_inode(iid, inode)?;
        Ok(iid)
    }

    fn rename(
        &self,
        from: InodeID, name: &str,
        to: InodeID, newname: &str
    ) -> FsResult<()> {
        // remove to/newname unless it's a non-empty dir
        if let Some(iid) = self.lookup(to, newname)? {
            let meta = self.get_meta(iid)?;
            if meta.ftype == FileType::Dir && meta.size > 2 * DIRENT_SZ as u64 {
                return Err(FsError::DirectoryNotEmpty);
            }
            self.unlink(to, newname)?;
        }

        let from_inode = self.get_inode(from, true)?;
        if from == to {
            let mut lock = from_inode.write();
            lock.rename_child(name, newname)?;
            update_times!(self, lock, Atime, Ctime, Mtime);
        } else {
            let mut lock = from_inode.write();
            let (iid, tp) = lock.remove_child(name)?;
            update_times!(self, lock, Atime, Ctime, Mtime);

            let alock = self.get_inode(to, true)?;
            let mut lock = alock.write();
            lock.add_child(newname, tp, iid)?;
            update_times!(self, lock, Atime, Ctime, Mtime);
        }
        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &str) -> FsResult<Option<InodeID>> {
        // Currently we don't use de_cac
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        let ret = lock.find_child(name)?;
        update_times!(self, lock, Atime);
        // debug!("lookup parent {} name {:?} found {:?}", iid, name, ret);
        Ok(ret)
    }

    fn listdir(
        &self, iid: InodeID, offset: usize, num: usize,
    ) -> FsResult<Vec<(InodeID, String, FileType)>> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        let l = lock.read_child(offset, num)?.into_iter().map(
            |DirEntry {ipos, tp, name}| (ipos, name.into(), tp)
        ).collect();
        update_times!(self, lock, Atime);
        Ok(l)
    }

    fn fallocate(
        &self,
        iid: InodeID,
        mode: FallocateMode,
        offset: usize,
        len: usize,
    ) -> FsResult<()> {
        let alock = self.get_inode(iid, true)?;
        let mut lock = alock.write();
        lock.fallocate(mode, offset, len)?;
        update_times!(self, lock, Atime, Ctime, Mtime);
        Ok(())
    }
}

// change nr_data_file and blocks in superblock
pub fn nf_nb_change(
    pointer: &Arc<RwLock<(usize, usize)>>, f: isize, b: isize
) -> FsResult<()> {
    let mut lock = pointer.write();
    lock.0 = lock.0.checked_add_signed(f).unwrap();
    lock.1 = lock.1.checked_add_signed(b).unwrap();
    Ok(())
}
