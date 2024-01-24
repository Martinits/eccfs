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
use bitmap::*;
use std::fs;


pub const RWFS_MAGIC: u64 = 0x0045434352574653; // ECCRWFS
pub const NAME_MAX: u64 = DIRENT_NAME_MAX as u64;
pub const SB_FILE_NAME: &str = "meta";

pub const RW_CACHE_CAP_DEFAULT_ITBL: usize = 4;

pub const DATA_FILE_NAME_LEN: usize = size_of::<Hash256>() * 2;

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
    sb_meta_for_inode: Arc<RwLock<(usize, usize)>>,
}

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
        path: &Path, // must be a dir
        mode: FSMode,
        icache_cap_hint: Option<usize>,
        cache_de: usize,
    ) -> FsResult<Self> {
        assert!(io_try!(fs::metadata(path)).is_dir());
        let mut pb = path.to_path_buf();
        pb.push(SB_FILE_NAME);

        let mut sb_file = FileStorage::new(&pb, true)?;
        pb.pop();

        // read superblock
        let mut sb_blk = sb_file.read_blk(SUPERBLOCK_POS)?;
        // check crypto
        crypto_in(&mut sb_blk, CryptoHint::from_fsmode(mode.clone(), SUPERBLOCK_POS))?;
        let sb = SuperBlock::new(sb_blk)?;

        // check sb file len
        if sb_file.get_len()? != blk2byte!(sb.ibitmap_len + 1) {
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        // check nr_data_file
        if io_try!(fs::read_dir(path)).count() != sb.nr_data_file {
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }

        // read ibitmap
        if sb.ibitmap_len == 0 {
            // no possibilty that ibitmap is empty
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        let mut ibitmap_blks = vec![[0u8; BLK_SZ]; sb.ibitmap_len as usize];
        for (i, (blk, ke)) in ibitmap_blks.iter_mut().zip(sb.ibitmap_ke.iter()).enumerate() {
            let pos = i as u64 + sb.ibitmap_start;
            sb_file.read_blk_to(pos, blk)?;
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
        assert_eq!(itbl_file_name.len(), 2 * size_of::<Hash256>());
        pb.push(itbl_file_name);
        let mut itbl_storage = FileStorage::new(Path::new(&pb), true)?;
        pb.pop();
        if itbl_storage.get_len()? != blk2byte!(sb.itbl_len) {
            return Err(new_error!(FsError::SuperBlockCheckFailed));
        }
        let inode_tbl = RWHashTree::new(
            Some(RW_CACHE_CAP_DEFAULT_ITBL),
            Box::new(itbl_storage),
            mht::get_logi_nr_blk(sb.itbl_len as u64),
            Some(FSMode::from_key_entry(sb.itbl_ke, mode.is_encrypted())),
            mode.is_encrypted(),
        );

        let sb_meta_for_inode = Arc::new(RwLock::new((sb.nr_data_file, sb.blocks)));

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
            sb_meta_for_inode,
        })
    }

    fn fetch_inode(&self, iid: InodeID) -> FsResult<Inode> {
        let ib = self.read_itbl(iid)?;
        Inode::new_from_raw(
            &ib, iid, &self.path, self.mode.is_encrypted(),
            self.sb_meta_for_inode.clone(),
        )
    }

    fn write_back_inode(&self, iid: InodeID, inode: Inode) -> FsResult<()> {
        let ib = inode.destroy()?;
        self.write_itbl(iid, &ib)
    }

    fn write_itbl(&self, iid: InodeID, ib: &InodeBytes) -> FsResult<()> {
        mutex_lock!(self.inode_tbl).write_exact(
            iid_to_htree_logi_pos(iid), ib
        )?;
        Ok(())
    }

    fn read_itbl(&self, iid: InodeID) -> FsResult<InodeBytes> {
        let mut ib = [0u8; INODE_SZ];
        let read = mutex_lock!(self.inode_tbl).read_exact(
            iid_to_htree_logi_pos(iid), &mut ib
        )?;
        assert_eq!(read, INODE_SZ);
        Ok(ib)
    }

    fn get_inode(&self, iid: InodeID, dirty: bool) -> FsResult<Arc<RwLock<Inode>>> {
        let mut icac = mutex_lock!(&self.icac);
        let ainode = if let Some(ainode) = icac.get(iid)? {
            ainode
        } else {
            // cache miss
            let ainode = Arc::new(RwLock::new(self.fetch_inode(iid)?));
            if let Some((iid, rw_inode)) = icac.insert_and_get(iid, &ainode)? {
                // write back inode
                let inode = rw_inode.into_inner().unwrap();
                self.write_back_inode(iid, inode)?;
            }
            ainode
        };
        if dirty {
            icac.mark_dirty(iid)?;
        }
        Ok(ainode)
    }

    fn get_inode_try(&self, iid: InodeID, dirty: bool) -> FsResult<Option<Arc<RwLock<Inode>>>> {
        let mut icac = mutex_lock!(&self.icac);
        if let Some(ainode) = icac.get(iid)? {
            if dirty {
                icac.mark_dirty(iid)?;
            }
            Ok(Some(ainode))
        } else {
            Ok(None)
        }
    }

    fn insert_inode(&self, iid: InodeID, inode: Inode) -> FsResult<()> {
        let mut icac = mutex_lock!(&self.icac);
        let ainode = Arc::new(RwLock::new(inode));
        if let Some((iid, rw_inode)) = icac.insert_and_get(iid, &ainode)? {
            // write back inode
            let inode = rw_inode.into_inner().unwrap();
            self.write_back_inode(iid, inode)?;
        }
        icac.mark_dirty(iid)?;
        Ok(())
    }

    fn remove_inode(&self, iid: InodeID) -> FsResult<()> {
        // load inode, ensure its in cache
        let _ = self.get_inode(iid, false)?;

        let mut icac = mutex_lock!(&self.icac);
        let lock_inode = icac.flush_key_force(iid)?.unwrap();
        let ino = lock_inode.into_inner().unwrap();

        if ino.tp == FileType::Reg {
            rwlock_write!(self.sb).files -= 1;
        }

        // remove data file
        ino.remove_data_file()?;

        // zero that disk range and reset bitmap
        self.write_itbl(iid, &ZERO_INODE)?;

        Ok(())
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
        sb_file.set_len(1 + ibitmap_blks.len() as u64)?;
        for (i, blk) in ibitmap_blks.iter_mut().enumerate() {
            let pos = i as u64 + rwlock_read!(self.sb).ibitmap_start;
            let ke = crypto_out(blk,
                if self.mode.is_encrypted() {
                    Some(self.key_gen.gen_key(pos)?)
                } else {
                    None
                },
                pos
            )?.into_key_entry();
            ibitmap_ke.push(ke);
            sb_file.write_blk(pos, blk)?;
        }
        {
            let mut lock = rwlock_write!(self.sb);
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
            let mut lock = rwlock_write!(self.sb);
            lock.nr_data_file = rwlock_read!(self.sb_meta_for_inode).0;
            lock.blocks = rwlock_read!(self.sb_meta_for_inode).1;
        }
        // write superblock
        let mut sb_blk = rwlock_read!(self.sb).write()?;
        let mode = crypto_out(&mut sb_blk,
            if self.mode.is_encrypted() {
                let key = if self.regen_root_key {
                    self.key_gen.gen_key(SUPERBLOCK_POS)?
                } else {
                    self.mode.get_key().unwrap()
                };
                Some(key)
            } else {
                None
            },
            SUPERBLOCK_POS
        )?;
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
                self.write_back_inode(iid, inode)?;
            }
        }

        if let Some(ref de_cac) = self.de_cac {
            mutex_lock!(de_cac).flush_all(false)?;
            // no write back, because de cache is not a write buffer
        }

        // flush itbl and store new ke into superblock
        let itbl_mode = mutex_lock!(self.inode_tbl).flush()?;
        let mut lock = rwlock_write!(self.sb);
        lock.itbl_ke = itbl_mode.into_key_entry();
        let new_itbl_len = mht::get_phy_nr_blk(mutex_lock!(self.inode_tbl).length) as usize;
        nf_nb_change(
            &self.sb_meta_for_inode,
            0,
            new_itbl_len as isize - lock.itbl_len as isize
        )?;
        lock.itbl_len = new_itbl_len;

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

    fn iset_link(&self, iid: InodeID, new_lnk: &OsStr) -> FsResult<()> {
        rwlock_write!(self.get_inode(iid, true)?).set_link(Path::new(new_lnk))
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        if let Some(lock) = self.get_inode_try(iid, true)? {
            let ib = rwlock_write!(lock).sync_meta()?;
            self.write_itbl(iid, &ib)?;
            mutex_lock!(&self.icac).unmark_dirty(iid)?;
        }
        Ok(())
    }

    fn isync_data(&self, iid: InodeID) -> FsResult<()> {
        if let Some(lock) = self.get_inode_try(iid, true)? {
            rwlock_write!(lock).sync_data()?;
        }
        Ok(())
    }

    fn create(
        &self,
        parent: InodeID,
        name: &OsStr,
        ftype: FileType,
        uid: u32,
        gid: u32,
        perm: FilePerm,
    ) -> FsResult<InodeID> {
        let iid = mutex_lock!(self.ibitmap).alloc()?;
        let inode = Inode::new(
            iid, parent, ftype, uid, gid, perm,
            &self.path, self.mode.is_encrypted(), self.sb_meta_for_inode.clone(),
        )?;

        rwlock_write!(self.get_inode(parent, true)?).add_child(name, ftype, iid)?;

        self.insert_inode(iid, inode)?;

        if ftype == FileType::Reg {
            rwlock_write!(self.sb).files += 1;
        }

        Ok(iid)
    }

    fn link(&self, parent: InodeID, name: &OsStr, linkto: InodeID) -> FsResult<()> {
        let to = self.get_inode(linkto, true)?;
        let mut lock = rwlock_write!(to);

        // hard links not allowed for directories
        if lock.tp == FileType::Dir {
            return Err(FsError::PermissionDenied);
        }

        lock.nlinks += 1;
        let tp = lock.tp;

        rwlock_write!(self.get_inode(parent, true)?).add_child(
            name, tp, linkto,
        )?;
        Ok(())
    }

    fn unlink(&self, parent: InodeID, name: &OsStr) -> FsResult<()> {
        let (iid, _) = rwlock_write!(self.get_inode(parent, true)?).remove_child(name)?;

        let do_remove = {
            let inode = self.get_inode(iid, true)?;
            let mut lock = rwlock_write!(inode);
            if lock.nlinks == 1 {
                true
            } else {
                lock.nlinks -= 1;
                false
            }
        };

        if do_remove {
            self.remove_inode(iid)?;
        }

        Ok(())
    }

    fn symlink(
        &self,
        parent: InodeID,
        name: &OsStr,
        to: &Path,
        uid: u32,
        gid: u32,
    ) -> FsResult<InodeID> {
        let iid = mutex_lock!(self.ibitmap).alloc()?;
        // symlink permissions are always 0777 since on Linux they are not used anyway
        let mut inode = Inode::new(
            iid, parent, FileType::Lnk, uid, gid, FilePerm::from_bits(PERM_MASK).unwrap(),
            &self.path, self.mode.is_encrypted(), self.sb_meta_for_inode.clone(),
        )?;
        inode.set_link(to)?;

        rwlock_write!(self.get_inode(parent, true)?).add_child(name, FileType::Lnk, iid)?;

        self.insert_inode(iid, inode)?;
        Ok(iid)
    }

    fn rename(
        &self,
        from: InodeID, name: &OsStr,
        to: InodeID, newname: &OsStr
    ) -> FsResult<()> {
        let from_inode = self.get_inode(from, true)?;
        if from == to {
            rwlock_write!(from_inode).rename_child(name, newname)?;
        } else {
            let (iid, tp) = rwlock_write!(from_inode).remove_child(name)?;
            rwlock_write!(self.get_inode(to, true)?).add_child(newname, tp, iid)?;
        }
        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        // Currently we don't use de_cac
        rwlock_write!(self.get_inode(iid, true)?).find_child(name)
    }

    fn listdir(
        &self, iid: InodeID, offset: usize, num: usize,
    ) -> FsResult<Vec<(InodeID, PathBuf, FileType)>> {
        let inode = self.get_inode(iid, true)?;
        let l = rwlock_write!(inode).read_child(offset, num)?.into_iter().map(
            |DirEntry {ipos, tp, name}| (ipos, name.into(), tp)
        ).collect();
        Ok(l)
    }

    fn fallocate(
        &self,
        iid: InodeID,
        mode: FallocateMode,
        offset: usize,
        len: usize,
    ) -> FsResult<()> {
        rwlock_write!(self.get_inode(iid, true)?).fallocate(mode, offset, len)
    }
}

// change nr_data_file and blocks in superblock
pub fn nf_nb_change(
    pointer: &Arc<RwLock<(usize, usize)>>, f: isize, b: isize
) -> FsResult<()> {
    let mut lock = rwlock_write!(pointer);
    lock.0 = lock.0.checked_add_signed(f).unwrap();
    lock.1 = lock.1.checked_add_signed(b).unwrap();
    Ok(())
}
