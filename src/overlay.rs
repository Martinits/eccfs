use crate::*;
use crate::vfs::*;
use std::sync::{RwLock, RwLockReadGuard};
use std::collections::{HashMap, HashSet};
use std::ffi::OsString;


#[derive(Clone)]
pub struct InodePos(usize, InodeID);

#[derive(Clone)]
pub struct Inode {
    tp: FileType,
    // last valid ancestor's inode in RW layer
    // if all ancestor is present, it's same as this inode id, i.e. ipos[0]'s iid,
    // and in this circumstance, ipos[0] must be RW layer
    rw_fiid: InodeID,
    // last valid ancestor's idx in full_path
    rw_fidx: usize,
    // full path from root dir, with perm, uid, gid
    full_path: Vec<(OsString, FilePerm, u32, u32)>,
    // existing inodes in the lower layers
    // for reg and sym, len is only 1
    ipos: Vec<InodePos>,
    // if true, same names in lower layers are blacked out
    // only useful when ipos[0] is RW layer
    // actually only useful for dirs, but set for reg and sym, too
    black_out_ro: bool,
    // cached dir entries: all children here are allocated an iid and sotred in icac
    // useful only for dirs
    children: Option<HashMap<PathBuf, (FileType, InodeID)>>,
}

const RW_LAYER_IDX: usize = 0;

pub struct OverlayFS {
    /// filesystem layers, 0 is RW layer
    layers: Vec<RwLock<Box<dyn FileSystem>>>,
    /// inode cache, all found inodes are here, second number is next_iid
    icac: RwLock<(HashMap<InodeID, Inode>, InodeID)>,
}

const BLACK_OUT_PREFIX: &str = ".blacked.";

fn black_out_file_of(name: &OsStr) -> PathBuf {
    format!("{}{}", BLACK_OUT_PREFIX, name.to_str().unwrap()).into()
}

fn is_black_out_file(name: &OsStr) -> bool {
    name.to_str().unwrap().starts_with(BLACK_OUT_PREFIX)
}

fn rm_black_out_prefix(name: &PathBuf) -> PathBuf {
    unsafe {
        OsStr::from_encoded_bytes_unchecked(
            &name.as_os_str().as_encoded_bytes()[BLACK_OUT_PREFIX.len()..]
        )
    }.into()
}

impl OverlayFS {
    pub fn new(
        layers: Vec<Box<dyn FileSystem>>,
    ) -> FsResult<Self> {
        // prepare root dir
        // TODO:
        let root_inode = Inode {
            tp: FileType::Dir,
            rw_fiid: 0,
            rw_fidx: 0,
            full_path: vec![
                ("/".into(), FilePerm::from_bits(0o777).unwrap(), 0, 0)
            ],
            ipos: Vec::new(),
            black_out_ro: false,
            children: None,
        };

        let mut map = HashMap::new();
        map.insert(ROOT_INODE_ID, root_inode);

        Ok(Self {
            layers: layers.into_iter().map(
                |fs| RwLock::new(fs)
            ).collect(),
            icac: RwLock::new((map, 2)),
        })
    }

    fn insert_inode(&self, inode: Inode) -> FsResult<InodeID> {
        let mut lock = rwlock_write!(self.icac);
        let iid = lock.1;
        lock.1 += 1;
        lock.0.insert(iid, inode).unwrap();
        Ok(iid)
    }

    // for reg and sym, copy file content
    // for dir, create new dir in RW only
    fn ensure_copy_up(&self, iid: InodeID) -> FsResult<()> {
        let mut lock = rwlock_write!(self.icac);
        let ino = lock.0.get_mut(&iid).unwrap();

        if ino.rw_fidx == ino.full_path.len() - 1 {
            return Ok(())
        }

        // crate all intermediate dirs
        let mut idx = ino.rw_fidx + 1;
        let mut father = ino.rw_fiid;
        let rwfs_lock = rwlock_read!(self.layers[RW_LAYER_IDX]);
        while idx < ino.full_path.len()-1 {
            match rwfs_lock.create(
                father,
                &ino.full_path[idx].0,
                FileType::Dir,
                ino.full_path[idx].2,
                ino.full_path[idx].3,
                ino.full_path[idx].1,
            ) {
                Ok(new_iid) => father = new_iid,
                Err(FsError::AlreadyExists) => {},
                Err(e) => return Err(e),
            }
            idx += 1;
        }


        let new_iid = rwfs_lock.create(
            father,
            &ino.full_path[idx].0,
            ino.tp,
            ino.full_path[idx].2,
            ino.full_path[idx].3,
            ino.full_path[idx].1,
        )?;

        match ino.tp {
            FileType::Reg => {
                assert_eq!(ino.ipos.len(), 1);
                let InodePos(lidx, innd) = ino.ipos[0];
                let mut buf = [0u8; BLK_SZ];
                let mut done = 0;
                loop {
                    let read = rwlock_read!(self.layers[lidx]).iread(innd, done, &mut buf)?;
                    let write = rwfs_lock.iwrite(new_iid, done, &buf[..read])?;
                    assert_eq!(read, write);
                    if read != BLK_SZ {
                        break;
                    }
                    done += read;
                }
                ino.ipos[0] = InodePos(RW_LAYER_IDX, new_iid);
            }
            FileType::Dir => {
                ino.ipos.insert(0, InodePos(RW_LAYER_IDX, new_iid));
            }
            FileType::Lnk => {
                assert_eq!(ino.ipos.len(), 1);
                let InodePos(lidx, innd) = ino.ipos[0];
                let lname = rwlock_read!(self.layers[lidx]).iread_link(innd)?;
                rwfs_lock.iset_link(new_iid, lname.as_os_str())?;
                ino.ipos[0] = InodePos(RW_LAYER_IDX, new_iid);
            }
        }

        ino.rw_fidx= ino.full_path.len() - 1;
        ino.rw_fiid = new_iid;

        Ok(())
    }

    fn ensure_black_out_file(
        &self,
        fs: &RwLockReadGuard<'_, Box<dyn FileSystem>>,
        parent: InodeID,
        name: &OsStr,
    ) -> FsResult<()> {
        let blk_name = black_out_file_of(name);
        if fs.lookup(parent, blk_name.as_os_str())?.is_none() {
            let Metadata { uid, gid, .. } = fs.get_meta(parent)?;
            fs.create(
                parent, blk_name.as_os_str(),
                FileType::Reg, uid, gid, FilePerm::from_bits(0o000).unwrap(),
            )?;
        }
        Ok(())
    }

    fn dir_has_ro_layer(&self, ino: &Inode) -> bool {
        assert_eq!(ino.tp, FileType::Dir);
        ino.ipos.len() > 1 || ino.ipos[0].0 != RW_LAYER_IDX
    }

    fn ensure_children_cached(&self, iid: InodeID) -> FsResult<()> {
        let mut lock = rwlock_write!(self.icac);
        let parent = lock.0.get_mut(&iid).unwrap();

        if parent.children.is_some() {
            return Ok(())
        }

        let mut blk_out_files = HashSet::new();
        let mut map = HashMap::new();
        for InodePos(lidx, innd) in parent.ipos.iter().filter(
            |InodePos(lidx, _)| *lidx == RW_LAYER_IDX || !parent.black_out_ro
        ) {
            let fs = rwlock_read!(self.layers[*lidx]);

            let mut offset = 0;
            while let Some((child_innd, name, tp)) = fs.next_entry(*innd, offset)? {
                if *lidx == RW_LAYER_IDX && is_black_out_file(name.as_os_str()) {
                    blk_out_files.insert(rm_black_out_prefix(&name));
                }
                if let Some((upper_tp, iid)) = map.get(&name) {
                    // if a child already found in upper layers and it's a dir
                    // we need to add this layer to ipos list
                    if tp == FileType::Dir && *upper_tp == FileType::Dir {
                        let mut lock = rwlock_write!(self.icac);
                        let ino = lock.0.get_mut(&iid).unwrap();
                        ino.ipos.push(InodePos(*lidx, child_innd));
                    }
                } else {
                    // create inode in icac
                    let Metadata { uid, gid, perm, .. } = fs.get_meta(child_innd)?;

                    let black_out_ro = if *lidx == RW_LAYER_IDX {
                        parent.black_out_ro | blk_out_files.contains(&name)
                    } else {
                        false
                    };

                    let mut full_path = parent.full_path.clone();
                    full_path.push((name.clone().into(), perm, uid, gid));

                    let (rw_fiid, rw_fidx) = {
                        if *lidx == RW_LAYER_IDX && parent.rw_fiid == *innd {
                            (child_innd, full_path.len() - 1)
                        } else {
                            (parent.rw_fiid, parent.rw_fidx)
                        }
                    };

                    let new_ino = Inode {
                        tp,
                        rw_fiid,
                        rw_fidx,
                        full_path,
                        ipos: vec![InodePos(*lidx, child_innd)],
                        black_out_ro,
                        children: None,
                    };
                    let new_iid = self.insert_inode(new_ino)?;
                    map.insert(name, (tp, new_iid));
                }
                offset += 1;
            }
        }

        Ok(())
    }
}

impl FileSystem for OverlayFS {
    fn init(&self) -> FsResult<()> {
        for fs in self.layers.iter() {
            rwlock_read!(fs).init()?;
        }
        Ok(())
    }

    fn destroy(&mut self) -> FsResult<FSMode> {
        for fs in self.layers[1..].iter() {
            rwlock_write!(fs).destroy()?;
        }
        rwlock_write!(self.layers[RW_LAYER_IDX]).destroy()
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        let mut info = rwlock_read!(self.layers[RW_LAYER_IDX]).finfo()?;
        for fs in self.layers[1..].iter() {
            let FsInfo {
                blocks,
                bfree,
                files,
                namemax,
                ..
            } = rwlock_read!(fs).finfo()?;
            info.blocks += blocks;
            info.bfree += bfree;
            info.files += files;
            info.namemax = info.namemax.min(namemax);
        }
        Ok(info)
    }

    fn fsync(&mut self) -> FsResult<()> {
        for fs in self.layers.iter().rev() {
            rwlock_write!(fs).fsync()?;
        }
        Ok(())
    }

    fn iread(&self, iid: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Reg);
        let InodePos(lidx, innd) = ino.ipos[0];
        rwlock_read!(self.layers[lidx]).iread(innd, offset, to)
    }

    fn iwrite(&self, iid: InodeID, offset: usize, from: &[u8]) -> FsResult<usize> {
        self.ensure_copy_up(iid)?;
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Reg);
        let InodePos(lidx, innd) = ino.ipos[0];
        rwlock_read!(self.layers[lidx]).iwrite(innd, offset, from)
    }

    fn get_meta(&self, iid: InodeID) -> FsResult<Metadata> {
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        let InodePos(lidx, innd) = ino.ipos[0];
        match ino.tp {
            FileType::Reg | FileType::Lnk => {
                rwlock_read!(self.layers[lidx]).get_meta(innd)
            }
            FileType::Dir => {
                let InodePos(top_lidx, top_innd) = ino.ipos[0].clone();
                let mut meta = rwlock_read!(self.layers[top_lidx]).get_meta(top_innd)?;
                meta.iid = iid;
                meta.ftype = FileType::Dir;
                for InodePos(lidx, innd) in ino.ipos.iter().skip(1) {
                    let mt = rwlock_read!(self.layers[*lidx]).get_meta(*innd)?;
                    meta.size += mt.size;
                    meta.blocks += mt.blocks;
                }
                Ok(meta)
            }
        }
    }

    fn set_meta(&self, iid: InodeID, set_meta: SetMetadata) -> FsResult<()> {
        self.ensure_copy_up(iid)?;
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        let InodePos(lidx, innd) = ino.ipos[0];
        rwlock_read!(self.layers[lidx]).set_meta(innd, set_meta)?;
        Ok(())
    }

    fn iread_link(&self, iid: InodeID) -> FsResult<PathBuf> {
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Lnk);
        let InodePos(lidx, innd) = ino.ipos[0];
        rwlock_read!(self.layers[lidx]).iread_link(innd)
    }

    fn iset_link(&self, iid: InodeID, new_lnk: &OsStr) -> FsResult<()> {
        self.ensure_copy_up(iid)?;
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Lnk);
        let InodePos(lidx, innd) = ino.ipos[0];
        rwlock_read!(self.layers[lidx]).iset_link(innd, new_lnk)?;
        Ok(())
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        match ino.tp {
            FileType::Reg | FileType::Lnk => {
                let InodePos(lidx, innd) = ino.ipos[0];
                rwlock_read!(self.layers[lidx]).isync_meta(innd)
            }
            FileType::Dir => {
                for InodePos(lidx, innd) in ino.ipos.iter() {
                    rwlock_read!(self.layers[*lidx]).isync_meta(*innd)?;
                }
                Ok(())
            }
        }
    }

    fn isync_data(&self, iid: InodeID) -> FsResult<()> {
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        match ino.tp {
            FileType::Reg | FileType::Lnk => {
                let InodePos(lidx, innd) = ino.ipos[0];
                rwlock_read!(self.layers[lidx]).isync_data(innd)
            }
            FileType::Dir => {
                for InodePos(lidx, innd) in ino.ipos.iter() {
                    rwlock_read!(self.layers[*lidx]).isync_data(*innd)?;
                }
                Ok(())
            }
        }
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
        if is_black_out_file(name) {
            return Err(FsError::PermissionDenied);
        }
        if self.lookup(parent, name)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        self.ensure_copy_up(parent)?;
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&parent).unwrap();
        assert_eq!(ino.tp, FileType::Dir);

        let InodePos(lidx, innd) = ino.ipos[0];
        let (new_innd, blk_out_file_exist) = {
            let lock = rwlock_read!(self.layers[lidx]);
            (
                lock.create(innd, name, ftype, uid, gid, perm)?,
                lock.lookup(innd, black_out_file_of(name).as_os_str())?.is_some()
            )
        };

        let mut full_path = ino.full_path.clone();
        full_path.push((name.into(), perm, uid, gid));
        let new_ino = Inode {
            tp: ftype,
            rw_fiid: innd,
            rw_fidx: full_path.len()-1,
            full_path,
            ipos: vec![InodePos(RW_LAYER_IDX, new_innd)],
            black_out_ro: ino.black_out_ro | blk_out_file_exist,
            children: None,
        };

        self.insert_inode(new_ino)
    }

    fn link(&self, parent: InodeID, name: &OsStr, linkto: InodeID) -> FsResult<()> {
        if is_black_out_file(name) {
            return Err(FsError::PermissionDenied);
        }
        if self.lookup(parent, name)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        self.ensure_copy_up(parent)?;
        self.ensure_copy_up(linkto)?;

        let lock = rwlock_read!(self.icac);
        let to = lock.0.get(&linkto).unwrap();
        if to.tp == FileType::Dir {
            return Err(FsError::IsADirectory);
        }
        let InodePos(to_lidx, to_innd) = to.ipos[0].clone();
        assert_eq!(to_lidx, RW_LAYER_IDX);

        let fino = lock.0.get(&parent).unwrap();
        let InodePos(f_lidx, f_innd) = fino.ipos[0].clone();
        assert_eq!(f_lidx, RW_LAYER_IDX);

        rwlock_read!(self.layers[f_lidx]).link(f_innd, name, to_innd)?;
        Ok(())
    }

    fn unlink(&self, parent: InodeID, name: &OsStr) -> FsResult<()> {
        if is_black_out_file(name) {
            return Err(FsError::PermissionDenied);
        }

        self.ensure_copy_up(parent)?;
        let lock = rwlock_read!(self.icac);
        let fino = lock.0.get(&parent).unwrap();
        let InodePos(lidx, innd) = fino.ipos[0].clone();
        assert_eq!(lidx, RW_LAYER_IDX);

        let lock = rwlock_read!(self.layers[lidx]);
        match lock.unlink(parent, name) {
            Ok(_) | Err(FsError::NotFound) => {
                // if black out file not exists, create one
                self.ensure_black_out_file(&lock, innd, name)?;
            }
            Err(e) => return Err(e),
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
        if is_black_out_file(name) {
            return Err(FsError::PermissionDenied);
        }
        if self.lookup(parent, name)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        self.ensure_copy_up(parent)?;
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&parent).unwrap();

        let InodePos(lidx, innd) = ino.ipos[0].clone();
        let (new_innd, blk_out_file_exist) = {
            let lock = rwlock_read!(self.layers[lidx]);
            (
                lock.symlink(innd, name, to, uid, gid)?,
                lock.lookup(innd, black_out_file_of(name).as_os_str())?.is_some()
            )
        };

        let mut full_path = ino.full_path.clone();
        full_path.push((name.into(), FilePerm::from_bits(0o777).unwrap(), uid, gid));
        let new_ino = Inode {
            tp: FileType::Lnk,
            rw_fiid: innd,
            rw_fidx: full_path.len()-1,
            full_path,
            ipos: vec![InodePos(RW_LAYER_IDX, new_innd)],
            black_out_ro: ino.black_out_ro | blk_out_file_exist,
            children: None,
        };

        self.insert_inode(new_ino)
    }

    fn rename(
        &self,
        from: InodeID, name: &OsStr,
        to: InodeID, newname: &OsStr
    ) -> FsResult<()> {
        if is_black_out_file(name) {
            return Err(FsError::PermissionDenied);
        }
        if is_black_out_file(newname) {
            return Err(FsError::PermissionDenied);
        }
        if self.lookup(to, newname)?.is_some() {
            return Err(FsError::AlreadyExists);
        }

        let lock = rwlock_read!(self.icac);

        let old_iid = if let Some(old_iid) = self.lookup(from, name)? {
            let old_ino = lock.0.get(&old_iid).unwrap();
            // refuse to move a dir with children in RO layers
            if self.dir_has_ro_layer(old_ino) {
                return Err(FsError::PermissionDenied);
            }
            old_iid
        } else {
            return Err(FsError::NotFound);
        };

        self.ensure_copy_up(from)?;
        self.ensure_copy_up(to)?;

        let from_ino = lock.0.get(&from).unwrap();
        assert_eq!(from_ino.tp, FileType::Dir);
        let InodePos(from_lidx, from_innd) = from_ino.ipos[0].clone();
        assert_eq!(from_lidx, RW_LAYER_IDX);
        let fs = rwlock_read!(self.layers[from_lidx]);

        self.ensure_copy_up(old_iid)?;

        if from == to {
            // from and to are same dir
            fs.rename(from_innd, name, from_innd, newname)?;
        } else {
            // from and to are different dir
            let to_ino = lock.0.get(&to).unwrap();
            assert_eq!(to_ino.tp, FileType::Dir);
            let InodePos(to_lidx, to_innd) = to_ino.ipos[0].clone();
            assert_eq!(to_lidx, RW_LAYER_IDX);

            fs.rename(from_innd, name, to_innd, newname)?;
        }
        // create black out file for oldname
        self.ensure_black_out_file(&fs, from_innd, name)?;

        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &OsStr) -> FsResult<Option<InodeID>> {
        self.ensure_children_cached(iid)?;

        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();

        let item = ino.children.as_ref().unwrap().iter().find(
            |(pb, _)| pb.as_os_str() == name
        );

        Ok(item.map(
            |(_, (_, iid))| *iid
        ))
    }

    fn listdir(
        &self, iid: InodeID, offset: usize, num: usize,
    ) -> FsResult<Vec<(InodeID, PathBuf, FileType)>> {
        self.ensure_children_cached(iid)?;

        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();

        let mut ret = Vec::new();
        for (name, (tp, iid)) in ino.children.as_ref().unwrap().iter().skip(offset) {
            ret.push((*iid, name.clone(), *tp));
            if num != 0 && ret.len() >= num {
                break;
            }
        }

        Ok(ret)
    }

    fn fallocate(
        &self,
        iid: InodeID,
        mode: FallocateMode,
        offset: usize,
        len: usize,
    ) -> FsResult<()> {
        self.ensure_copy_up(iid)?;
        let lock = rwlock_read!(self.icac);
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Reg);
        let InodePos(lidx, innd) = ino.ipos[0];
        rwlock_read!(self.layers[lidx]).fallocate(innd, mode, offset, len)?;
        Ok(())
    }
}
