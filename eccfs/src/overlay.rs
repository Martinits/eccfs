use crate::*;
use crate::vfs::*;
use spin::{RwLock, RwLockReadGuard, RwLockWriteGuard};
use alloc::collections::{BTreeMap, BTreeSet};

extern crate alloc;
use alloc::vec::Vec;
use alloc::boxed::Box;
use alloc::string::{String, ToString};


#[derive(Clone, Debug)]
pub struct InodePos(usize, InodeID);

#[derive(Clone, Debug)]
pub struct Inode {
    tp: FileType,
    // last valid ancestor's inode in RW layer
    // if ipos[0] is RW layer, all ancestor and itself is present,
    // then rw_fiid is the same as this inode id, i.e. ipos[0]'s iid,
    rw_fiid: InodeID,
    // last valid ancestor's idx in full_path
    rw_fidx: isize,
    // full path from root dir, with perm, uid, gid
    full_path: Vec<(String, FilePerm, u32, u32)>,
    // existing inodes in the lower layers
    // for reg and sym, len is only 1
    ipos: Vec<InodePos>,
    // if true, same names in lower layers are blacked out
    // only useful when ipos[0] is RW layer
    // actually only useful for dirs, but set for reg and sym, too
    black_out_ro: bool,
    // cached dir entries: all children here are allocated an iid and sotred in icac
    // useful only for dirs
    children: Option<BTreeMap<String, (FileType, InodeID)>>,
}

// impl Inode {
//     fn add_child(&mut self, name: &str, tp: FileType, iid: InodeID) {
//         let (map, l) = self.children.as_mut().unwrap();
//         map.insert(name.into(), l.len());
//         l.push((name.into(), tp, iid));
//     }
//
//     fn remove_child(&mut self, name: &str) -> (String, FileType, InodeID) {
//         let (map, l) = self.children.as_mut().unwrap();
//         let idx = map.remove(&String::from(name)).unwrap();
//         l.remove(idx)
//     }
//
//     fn find_child(&self, name: &str) -> Option<(String, FileType, InodeID)> {
//         let (map, l) = self.children.as_ref().unwrap();
//         map.iter().find(
//             |(pb, _)| pb.as_os_str() == name
//         ).map(
//             |(_, &idx)| {
//                 l[idx].clone()
//             }
//         )
//     }
//
//     fn list_child(&self, offset: usize, num: usize) -> Vec<(String, FileType, InodeID)> {
//         let (_, l) = self.children.as_ref().unwrap();
//         let end = if num == 0 {
//             l.len()
//         } else {
//             l.len().min(offset + num)
//         };
//         l[offset..end].iter().map(
//             |x| x.clone()
//         ).collect()
//     }
// }

const RW_LAYER_IDX: usize = 0;

pub struct OverlayFS {
    /// filesystem layers, 0 is RW layer
    layers: Vec<RwLock<Box<dyn FileSystem>>>,
    /// inode cache, all found inodes are here, second number is next_iid
    icac: RwLock<(BTreeMap<InodeID, Inode>, InodeID)>,
}

const BLACK_OUT_PREFIX: &str = ".blacked.";

fn black_out_file_of(name: &str) -> String {
    alloc::format!("{}{}", BLACK_OUT_PREFIX, name)
}

fn is_black_out_file(name: &str) -> bool {
    name.starts_with(BLACK_OUT_PREFIX)
}

fn rm_black_out_prefix(name: &str) -> String {
    name[BLACK_OUT_PREFIX.len()..].to_string()
}

impl OverlayFS {
    pub fn new(
        upper: Box<dyn FileSystem>,
        mut lower: Vec<Box<dyn FileSystem>>,
    ) -> FsResult<Self> {
        // prepare root dir
        lower.insert(RW_LAYER_IDX, upper);
        let layers = lower;

        let mut ipos = Vec::new();
        for (i, layer) in layers.iter().enumerate() {
            let meta = layer.get_meta(ROOT_INODE_ID)?;
            if meta.ftype != FileType::Dir {
                return Err(new_error!(FsError::NotADirectory));
            }
            ipos.push(InodePos(i, ROOT_INODE_ID));
        }

        let root_inode = Inode {
            tp: FileType::Dir,
            rw_fiid: ROOT_INODE_ID,
            rw_fidx: -1,
            full_path: Vec::new(),
            ipos,
            black_out_ro: false, // root inode of lower layers must not be blacked
            children: None,
        };

        let mut map = BTreeMap::new();
        map.insert(ROOT_INODE_ID, root_inode);


        Ok(Self {
            layers: layers.into_iter().map(
                |fs| RwLock::new(fs)
            ).collect(),
            icac: RwLock::new((map, 2)),
        })
    }

    #[allow(unused)]
    fn insert_inode(&self, inode: Inode) -> FsResult<InodeID> {
        let mut lock = self.icac.write();
        self.insert_inode_with_lock(&mut lock, inode)
    }

    fn insert_inode_with_lock(
        &self,
        lock: &mut RwLockWriteGuard<(BTreeMap<u64, Inode>, u64)>,
        inode: Inode
    ) -> FsResult<InodeID> {
        let iid = lock.1;
        // debug!("insert inode {iid}");
        lock.1 += 1;
        assert!(lock.0.insert(iid, inode).is_none());
        Ok(iid)
    }

    // for reg and sym, copy file content
    // for dir, create new dir in RW only
    fn ensure_copy_up(&self, iid: InodeID) -> FsResult<()> {
        let mut lock = self.icac.write();
        let ino = lock.0.get_mut(&iid).unwrap();

        if ino.rw_fidx == ino.full_path.len() as isize - 1 {
            return Ok(())
        }

        // crate all intermediate dirs
        let mut idx = ino.rw_fidx + 1;
        let mut father = ino.rw_fiid;
        let rwfs_lock = self.layers[RW_LAYER_IDX].read();
        while idx < ino.full_path.len() as isize - 1 {
            let path = &ino.full_path[idx as usize];
            match rwfs_lock.create(
                father,
                &path.0,
                FileType::Dir,
                path.2,
                path.3,
                path.1,
            ) {
                Ok(new_iid) => father = new_iid,
                // Err(FsError::AlreadyExists) => {},
                Err(e) => return Err(e),
            }
            idx += 1;
        }

        let path = &ino.full_path[idx as usize];
        let new_iid = rwfs_lock.create(
            father,
            &path.0,
            ino.tp,
            path.2,
            path.3,
            path.1,
        )?;

        match ino.tp {
            FileType::Reg => {
                assert_eq!(ino.ipos.len(), 1);
                let InodePos(lidx, innd) = ino.ipos[0];
                let mut buf = [0u8; BLK_SZ];
                let mut done = 0;
                loop {
                    let read = self.layers[lidx].read().iread(innd, done, &mut buf)?;
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
                let lname = self.layers[lidx].read().iread_link(innd)?;
                rwfs_lock.iset_link(new_iid, &lname)?;
                ino.ipos[0] = InodePos(RW_LAYER_IDX, new_iid);
            }
        }

        ino.rw_fidx = ino.full_path.len() as isize - 1;
        ino.rw_fiid = new_iid;

        Ok(())
    }

    fn ensure_black_out_file(
        &self,
        fs: &RwLockReadGuard<'_, Box<dyn FileSystem>>,
        parent: InodeID,
        name: &str,
    ) -> FsResult<()> {
        let blk_name = black_out_file_of(name);
        if fs.lookup(parent, &blk_name)?.is_none() {
            let Metadata { uid, gid, .. } = fs.get_meta(parent)?;
            fs.create(
                parent, &blk_name,
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
        let mut lock = self.icac.write();

        let parent_ino = {
            let parent = lock.0.get(&iid).unwrap();
            if parent.tp != FileType::Dir {
                return Err(FsError::NotADirectory);
            }

            if parent.children.is_some() {
                // debug!("children already cached");
                return Ok(())
            }

            parent.clone()
        };

        // debug!("caching children of parent: {:?}", parent_ino);

        let mut blk_out_files = BTreeSet::new();
        let mut map = BTreeMap::new();
        for InodePos(lidx, innd) in parent_ino.ipos.iter().filter(
            |InodePos(lidx, _)| *lidx == RW_LAYER_IDX || !parent_ino.black_out_ro
        ) {
            let fs = self.layers[*lidx].read();
            // debug!("processing layer {} innd {}", lidx, innd);

            let mut offset = 0;
            while let Some((child_innd, name, tp)) = fs.next_entry(*innd, offset)? {
                // debug!("child {} innd {} tp {:?}", name.display(), child_innd, tp);
                if *lidx == RW_LAYER_IDX && is_black_out_file(name.as_str()) {
                    // debug!("is black out file, remember it");
                    blk_out_files.insert(rm_black_out_prefix(&name));
                } else if let Some((upper_tp, iid)) = map.get(&name) {
                    // if a child already found in upper layers and it's a dir
                    // we need to add this layer to ipos list
                    // debug!("already exist in upper");
                    if tp == FileType::Dir && *upper_tp == FileType::Dir {
                        // debug!("is dir, update ipos");
                        let ino = lock.0.get_mut(iid).unwrap();
                        ino.ipos.push(InodePos(*lidx, child_innd));
                    }
                } else {
                    // create inode in icac
                    // debug!("first found, creating new ovl inode");
                    let Metadata { uid, gid, perm, .. } = fs.get_meta(child_innd)?;

                    let black_out_ro = if *lidx == RW_LAYER_IDX {
                        parent_ino.black_out_ro | blk_out_files.contains(&name)
                    } else {
                        false
                    };
                    // debug!("black_out_ro = {}", black_out_ro);

                    let mut full_path = parent_ino.full_path.clone();
                    full_path.push((name.clone().into(), perm, uid, gid));

                    let (rw_fiid, rw_fidx) = {
                        if *lidx == RW_LAYER_IDX {
                            // debug!("at rw layer, all ancestors exists");
                            // actually is parent has a RW layer,
                            // parent.rw_fiid == *innd must hold
                            assert_eq!(parent_ino.rw_fiid, *innd);
                            (child_innd, full_path.len() as isize - 1)
                        } else {
                            // debug!("at ro layer, inherit parent rw_fiid");
                            (parent_ino.rw_fiid, parent_ino.rw_fidx)
                        }
                    };

                    let mut ipos = Vec::new();
                    ipos.push(InodePos(*lidx, child_innd));
                    let new_ino = Inode {
                        tp,
                        rw_fiid,
                        rw_fidx,
                        full_path,
                        ipos,
                        black_out_ro,
                        children: None,
                    };
                    let new_iid = self.insert_inode_with_lock(&mut lock, new_ino)?;
                    map.insert(name.clone(), (tp, new_iid));
                }
                offset += 1;
            }
        }

        // store in parent inode
        lock.0.get_mut(&iid).unwrap().children = Some(map);

        Ok(())
    }
}

macro_rules! allow_nosys {
    ($res: expr) => {
        match $res {
            Ok(_) | Err(FsError::NotSupported) => {},
            Err(e) => return Err(e),
        }
    }
}

impl FileSystem for OverlayFS {
    fn init(&self) -> FsResult<()> {
        for fs in self.layers.iter() {
            fs.read().init()?;
        }
        Ok(())
    }

    fn destroy(&mut self) -> FsResult<FSMode> {
        for fs in self.layers[1..].iter() {
            fs.write().destroy()?;
        }
        self.layers[RW_LAYER_IDX].write().destroy()
    }

    fn finfo(&self) -> FsResult<FsInfo> {
        let mut info = self.layers[RW_LAYER_IDX].read().finfo()?;
        for fs in self.layers[1..].iter() {
            let FsInfo {
                blocks,
                bfree,
                files,
                namemax,
                ..
            } = fs.read().finfo()?;
            info.blocks += blocks;
            info.bfree += bfree;
            info.files += files;
            info.namemax = info.namemax.min(namemax);
        }
        Ok(info)
    }

    fn fsync(&mut self) -> FsResult<()> {
        for fs in self.layers.iter().rev() {
            fs.write().fsync()?;
        }
        Ok(())
    }

    fn iread(&self, iid: InodeID, offset: usize, to: &mut [u8]) -> FsResult<usize> {
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Reg);
        let InodePos(lidx, innd) = ino.ipos[0];
        self.layers[lidx].read().iread(innd, offset, to)
    }

    fn iwrite(&self, iid: InodeID, offset: usize, from: &[u8]) -> FsResult<usize> {
        self.ensure_copy_up(iid)?;
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Reg);
        let InodePos(lidx, innd) = ino.ipos[0];
        assert_eq!(lidx, RW_LAYER_IDX);
        self.layers[lidx].read().iwrite(innd, offset, from)
    }

    fn get_meta(&self, iid: InodeID) -> FsResult<Metadata> {
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        let InodePos(lidx, innd) = ino.ipos[0];
        match ino.tp {
            FileType::Reg | FileType::Lnk => {
                let mut meta = self.layers[lidx].read().get_meta(innd)?;
                meta.iid = iid;
                Ok(meta)
            }
            FileType::Dir => {
                let InodePos(top_lidx, top_innd) = ino.ipos[0].clone();
                let mut meta = self.layers[top_lidx].read().get_meta(top_innd)?;
                meta.iid = iid;
                meta.ftype = FileType::Dir;
                for InodePos(lidx, innd) in ino.ipos.iter().skip(1) {
                    let mt = self.layers[*lidx].read().get_meta(*innd)?;
                    meta.size += mt.size;
                    meta.blocks += mt.blocks;
                }
                Ok(meta)
            }
        }
    }

    fn set_meta(&self, iid: InodeID, set_meta: SetMetadata) -> FsResult<()> {
        self.ensure_copy_up(iid)?;
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        let InodePos(lidx, innd) = ino.ipos[0];
        assert_eq!(lidx, RW_LAYER_IDX);
        self.layers[lidx].read().set_meta(innd, set_meta)?;
        Ok(())
    }

    fn iread_link(&self, iid: InodeID) -> FsResult<String> {
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Lnk);
        let InodePos(lidx, innd) = ino.ipos[0];
        self.layers[lidx].read().iread_link(innd)
    }

    fn iset_link(&self, iid: InodeID, new_lnk: &str) -> FsResult<()> {
        self.ensure_copy_up(iid)?;
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Lnk);
        let InodePos(lidx, innd) = ino.ipos[0];
        assert_eq!(lidx, RW_LAYER_IDX);
        self.layers[lidx].read().iset_link(innd, new_lnk)?;
        Ok(())
    }

    fn isync_meta(&self, iid: InodeID) -> FsResult<()> {
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        match ino.tp {
            FileType::Reg | FileType::Lnk => {
                let InodePos(lidx, innd) = ino.ipos[0];
                self.layers[lidx].read().isync_meta(innd)
            }
            FileType::Dir => {
                for InodePos(lidx, innd) in ino.ipos.iter() {
                    self.layers[*lidx].read().isync_meta(*innd)?;
                }
                Ok(())
            }
        }
    }

    fn isync_data(&self, iid: InodeID) -> FsResult<()> {
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        match ino.tp {
            FileType::Reg | FileType::Lnk => {
                let InodePos(lidx, innd) = ino.ipos[0];
                allow_nosys!(self.layers[lidx].read().isync_data(innd));
            }
            FileType::Dir => {
                for InodePos(lidx, innd) in ino.ipos.iter() {
                    allow_nosys!(self.layers[*lidx].read().isync_data(*innd));
                }
            }
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
        if is_black_out_file(name) {
            return Err(new_error!(FsError::PermissionDenied));
        }
        if self.lookup(parent, name)?.is_some() {
            return Err(new_error!(FsError::AlreadyExists));
        }

        self.ensure_children_cached(parent)?;
        self.ensure_copy_up(parent)?;

        let mut lock = self.icac.write();
        let ino = lock.0.get_mut(&parent).unwrap().clone();
        assert_eq!(ino.tp, FileType::Dir);

        let InodePos(lidx, innd) = ino.ipos[0];
        let (new_innd, blk_out_file_exist) = {
            let lock = self.layers[lidx].read();
            (
                lock.create(innd, name, ftype, uid, gid, perm)?,
                lock.lookup(innd, black_out_file_of(name).as_str())?.is_some()
            )
        };

        let mut full_path = ino.full_path.clone();
        full_path.push((name.into(), perm, uid, gid));
        let mut ipos = Vec::new();
        ipos.push(InodePos(RW_LAYER_IDX, new_innd));
        let new_ino = Inode {
            tp: ftype,
            rw_fiid: new_innd,
            rw_fidx: full_path.len() as isize - 1,
            full_path,
            // create sth means this name does not exist in any lower layers,
            // or it is blacked out, so the new overlay inode has no lower layers
            ipos,
            black_out_ro: ino.black_out_ro | blk_out_file_exist,
            children: None,
        };

        let new_iid = self.insert_inode_with_lock(&mut lock, new_ino)?;

        let ino = lock.0.get_mut(&parent).unwrap();
        ino.children.as_mut().unwrap().insert(name.into(), (ftype, new_iid));

        Ok(new_iid)
    }

    fn link(&self, parent: InodeID, name: &str, linkto: InodeID) -> FsResult<()> {
        if is_black_out_file(name) {
            return Err(new_error!(FsError::PermissionDenied));
        }
        if self.lookup(parent, name)?.is_some() {
            return Err(new_error!(FsError::AlreadyExists));
        }

        self.ensure_copy_up(parent)?;
        self.ensure_copy_up(linkto)?;
        self.ensure_children_cached(parent)?;

        let mut lock = self.icac.write();
        let to = lock.0.get(&linkto).unwrap();
        let tp = to.tp;
        if tp == FileType::Dir {
            return Err(new_error!(FsError::IsADirectory));
        }
        let InodePos(to_lidx, to_innd) = to.ipos[0].clone();
        assert_eq!(to_lidx, RW_LAYER_IDX);

        let fino = lock.0.get_mut(&parent).unwrap();
        let InodePos(f_lidx, f_innd) = fino.ipos[0].clone();
        assert_eq!(f_lidx, RW_LAYER_IDX);

        self.layers[f_lidx].read().link(f_innd, name, to_innd)?;

        fino.children.as_mut().unwrap().insert(name.into(), (tp, linkto));

        Ok(())
    }

    fn unlink(&self, parent: InodeID, name: &str) -> FsResult<()> {
        if is_black_out_file(name) {
            return Err(new_error!(FsError::PermissionDenied));
        }

        self.ensure_copy_up(parent)?;
        self.ensure_children_cached(parent)?;

        let child_iid = self.lookup(parent, name)?.ok_or_else(
            || new_error!(FsError::NotFound)
        )?;

        let mut lock = self.icac.write();
        let fino = lock.0.get(&parent).unwrap();
        let InodePos(lidx, innd) = fino.ipos[0].clone();
        assert_eq!(lidx, RW_LAYER_IDX);

        let fs = self.layers[lidx].read();
        match fs.unlink(innd, name) {
            Ok(_) | Err(FsError::NotFound) => {
            // Ok(_) => {
                self.ensure_black_out_file(&fs, innd, name)?;
                // set black out ro
                let ino = lock.0.get_mut(&child_iid).unwrap();
                ino.black_out_ro = true;
            }
            Err(e) => return Err(e),
        }

        let fino = lock.0.get_mut(&parent).unwrap();
        fino.children.as_mut().unwrap().remove(&String::from(name));

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
        if is_black_out_file(name) {
            return Err(new_error!(FsError::PermissionDenied));
        }
        if self.lookup(parent, name)?.is_some() {
            return Err(new_error!(FsError::AlreadyExists));
        }

        self.ensure_copy_up(parent)?;
        self.ensure_children_cached(parent)?;

        let mut lock = self.icac.write();
        let ino = lock.0.get_mut(&parent).unwrap().clone();

        let InodePos(lidx, innd) = ino.ipos[0].clone();
        assert_eq!(lidx, RW_LAYER_IDX);
        let (new_innd, blk_out_file_exist) = {
            let lock = self.layers[lidx].read();
            (
                lock.symlink(innd, name, to, uid, gid)?,
                lock.lookup(innd, black_out_file_of(name).as_str())?.is_some()
            )
        };

        let mut full_path = ino.full_path.clone();
        full_path.push((name.into(), FilePerm::from_bits(0o777).unwrap(), uid, gid));
        let mut ipos = Vec::new();
        ipos.push(InodePos(RW_LAYER_IDX, new_innd));
        let new_ino = Inode {
            tp: FileType::Lnk,
            rw_fiid: new_innd,
            rw_fidx: full_path.len() as isize - 1,
            full_path,
            ipos,
            black_out_ro: ino.black_out_ro | blk_out_file_exist,
            children: None,
        };

        let new_iid = self.insert_inode_with_lock(&mut lock, new_ino)?;

        let ino = lock.0.get_mut(&parent).unwrap();
        ino.children.as_mut().unwrap().insert(name.into(), (FileType::Lnk, new_iid));

        Ok(new_iid)
    }

    fn rename(
        &self,
        from: InodeID, name: &str,
        to: InodeID, newname: &str
    ) -> FsResult<()> {
        if is_black_out_file(name) {
            return Err(new_error!(FsError::PermissionDenied));
        }
        if is_black_out_file(newname) {
            return Err(new_error!(FsError::PermissionDenied));
        }

        let old_iid = if let Some(old_iid) = self.lookup(from, name)? {
            let lock = self.icac.read();
            let old_ino = lock.0.get(&old_iid).unwrap();
            // refuse to move a dir with children in RO layers
            if old_ino.tp == FileType::Dir && self.dir_has_ro_layer(old_ino) {
                return Err(new_error!(FsError::PermissionDenied));
            }
            old_iid
        } else {
            return Err(new_error!(FsError::NotFound));
        };

        self.ensure_copy_up(from)?;
        self.ensure_copy_up(to)?;
        self.ensure_children_cached(from)?;
        self.ensure_children_cached(to)?;

        self.ensure_copy_up(old_iid)?;

        let mut lock = self.icac.write();
        let from_ino = lock.0.get_mut(&from).unwrap();
        assert_eq!(from_ino.tp, FileType::Dir);
        let InodePos(from_lidx, from_innd) = from_ino.ipos[0].clone();
        assert_eq!(from_lidx, RW_LAYER_IDX);
        let fs = self.layers[from_lidx].read();

        // remove cached old child
        let from_children = from_ino.children.as_mut().unwrap();
        let entry = from_children.remove(&String::from(name)).unwrap();

        let (to_innd, to_ino) = if from == to {
            // from and to are same dir
            (from_innd, from_ino)
        } else {
            // from and to are different dir
            let to_ino = lock.0.get_mut(&to).unwrap();
            assert_eq!(to_ino.tp, FileType::Dir);
            let InodePos(to_lidx, to_innd) = to_ino.ipos[0].clone();
            assert_eq!(to_lidx, RW_LAYER_IDX);

            (to_innd, to_ino)
        };
        fs.rename(from_innd, name, to_innd, newname)?;

        // add new cached child
        to_ino.children.as_mut().unwrap().insert(String::from(newname), entry);

        // create black out file for oldname
        self.ensure_black_out_file(&fs, from_innd, name)?;
        // set black out ro
        let ino = lock.0.get_mut(&old_iid).unwrap();
        ino.black_out_ro = true;

        Ok(())
    }

    fn lookup(&self, iid: InodeID, name: &str) -> FsResult<Option<InodeID>> {
        self.ensure_children_cached(iid)?;

        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();

        let ret = ino.children.as_ref().unwrap().iter().find(
            |(pb, _)| pb.as_str() == name
        ).map(
            |(_, (_, iid))| *iid
        );

        // debug!("lookup return {:?}", ret);

        Ok(ret)
    }

    fn listdir(
        &self, iid: InodeID, offset: usize, num: usize,
    ) -> FsResult<Vec<(InodeID, String, FileType)>> {
        self.ensure_children_cached(iid)?;

        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();

        let mut ret = Vec::new();
        for (name, (tp, iid)) in ino.children.as_ref().unwrap().iter().skip(offset) {
            ret.push((*iid, name.clone(), *tp));
            if num != 0 && ret.len() >= num {
                break;
            }
        }

        // debug!("listdir return {:?}", ret);

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
        let lock = self.icac.read();
        let ino = lock.0.get(&iid).unwrap();
        assert_eq!(ino.tp, FileType::Reg);
        let InodePos(lidx, innd) = ino.ipos[0];
        assert_eq!(lidx, RW_LAYER_IDX);
        self.layers[lidx].read().fallocate(innd, mode, offset, len)?;
        Ok(())
    }
}
