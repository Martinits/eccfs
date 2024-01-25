use std::sync::Arc;
use crate::bcache::*;
use crate::*;
use crate::crypto::*;
use crate::storage::RWStorage;
use std::collections::HashMap;
use super::*;


// if ke_buf size exceeds 1/ratio of cache size, a flush is needed
const RW_KE_BUF_CAP_RATIO: usize = 2;

// data block is forced to be cached due to write back issues
// need to lock this whole struct
pub struct RWHashTree {
    // in rw, every htree has its own cache
    cache: RWCache,
    backend: Box<dyn RWStorage>,
    pub logi_len: u64, // logical size, in blocks
    encrypted: bool,
    root_mode: FSMode,
    ke_buf: HashMap<u64, KeyEntry>,
    key_gen: KeyGen,
}

impl RWHashTree {
    pub fn new(
        cache_cap_hint: Option<usize>,
        backend: Box<dyn RWStorage>,
        length: u64,
        root_mode: Option<FSMode>,
        encrypted: bool,
    ) -> Self {
        if length == 0 {
            assert!(root_mode.is_none());
        }

        Self {
            cache: RWCache::new(
                cache_cap_hint.unwrap_or(rw_cache_cap_defaults(length as usize))
            ),
            backend,
            logi_len: length,
            encrypted,
            root_mode: root_mode.unwrap_or(FSMode::new_zero(encrypted)),
            ke_buf: HashMap::new(),
            key_gen: KeyGen::new(),
        }
    }

    pub fn get_cur_mode(&self) -> FSMode {
        self.root_mode.clone()
    }

    pub fn resize(&mut self, nr_blk: u64) -> FsResult<()> {
        // debug!("resize to {}", nr_blk);

        let new_phy_nr_blk = mht::get_phy_nr_blk(nr_blk);
        // if the htree is cut, there should be invalid ke that points to somewhere over length
        // but it's ok, since we don't check anything over length
        self.backend.set_len(new_phy_nr_blk)?;

        if nr_blk < self.logi_len {
            if nr_blk == 0 {
                self.root_mode = FSMode::new_zero(self.encrypted);
            }
            self.logi_len = nr_blk;
            // flush all blocks beyond new length that is cached
            for k in self.cache.flush_keys()?.into_iter().filter(|k| *k>=new_phy_nr_blk) {
                self.cache.flush_key(k)?;
            }
            return Ok(());
        }

        let mut idx_pos = 0;
        let mut idx_blk = None;
        let mut idx_blk_next_idx = 0;
        for pos in mht::get_phy_nr_blk(self.logi_len)..new_phy_nr_blk {
            if mht::is_idx(pos) {
                if let Some(blk) = idx_blk {
                    let ke = self.backend_write(idx_pos, blk)?.into_key_entry();
                    self.buffer_ke(idx_pos, ke)?;
                }
                idx_blk = Some([0u8; BLK_SZ]);
                idx_pos = pos;
                idx_blk_next_idx = 0;
            } else {
                let ke = self.backend_write(pos, [0u8; BLK_SZ])?.into_key_entry();
                if let Some(idx) = &mut idx_blk {
                    assert!(idx_blk_next_idx < mht::DATA_PER_BLK);
                    mht::set_ke(idx, mht::Data(idx_blk_next_idx), &ke)?;
                    idx_blk_next_idx += 1;
                } else {
                    // idx block already exists
                    self.buffer_ke(pos, ke)?;
                }
            }
        }
        if let Some(blk) = idx_blk {
            let ke = self.backend_write(idx_pos, blk)?.into_key_entry();
            self.buffer_ke(idx_pos, ke)?;
        }

        // reset htree length
        self.logi_len = nr_blk;

        self.possible_flush_ke_buf()?;

        Ok(())
    }

    pub fn zero_range(&mut self, offset: usize, len: usize) -> FsResult<()> {
        let org_len = blk2byte!(self.logi_len) as usize;

        let end = (offset + len).div_ceil(BLK_SZ);
        self.resize(end.div_ceil(BLK_SZ) as u64)?;

        if offset >= org_len {
            return Ok(())
        }

        let end = end.min(org_len);

        let start = { // in blocks
            if offset % BLK_SZ != 0 {
                let len = BLK_SZ - offset % BLK_SZ;
                assert_eq!(self.write_exact(offset, &vec![0u8; len])?, len);
            }
            mht::get_phy_nr_blk(offset.div_ceil(BLK_SZ) as u64)
        };
        let end = { // in blocks
            if end % BLK_SZ != 0 {
                let len = end % BLK_SZ;
                assert_eq!(self.write_exact(end - len, &vec![0u8; len])?, len);
            }
            mht::get_phy_nr_blk((end / BLK_SZ) as u64)
        };


        // now zero blocks in (start..end) which is not newly padded
        for pos in start..end {
            if !mht::is_idx(pos) {
                if let Some(apay) = self.cache.get_blk_try(pos)? {
                    rwlock_write!(apay).fill(0);
                    self.cache.mark_dirty(pos)?;
                } else {
                    self.write_back(pos, [0u8; BLK_SZ])?;
                }
            }
        }

        self.possible_flush_ke_buf()?;

        Ok(())
    }

    // pos is by block
    pub fn get_blk(&mut self, pos: u64, write: bool) -> FsResult<Option<Arc<RWPayLoad>>> {
        // debug!("get blk {}", pos);
        if pos >= self.logi_len {
            if !write {
                return Ok(None);
            }
            // pad file length to pos + 1
            self.resize(pos + 1)?;
        }

        let data_phy = mht::logi2phy(pos);
        if let Some(apay) = self.cache.get_blk_try(data_phy)? {
            if write {
                self.cache.mark_dirty(data_phy)?;
            }
            return Ok(Some(apay))
        }

        // data blk not cached
        let mut idx_stack = Vec::new();
        let mut idxphy = mht::phy2idxphy(data_phy);
        idx_stack.push((mht::logi2dataidx(pos), data_phy));

        let first_cached_idx = {
            // find backward through the tree to the first cached idx blk
            let mut safe_cnt = 0;
            loop {
                if safe_cnt >= MAX_LOOP_CNT {
                    panic!("Loop exceeds MAX count!");
                } else if let Some(apay) = self.cache.get_blk_try(idxphy)? {
                    break apay;
                } else if idxphy == HTREE_ROOT_BLK_PHY_POS {
                    // root blk is not cached
                    break self.cache_miss(idxphy, self.root_mode.clone())?;
                } else {
                    let (father, child_idx) = mht::idxphy2father(idxphy);
                    idx_stack.push((child_idx, idxphy));
                    idxphy = father;
                }
                safe_cnt += 1;
            }
        };

        // down the tree, use child_idx to get next idx blk, then final data blk
        let mut cur_apay = first_cached_idx;
        while !idx_stack.is_empty() {
            let (child_idx, child_phy) = idx_stack.pop().unwrap();
            // try get ke from ke_buf
            let ke = if let Some(ke) = self.ke_buf.remove(&child_phy) {
                ke
            } else {
                let lock = rwlock_read!(cur_apay);
                mht::get_ke(
                    &lock,
                    // if this is the last index, it's an data block
                    if idx_stack.is_empty() {
                        mht::Data(child_idx)
                    } else {
                        mht::Index(child_idx)
                    }
                )
            };
            let mode = FSMode::from_key_entry(ke, self.encrypted);
            cur_apay = self.cache_miss(child_phy, mode)?;
        }

        // mark dirty
        if write {
            self.cache.mark_dirty(mht::logi2phy(pos))?;
        }

        Ok(Some(cur_apay))
    }

    fn cache_miss(
        &mut self, pos: u64, mode: FSMode
    ) -> FsResult<Arc<RWPayLoad>> {
        // debug!("cache miss {}", pos);
        let mut blk = self.backend_read(pos, mode)?;
        let dirty = self.possible_ke_wb(pos, &mut blk)?;

        let (apay, wb) = self.cache.insert_and_get(pos, blk)?;
        if dirty {
            self.cache.mark_dirty(pos)?;
        }

        if let Some((pos, blk)) = wb {
            // need write back
            self.write_back(pos, blk)?;
        }
        Ok(apay)
    }

    fn write_back(&mut self, pos: u64, mut blk: Block) -> FsResult<()> {
        // debug!("write back {pos}");
        // debug!("ke_buf before wb: {:?}", self.ke_buf.keys().collect::<Vec<_>>());
        assert_eq!(self.possible_ke_wb(pos, &mut blk)?, false);

        let mode = self.backend_write(pos, blk)?;

        // ke changes, try to write back into father
        self.buffer_ke(pos, mode.into_key_entry())?;
        Ok(())
    }

    fn backend_read(&mut self, pos: u64, mode: FSMode) -> FsResult<Block> {
        let mut blk = self.backend.read_blk(pos)?;
        crypto_in(&mut blk, CryptoHint::from_fsmode(mode, pos))?;
        Ok(blk)
    }

    fn backend_write(
        &mut self, pos: u64, mut blk: Block,
    ) -> FsResult<FSMode> {
        let mode = crypto_out(
            &mut blk,
            if self.encrypted {
                // generate new aes key on every write_back
                Some(self.key_gen.gen_key(pos)?)
            } else {
                None
            },
            pos
        )?;
        self.backend.write_blk(pos, &blk)?;
        Ok(mode)
    }

    pub fn read_exact(&mut self, mut offset: usize, to: &mut [u8]) -> FsResult<usize> {
        assert!(offset + to.len() <= blk2byte!(self.logi_len) as usize);

        let total = to.len();
        let mut done = 0;
        while done < total {
            let apay = self.get_blk(
                ( offset / BLK_SZ ) as u64, false
            )?.ok_or_else(|| new_error!(FsError::IncompatibleMetadata))?;
            let round = (total - done).min(BLK_SZ - offset % BLK_SZ);
            let start = offset % BLK_SZ;
            to[done..done+round].copy_from_slice(
                &rwlock_read!(apay)[start..start+round]
            );
            done += round;
            offset += round;
        }
        Ok(done)
    }

    pub fn write_exact(&mut self, mut offset: usize, from: &[u8]) -> FsResult<usize> {
        let total = from.len();
        let mut done = 0;
        while done < total {
            let apay = self.get_blk(
                ( offset / BLK_SZ ) as u64, true
            )?.unwrap();
            let round = (total - done).min(BLK_SZ - offset % BLK_SZ);
            let start = offset % BLK_SZ;
            rwlock_write!(apay)[start..start+round].copy_from_slice(
                &from[done..done+round]
            );
            done += round;
            offset += round;
        }

        Ok(done)
    }

    // flush all blocks including root
    pub fn flush(&mut self) -> FsResult<FSMode> {
        // debug!("Flush htree");
        let mut keys = self.cache.flush_keys()?;
        // write back from big pos to small pos,
        // to increase possibility of ke write back
        keys.sort();
        for k in keys {
            if let Some(blk) = self.cache.flush_key(k)? {
                // write back if dirty
                self.write_back(k, blk)?;
            }
        }

        self.flush_ke_buf()?;

        Ok(self.root_mode.clone())
    }

    // this function does not modify cache (but maybe cached blocks)
    fn flush_ke_buf(&mut self) -> FsResult<()> {
        if self.ke_buf.len() == 0 {
            return Ok(());
        }

        // let mut cache_keys = self.cache.flush_keys()?;
        // cache_keys.sort();
        // debug!("cache keys: {:?}", cache_keys);
        // let mut keys = self.ke_buf.keys().collect::<Vec<_>>();
        // keys.sort();
        // debug!("Flush ke buf");
        // debug!("ke_buf: {:?}", keys);
        let mut buf: HashMap<_, Vec<_>> = HashMap::new();
        for (pos, ke) in mem::take(&mut self.ke_buf) {
            let (f, idx) = mht::get_father_idx(pos);
            if let Some(v) = buf.get_mut(&f) {
                v.push((idx, ke));
            } else {
                assert!(buf.insert(f, vec![(idx, ke)]).is_none());
            }
        }
        // debug!("buf: {:?}", buf.iter().map(
        //     |(k, v)| (k, v.iter().map(|x|x.0.clone()).collect::<Vec<_>>())
        // ).collect::<Vec<_>>());

        macro_rules! write_ke_list {
            ($blk: expr, $ke_list: expr) => {
                for (idx, ke) in $ke_list {
                    mht::set_ke(&mut $blk, idx.clone(), &ke)?;
                }
            };
        }

        // pin root block
        let mut root_blk = if self.cache.get_blk_try(HTREE_ROOT_BLK_PHY_POS)?.is_some() {
            // root already cached
            None
        } else {
            Some(self.backend_read(HTREE_ROOT_BLK_PHY_POS, self.root_mode.clone())?)
        };

        let mut keys: Vec<_> = buf.keys().map(
            |k| *k
        ).collect();
        keys.sort();

        for pos in keys.into_iter().rev() {
            let ke_list = buf.remove(&pos);
            if ke_list.is_none() {
                continue;
            }
            let ke_list = ke_list.unwrap();

            if let Some(apay) = self.cache.get_blk_try(pos)? {
                // cached just write, do not handle new ke
                let mut lock = rwlock_write!(apay);
                write_ke_list!(&mut lock, ke_list);
                self.cache.mark_dirty(pos)?;
                continue;
            }

            // not cached
            let mut idxphy = pos;
            let mut idx_stack = Vec::new();

            let mut last_ke_dest = None;
            // find backward through the tree to the first cached idx blk
            // return first not cached block
            let (first_not_cached, mode) = loop {
                if let Some(apay) = self.cache.get_blk_try(idxphy)? {
                    // a cache block should not have any pending ke in ke_buf
                    // let ret = buf.remove(&idxphy);
                    // if ret.is_some() {
                    //     panic!("phy {} have childs ke {:?} not wb",
                    //         idxphy,
                    //     ret.as_ref().unwrap().iter().map(|x| x.0.clone()).collect::<Vec<_>>());
                    // }
                    assert!(buf.remove(&idxphy).is_none());

                    let (child_idx, child_phy) = idx_stack.pop().unwrap();
                    last_ke_dest = Some((idxphy, apay.clone(), child_idx));

                    let ke = {
                        let lock = rwlock_read!(apay);
                        mht::get_ke(
                            &lock,
                            // must be index
                            mht::Index(child_idx)
                        )
                    };
                    break (child_phy, FSMode::from_key_entry(ke, self.encrypted));
                } else if idxphy == HTREE_ROOT_BLK_PHY_POS {
                    // root blk is not cached
                    break (idxphy, self.root_mode.clone());
                } else {
                    let (father, child_idx) = mht::idxphy2father(idxphy);
                    idx_stack.push((child_idx, idxphy));
                    idxphy = father;
                }
            };

            let (mut cur_phy, mut cur_mode) = (first_not_cached, mode);
            // down the tree, use child_idx to get next idx blk
            let mut blk_stack = Vec::new();
            while !idx_stack.is_empty() {
                let mut cur_blk = if cur_phy == HTREE_ROOT_BLK_PHY_POS {
                    root_blk.clone().unwrap()
                } else {
                    self.backend_read(cur_phy, cur_mode)?
                };
                if let Some(ke_list) = buf.remove(&cur_phy) {
                    write_ke_list!(cur_blk, ke_list);
                }
                let (child_idx, child_phy) = idx_stack.pop().unwrap();
                blk_stack.push((cur_phy, cur_blk, child_idx));

                // try get ke from ke_buf
                let ke = mht::get_ke(
                    &cur_blk,
                    // must be index
                    mht::Index(child_idx)
                );
                cur_mode = FSMode::from_key_entry(ke, self.encrypted);
                cur_phy = child_phy;
            }

            assert!(pos == cur_phy);

            // get "pos" and write ke
            if cur_phy == HTREE_ROOT_BLK_PHY_POS {
                write_ke_list!(root_blk.as_mut().unwrap(), ke_list);
                continue;
            }
            let mut cur_blk = self.backend_read(cur_phy, cur_mode)?;
            write_ke_list!(cur_blk, ke_list);

            // write back "pos"
            let mut ke = self.backend_write(cur_phy, cur_blk)?.into_key_entry();

            // write back blk_stack
            for (pos, mut blk, child_idx) in blk_stack.into_iter().rev() {
                mht::set_ke(&mut blk, mht::Index(child_idx), &ke)?;
                if pos == HTREE_ROOT_BLK_PHY_POS {
                    assert!(root_blk.is_some());
                    root_blk = Some(blk);
                    break;
                } else {
                    ke = self.backend_write(pos, blk)?.into_key_entry();
                }
            }

            // write last ke to first_cached_idx or root
            if let Some((pos, apay, idx)) = last_ke_dest {
                let mut lock = rwlock_write!(apay);
                mht::set_ke(&mut lock, mht::Index(idx), &ke)?;
                self.cache.mark_dirty(pos)?;
            } else {
                // last ke goes to root
                self.root_mode = FSMode::from_key_entry(ke, self.encrypted);
            }
        }

        // unpin root block and write back
        if let Some(blk) = root_blk {
            self.root_mode = self.backend_write(HTREE_ROOT_BLK_PHY_POS, blk)?;
        }

        Ok(())
    }

    fn buffer_ke(&mut self, pos: u64, ke: KeyEntry) -> FsResult<()> {
        let (father, child_idx) = mht::get_father_idx(pos);
        if let Some(apay) = self.cache.get_blk_try(father)? {
            // debug!("ke of {} goes to cached father {}", pos, father);
            let mut lock = rwlock_write!(apay);
            mht::set_ke(
                &mut lock,
                child_idx,
                &ke,
            )?;
            self.cache.mark_dirty(father)?;
        } else {
            // debug!("buffer ke of {pos}");
            if pos == HTREE_ROOT_BLK_PHY_POS {
                self.root_mode = FSMode::from_key_entry(ke, self.encrypted);
            } else {
                self.ke_buf.insert(pos, ke);
            }
            self.possible_flush_ke_buf()?;
        }
        Ok(())
    }

    fn possible_flush_ke_buf(&mut self) -> FsResult<()> {
        if self.ke_buf.len() >= self.cache.get_cap() / RW_KE_BUF_CAP_RATIO {
            self.flush_ke_buf()?;
        }
        Ok(())
    }

    fn possible_ke_wb(&mut self, pos: u64, blk: &mut Block) -> FsResult<bool> {
        if !mht::is_idx(pos) {
            return Ok(false);
        }

        let mut dirty = false;

        // idx ke
        let mut child_phy = mht::get_first_idx_child_phy(pos);
        for i in 0..mht::CHILD_PER_BLK {
            if let Some(ke) = self.ke_buf.remove(&child_phy) {
                mht::set_ke(
                    blk,
                    mht::Index(i),
                    &ke,
                )?;
                dirty = true;
            }
            child_phy = mht::next_idx_sibling_phy(child_phy);
        }

        // data ke
        let mut child_phy = mht::get_first_data_child_phy(pos);
        for i in 0..mht::DATA_PER_BLK {
            if let Some(ke) = self.ke_buf.remove(&child_phy) {
                mht::set_ke(
                    blk,
                    mht::Data(i),
                    &ke,
                )?;
                dirty = true;
            }
            child_phy = mht::next_data_sibling_phy(child_phy);
        }

        let mut keys = self.ke_buf.keys().collect::<Vec<_>>();
        keys.sort();
        // debug!("ke_buf after possible ke wb: {:?}", keys);

        Ok(dirty)
    }
}

#[cfg(test)]
mod test {
    use crate::*;
    use super::*;

    const MODE_PATH: &str = "test/mode";
    fn open_htree(htree_path: &str) -> FsResult<RWHashTree> {
        use crate::*;
        use crate::storage::FileStorage;
        use super::*;
        use std::path::Path;
        use std::fs::{self, File};
        use std::io::prelude::*;

        let mut len = io_try!(fs::metadata(htree_path)).len();
        assert_eq!(len % BLK_SZ as u64, 0);
        len /= BLK_SZ as u64;

        let mode = if Path::new(MODE_PATH).exists() {
            let mut f = io_try!(File::open("test/mode"));
            let mut b = vec![0u8; std::mem::size_of::<FSMode>()];
            f.read_exact(&mut b).unwrap();
            let mode = unsafe {
                &*(b.as_ptr() as *const FSMode)
            };
            match mode {
                FSMode::IntegrityOnly(hash) => {
                    let s = hex::encode_upper(hash);
                    info!("Run in IntegrityOnly Mode:");
                    info!("Hash: {}", s);
                }
                FSMode::Encrypted(key, mac) => {
                    info!("Run in Encrypted Mode:");
                    let k = hex::encode_upper(key);
                    let m = hex::encode_upper(mac);
                    info!("Key: {}", k);
                    info!("Mac: {}", m);
                }
            }
            Some(mode.clone())
        } else {
            assert_eq!(len, 0);
            info!("Mode file not found, run with empty file");
            None
        };

        let back = FileStorage::new(
            Path::new(htree_path),
            true,
        )?;
        Ok(RWHashTree::new(
            Some(10),
            Box::new(back),
            len,
            mode,
            false,
        ))
    }

    fn close_htree(mut htree: RWHashTree) -> FsResult<()> {
        use super::*;
        use std::fs::{self, OpenOptions};
        use std::io::prelude::*;

        let mode = htree.flush()?;

        // write mode to file
        let _ = fs::remove_file(MODE_PATH);
        let mut f = OpenOptions::new().write(true).create_new(true).open(MODE_PATH).unwrap();
        let written = f.write(unsafe {
            std::slice::from_raw_parts(
                &mode as *const FSMode as *const u8,
                std::mem::size_of::<FSMode>(),
            )
        }).unwrap();
        assert_eq!(written, std::mem::size_of::<FSMode>());
        match mode {
            FSMode::IntegrityOnly(hash) => {
                let s = hex::encode_upper(hash);
                info!("Flush gets IntegrityOnly Mode:");
                info!("Hash: {}", s);
            }
            FSMode::Encrypted(key, mac) => {
                info!("Flush gets Encrypted Mode:");
                let k = hex::encode_upper(key);
                let m = hex::encode_upper(mac);
                info!("Key: {}", k);
                info!("Mac: {}", m);
            }
        }

        Ok(())
    }

    #[test]
    fn rwhtree() -> FsResult<()> {
        use crate::*;
        use std::io::prelude::*;

        env_logger::builder()
            .filter_level(log::LevelFilter::Debug)
            .init();

        let mut buf = [0u8; BLK_SZ];
        let mut writer: &mut [u8] = buf.as_mut_slice();

        let offsets: Vec<_> = (0..1000*BLK_SZ).step_by(BLK_SZ).collect();

        debug!("Writing");

        let mut htree = open_htree("test/test.rwhtree")?;

        let string = "hello!!!";

        let written = io_try!(writer.write(string.as_bytes()));
        assert_eq!(written, string.len());

        for off in offsets.iter() {
            let written = htree.write_exact(*off, &buf[..string.len()])?;
            assert_eq!(written, string.len());
        }

        close_htree(htree)?;

        debug!("Checking");

        let mut htree = open_htree("test/test.rwhtree")?;

        for off in offsets.iter() {
            let read = htree.read_exact(*off, &mut buf[..string.len()])?;
            assert_eq!(read, string.len());
        }

        close_htree(htree)?;

        Ok(())
    }
}
