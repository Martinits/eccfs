use std::sync::{Arc, Mutex};
use crate::bcache::*;
use crate::*;
use crate::crypto::*;
use crate::storage::RWStorage;
use std::collections::HashMap;

/// This module provides data in blocks

pub mod mht {
    use crate::*;
    use crate::crypto::*;
    use std::io::Write;
    use super::*;

    pub const ENTRY_PER_BLK: u64 = BLK_SZ as u64 / KEY_ENTRY_SZ as u64;
    pub const CHILD_PER_BLK: u64 = ENTRY_PER_BLK * 1 / 4;
    pub const DATA_PER_BLK: u64 = ENTRY_PER_BLK * 3 / 4;

    pub fn logi2phy(logi: u64) -> u64 {
        let nr_idx = (logi + 1).div_ceil(DATA_PER_BLK);
        logi + nr_idx
    }

    pub fn logi2dataidx(logi: u64) -> u64 {
        logi % DATA_PER_BLK
    }

    pub fn phy2idxphy(phy: u64) -> u64 {
        phy - phy % (DATA_PER_BLK + 1)
    }

    pub fn phy2dataidx(phy: u64) -> u64 {
        phy - phy2idxphy(phy) - 1
    }

    // get idxblk's father's phypos and child_idx in father blk
    pub fn idxphy2father(idxphy: u64) -> (u64, u64) {
        if idxphy == HTREE_ROOT_BLK_PHY_POS {
            return (HTREE_ROOT_BLK_PHY_POS, 0)
        }
        let idx = idxphy / (DATA_PER_BLK + 1);
        let father = (idx - 1) / CHILD_PER_BLK;
        let fatherphy = father * (DATA_PER_BLK + 1);
        let child_idx = (idx - 1) % CHILD_PER_BLK;
        (fatherphy, child_idx)
    }

    pub fn get_first_idx_child_phy(idxphy: u64) -> u64 {
        let idxnum = idxphy2number(idxphy);
        (idxnum * CHILD_PER_BLK + 1) * (DATA_PER_BLK + 1)
    }

    pub fn next_idx_sibling_phy(child_phy: u64) -> u64 {
        child_phy + DATA_PER_BLK + 1
    }

    pub fn get_first_data_child_phy(idxphy: u64) -> u64 {
        idxphy + 1
    }

    pub fn next_data_sibling_phy(child_phy: u64) -> u64 {
        child_phy + 1
    }

    pub fn idxphy2number(idxphy: u64) -> u64 {
        assert_eq!(idxphy % (DATA_PER_BLK + 1), 0);
        idxphy / (DATA_PER_BLK + 1)
    }

    pub fn get_phy_nr_blk(logi_nr_blk: u64) -> u64 {
        logi_nr_blk + logi_nr_blk.div_ceil(DATA_PER_BLK)
    }

    pub fn is_idx(phy: u64) -> bool {
        phy % (DATA_PER_BLK + 1) == 0
    }

    pub fn get_father_idx(phy: u64) -> (u64, EntryType) {
        if is_idx(phy) {
            let (f, idx) = idxphy2father(phy);
            (f, Index(idx))
        } else {
            (phy2idxphy(phy), Data(phy2dataidx(phy)))
        }
    }

    #[derive(Clone)]
    pub enum EntryType {
        Index(u64),
        Data(u64)
    }
    pub use EntryType::*;

    pub fn get_ke(blk: &Block, tp: EntryType) -> KeyEntry {
        let pos = match tp {
            Index(idx) => idx,
            Data(idx) => CHILD_PER_BLK + idx,
        };
        let mut ret: KeyEntry = [0u8; std::mem::size_of::<KeyEntry>()];
        let from = pos as usize * KEY_ENTRY_SZ;
        ret.copy_from_slice(&blk[from .. from + KEY_ENTRY_SZ]);
        ret
    }

    pub fn set_ke(
        blk: &mut Block, tp: EntryType, ke: &KeyEntry
    ) -> FsResult<()> {
        let pos = match tp {
            Index(idx) => {
                assert!(idx < CHILD_PER_BLK);
                idx
            },
            Data(idx) => {
                assert!(idx < DATA_PER_BLK);
                CHILD_PER_BLK + idx
            },
        };
        let mut writer: &mut [u8] = &mut blk[pos as usize * KEY_ENTRY_SZ ..];
        let written = io_try!(writer.write(ke));
        assert_eq!(written, KEY_ENTRY_SZ);
        Ok(())
    }
}

pub const HTREE_ROOT_BLK_PHY_POS: u64 = 0;

// members are all readonly except backend, so no need to lock this whole struct
pub struct ROHashTree {
    backend: Mutex<ROCache>,
    start: u64, // in blocks
    length: u64, // in blocks
    encrypted: bool,
    cache_data: bool,
    root_hint: CryptoHint,
}

impl ROHashTree {
    pub fn new(
        backend: ROCache,
        start: u64,
        length: u64,
        root_hint: FSMode,
        cache_data: bool,
    ) -> Self {
        let encrypted = root_hint.is_encrypted();

        Self {
            backend: Mutex::new(backend),
            start,
            length,
            encrypted,
            cache_data,
            root_hint: CryptoHint::from_fsmode(root_hint, HTREE_ROOT_BLK_PHY_POS),
        }
    }

    // pos is by block
    pub fn get_blk(&self, pos: u64) -> FsResult<Arc<Block>> {
        if pos >= self.length {
            return Err(FsError::FileTooLarge)
        }

        let mut backend = mutex_lock!(self.backend);

        let data_phy = mht::logi2phy(pos);
        if self.cache_data {
            if let Some(ablk) = backend.get_blk_try(
                self.start + data_phy, self.cache_data
            )? {
                return Ok(ablk)
            }
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
                } else if let Some(ablk) = backend.get_blk_try(
                    self.start + idxphy, true
                )? {
                    break ablk;
                } else if idxphy == HTREE_ROOT_BLK_PHY_POS {
                    // root blk is not cached, give hint to fetch root block
                    break backend.get_blk_hint(
                        self.start + idxphy, true, self.root_hint.clone()
                    )?;
                } else {
                    let (father, child_idx) = mht::idxphy2father(idxphy);
                    idx_stack.push((child_idx, idxphy));
                    idxphy = father;
                }
                safe_cnt += 1;
            }
        };

        // down the tree, use child_idx to get next idx blk, then final data blk
        let mut this_idx_ablk = first_cached_idx;
        while !idx_stack.is_empty() {
            let (child_idx, child_phy) = idx_stack.pop().unwrap();
            let ke = mht::get_ke(
                &this_idx_ablk,
                // if this is the last index, it's an data block
                if idx_stack.is_empty() {
                    mht::Data(child_idx)
                } else {
                    mht::Index(child_idx)
                }
            );
            let hint = CryptoHint::from_key_entry(ke, self.encrypted, child_phy);
            this_idx_ablk = backend.get_blk_hint(
                self.start + child_phy, true, hint
            )?;
        }
        let data_ablk = this_idx_ablk;
        Ok(data_ablk)
    }

    pub fn read_exact(&self, mut offset: usize, to: &mut [u8]) -> FsResult<usize> {
        assert!(offset + to.len() <= blk2byte!(self.length) as usize);

        let total = to.len();
        let mut done = 0;
        while done < total {
            let ablk = self.get_blk(( offset / BLK_SZ ) as u64)?;
            let round = (total - done).min(BLK_SZ - offset % BLK_SZ);
            let start = offset % BLK_SZ;
            to[done..done+round].copy_from_slice(&ablk[start..start+round]);
            done += round;
            offset += round;
        }
        Ok(done)
    }

    // flush all blocks including root
    // pub fn flush(&self) -> FsResult<()> {
    //     mutex_lock!(self.backend).flush()
    // }
}

// if ke_buf size exceeds 1/ratio of cache size, a flush is needed
const RW_KE_BUF_CAP_RATIO: usize = 2;

// data block is forced to be cached due to write back issues
// need to lock this whole struct
pub struct RWHashTree {
    // in rw, every htree has its own cache
    cache: RWCache,
    backend: Box<dyn RWStorage>,
    length: u64, // in blocks
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
            length,
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
        let htree_phy_nr_blk = mht::get_phy_nr_blk(nr_blk);
        // if the htree is cut, there should be invalid ke that points to somewhere over length
        // but it's ok, since we don't check anything over length
        self.backend.set_len(htree_phy_nr_blk)?;

        if nr_blk < self.length {
            if nr_blk == 0 {
                self.root_mode = FSMode::new_zero(self.encrypted);
            }
            return Ok(());
        }

        let mut idx_pos = 0;
        let mut idx_blk = None;
        let mut idx_blk_next_idx = 0;
        for pos in mht::get_phy_nr_blk(self.length)..htree_phy_nr_blk {
            if mht::is_idx(pos) {
                if let Some(blk) = idx_blk {
                    let ke = self.backend_write(idx_pos, blk)?.into_key_entry();
                    self.buffer_ke(idx_pos, ke);
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
                    self.buffer_ke(pos, ke);
                }
            }
        }
        if let Some(blk) = idx_blk {
            let ke = self.backend_write(idx_pos, blk)?.into_key_entry();
            self.buffer_ke(idx_pos, ke);
        }

        // reset htree length
        self.length = nr_blk;

        self.possible_flush_ke_buf()?;
        Ok(())
    }

    // pos is by block
    pub fn get_blk(&mut self, pos: u64, write: bool) -> FsResult<Option<Arc<RWPayLoad>>> {
        if pos >= self.length {
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
        self.possible_ke_wb(pos, &mut blk)?;

        let mode = if self.encrypted {
            self.backend_write(pos, blk)?
        } else {
            self.backend_write(pos, blk)?
        };

        // if is root, just modify in struct
        if pos == HTREE_ROOT_BLK_PHY_POS {
            self.root_mode = mode;
            return Ok(())
        }

        // ke changes, try to write back into father
        let ke = mode.into_key_entry();
        let (father, child_idx) = mht::get_father_idx(pos);
        if let Some(apay) = self.cache.get_blk_try(father)? {
            let mut lock = rwlock_write!(apay);
            mht::set_ke(
                &mut lock,
                child_idx,
                &ke,
            )?;
            self.cache.mark_dirty(father)?;
        } else {
            self.buffer_ke(pos, ke);
            self.possible_flush_ke_buf()?;
        }
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
        assert!(offset + to.len() <= blk2byte!(self.length) as usize);

        let total = to.len();
        let mut done = 0;
        while done < total {
            let apay = self.get_blk(
                ( offset / BLK_SZ ) as u64, false
            )?.ok_or(FsError::IncompatibleMetadata)?;
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
        debug!("Flush htree");
        for (k, v) in self.cache.flush()?.into_iter() {
            self.write_back(k, v)?;
        }

        self.flush_ke_buf()?;

        Ok(self.root_mode.clone())
    }

    // this function does not modify cache (but maybe cached blocks)
    fn flush_ke_buf(&mut self) -> FsResult<()> {
        if self.ke_buf.len() == 0 {
            return Ok(());
        }

        debug!("Flush ke buf");
        debug!("ke_buf: {:?}", self.ke_buf.keys().collect::<Vec<_>>());
        let mut buf: HashMap<_, Vec<_>> = HashMap::new();
        for (pos, ke) in mem::take(&mut self.ke_buf) {
            let (f, idx) = mht::get_father_idx(pos);
            if let Some(v) = buf.get_mut(&f) {
                v.push((idx, ke));
            } else {
                assert!(buf.insert(f, vec![(idx, ke)]).is_none());
            }
        }

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
                    assert!(buf.remove(&idxphy).is_none());

                    let (child_idx, child_phy) = idx_stack.pop().unwrap();
                    last_ke_dest = Some((apay.clone(), child_idx));

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
            if let Some((apay, idx)) = last_ke_dest {
                let mut lock = rwlock_write!(apay);
                mht::set_ke(&mut lock, mht::Index(idx), &ke)?;
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

    fn buffer_ke(&mut self, pos: u64, ke: KeyEntry) {
        if pos == HTREE_ROOT_BLK_PHY_POS {
            self.root_mode = FSMode::from_key_entry(ke, self.encrypted);
        } else {
            self.ke_buf.insert(pos, ke);
        }
    }

    fn possible_flush_ke_buf(&mut self) -> FsResult<()> {
        if self.ke_buf.len() >= self.cache.get_cap() / RW_KE_BUF_CAP_RATIO {
            self.flush_ke_buf()?;
        }
        Ok(())
    }

    // return whether make changes to this block or not
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
