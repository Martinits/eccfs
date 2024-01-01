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
        if idxphy == 0 {
            return (0, 0)
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
    root_hint: CacheMissHint,
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
            root_hint: CacheMissHint::from_fsmode(root_hint, HTREE_ROOT_BLK_PHY_POS),
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
                } else if idxphy == 0 {
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
            let hint = CacheMissHint::from_key_entry(ke, self.encrypted, child_phy);
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
    pub fn flush(&self) -> FsResult<()> {
        mutex_lock!(self.backend).flush()
    }
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
        cache: RWCache,
        backend: Box<dyn RWStorage>,
        length: u64,
        root_mode: FSMode,
    ) -> Self {
        let encrypted = root_mode.is_encrypted();

        Self {
            cache,
            backend,
            length,
            encrypted,
            root_mode,
            ke_buf: HashMap::new(),
            key_gen: KeyGen::new(),
        }
    }

    // pos is by block
    pub fn get_blk(&mut self, pos: u64, write: bool) -> FsResult<Option<Arc<RWPayLoad>>> {
        if !write && pos >= self.length {
            return Ok(None)
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
                    break Some(apay);
                } else if idxphy == 0 {
                    // root blk is not cached
                    break None;
                    // break self.cache_miss(idxphy, Some(self.root_mode.clone()))?
                } else {
                    let (father, child_idx) = mht::idxphy2father(idxphy);
                    idx_stack.push((child_idx, idxphy));
                    idxphy = father;
                }
                safe_cnt += 1;
            }
        };

        // find first not cached block
        let (first_no_cache_idxphy, mode) = if let Some(apay) = first_cached_idx {
            let (child_idx, child_phy) = idx_stack.pop().unwrap();
            // try get ke from ke_buf
            let ke = if let Some(ke) = self.ke_buf.remove(&pos) {
                ke
            } else {
                let lock = rwlock_read!(apay);
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
            let mode = if ke_is_zero(&ke) {
                // new block
                assert!(child_phy >= self.length);
                assert!(write);
                None
            } else {
                Some(FSMode::from_key_entry(ke, self.encrypted))
            };
            (child_phy, mode)
        } else {
            // root is not cached
            (HTREE_ROOT_BLK_PHY_POS, Some(self.root_mode.clone()))
        };

        // down the tree, use child_idx to get next idx blk, then final data blk
        let (mut cur_phy, mut cur_mode) = (first_no_cache_idxphy, mode);
        while !idx_stack.is_empty() {
            let cur_apay = self.cache_miss(cur_phy, cur_mode)?;
            let (child_idx, child_phy) = idx_stack.pop().unwrap();
            // try get ke from ke_buf
            let ke = if let Some(ke) = self.ke_buf.remove(&pos) {
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
            cur_mode = if ke_is_zero(&ke) {
                // new block
                assert!(child_phy >= self.length);
                assert!(write);
                None
            } else {
                Some(FSMode::from_key_entry(ke, self.encrypted))
            };
            cur_phy = child_phy;
        }
        let data_apay = self.cache_miss(cur_phy, cur_mode)?;
        if write {
            self.cache.mark_dirty(cur_phy)?;
        }

        self.length = self.length.max(pos + 1);
        Ok(Some(data_apay))
    }

    // mode == None means to create new block
    fn cache_miss(
        &mut self, pos: u64, mode: Option<FSMode>
    ) -> FsResult<Arc<RWPayLoad>> {
        let blk = if let Some(mode) = mode {
            let mut blk = self.backend_read(pos, mode)?;
            self.possible_ke_wb(pos, &mut blk)?;
            blk
        } else {
            // create
            [0u8; BLK_SZ]
        };

        let (apay, wb) = self.cache.insert_and_get(pos, blk)?;
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
        }.into_key_entry();

        // ke changes, try to write back into father
        let (father, child_idx) = mht::get_father_idx(pos);
        if let Some(apay) = self.cache.get_blk_try(father)? {
            let mut lock = rwlock_write!(apay);
            mht::set_ke(
                &mut lock,
                child_idx,
                &mode,
            )?;
            self.cache.mark_dirty(father)?;
        } else {
            if self.ke_buf.len() >= self.cache.get_cap() / RW_KE_BUF_CAP_RATIO {
                self.flush_ke_buf()?;
            }
            self.ke_buf.insert(pos, mode);
        }
        Ok(())
    }

    fn backend_read(&mut self, pos: u64, mode: FSMode) -> FsResult<Block> {
        let mut blk = self.backend.read_blk(pos)?;
        match mode {
            FSMode::Encrypted(key, mac) => {
                aes_gcm_128_blk_dec(&mut blk, &key, &mac, pos)?;
            }
            FSMode::IntegrityOnly(hash) => {
                sha3_256_blk_check(&blk, &hash)?;
            }
        }
        Ok(blk)
    }

    fn backend_write(
        &mut self, pos: u64, mut blk: Block,
    ) -> FsResult<FSMode> {
        let mode = if self.encrypted {
            // generate new aes key on every write_back
            let key = self.key_gen.gen_key(pos)?;
            let mac = aes_gcm_128_blk_enc(&mut blk, &key, pos)?;
            FSMode::Encrypted(key, mac)
        } else {
            let hash = sha3_256_blk(&blk)?;
            FSMode::IntegrityOnly(hash)
        };
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
    pub fn flush(&mut self) -> FsResult<()> {
        for (k, v) in self.cache.flush()?.into_iter() {
            self.write_back(k, v)?;
        }

        self.flush_ke_buf()
    }

    fn flush_ke_buf(&mut self) -> FsResult<()> {
        let mut buf: HashMap<_, Vec<_>> = HashMap::new();
        for (pos, ke) in mem::take(&mut self.ke_buf) {
            let (f, idx) = mht::get_father_idx(pos);
            if let Some(v) = buf.get_mut(&f) {
                v.push((idx, ke));
            } else {
                buf.insert(f, vec![(idx, ke)]).unwrap();
            }
        }

        fn write_ke_list(
            apay: &Arc<RWPayLoad>,
            ke_list: Vec<(mht::EntryType, KeyEntry)>
        ) -> FsResult<()> {
            let mut lock = rwlock_write!(apay);
            for (idx, ke) in ke_list {
                mht::set_ke(&mut lock, idx.clone(), &ke)?;
            }
            Ok(())
        }

        fn write_ke_list_blk(
            blk: &mut Block,
            ke_list: Vec<(mht::EntryType, KeyEntry)>
        ) -> FsResult<()> {
            for (idx, ke) in ke_list {
                mht::set_ke(blk, idx.clone(), &ke)?;
            }
            Ok(())
        }

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
                write_ke_list(&apay, ke_list)?;
                break;
            }

            // not cached
            let mut idxphy = pos;
            let mut idx_stack = Vec::new();

            // find backward through the tree to the first cached idx blk
            let first_cached_idx = loop {
                if let Some(apay) = self.cache.get_blk_try(idxphy)? {
                    break Some(apay);
                } else if idxphy == 0 {
                    // root blk is not cached
                    break None;
                } else {
                    let (father, child_idx) = mht::idxphy2father(idxphy);
                    idx_stack.push((child_idx, idxphy));
                    idxphy = father;
                }
            };
            let last_ke_dest = first_cached_idx.clone();
            let mut last_ke_idx = 0;

            // find first not cached block
            let (first_no_cache_idxphy, mode) = if let Some(apay) = first_cached_idx {
                // any ke_list in buf for this block, write it first
                if let Some(ke_list) = buf.remove(&idxphy) {
                    write_ke_list(&apay, ke_list)?;
                }

                let (child_idx, child_phy) = idx_stack.pop().unwrap();
                last_ke_idx = child_idx;
                let ke = {
                    let lock = rwlock_read!(apay);
                    mht::get_ke(
                        &lock,
                        // must be index
                        mht::Index(child_idx)
                    )
                };
                let mode = if ke_is_zero(&ke) {
                    // new block
                    None
                } else {
                    Some(FSMode::from_key_entry(ke, self.encrypted))
                };
                (child_phy, mode)
            } else {
                // root is not cached
                (HTREE_ROOT_BLK_PHY_POS, Some(self.root_mode.clone()))
            };

            // down the tree, use child_idx to get next idx blk, then final data blk
            let (mut cur_phy, mut cur_mode) = (first_no_cache_idxphy, mode);
            let mut blk_stack = Vec::new();
            while !idx_stack.is_empty() {
                let mut cur_blk = if let Some(mode) = cur_mode {
                    self.backend_read(cur_phy, mode)?
                } else {
                    // new block
                    [0u8; BLK_SZ]
                };
                if let Some(ke_list) = buf.remove(&cur_phy) {
                    write_ke_list_blk(&mut cur_blk, ke_list)?;
                }
                let (child_idx, child_phy) = idx_stack.pop().unwrap();
                blk_stack.push((cur_phy, cur_blk, child_idx));

                // try get ke from ke_buf
                let ke = mht::get_ke(
                    &cur_blk,
                    // must be index
                    mht::Index(child_idx)
                );
                cur_mode = if ke_is_zero(&ke) {
                    // new block
                    None
                } else {
                    Some(FSMode::from_key_entry(ke, self.encrypted))
                };
                cur_phy = child_phy;
            }

            // get pos and write ke
            assert!(pos == cur_phy);
            let mut cur_blk = if let Some(mode) = cur_mode {
                self.backend_read(cur_phy, mode)?
            } else {
                // new block
                [0u8; BLK_SZ]
            };
            write_ke_list_blk(&mut cur_blk, ke_list)?;

            let mut ke = self.backend_write(cur_phy, cur_blk)?.into_key_entry();

            // write back blk_stack
            for (pos, mut blk, child_idx) in blk_stack.into_iter().rev() {
                mht::set_ke(&mut blk, mht::Index(child_idx), &ke)?;
                ke = self.backend_write(pos, blk)?.into_key_entry();
            }

            // write last ke to first_cached_idx or root
            if let Some(apay) = last_ke_dest {
                let mut lock = rwlock_write!(apay);
                mht::set_ke(&mut lock, mht::Index(last_ke_idx), &ke)?;
            } else {
                // last ke goes to root
                self.root_mode = FSMode::from_key_entry(ke, self.encrypted);
            }
        }

        Ok(())
    }

    fn possible_ke_wb(&mut self, pos: u64, blk: &mut Block) -> FsResult<()> {
        if !mht::is_idx(pos) {
            return Ok(());
        }

        // idx ke
        let mut child_phy = mht::get_first_idx_child_phy(pos);
        for i in 0..mht::CHILD_PER_BLK {
            if let Some(ke) = self.ke_buf.remove(&child_phy) {
                mht::set_ke(
                    blk,
                    mht::Index(i),
                    &ke,
                )?;
            }
            child_phy = mht::next_idx_sibling_phy(child_phy);
        }

        // data ke
        let mut child_phy = mht::get_first_data_child_phy(pos);
        for i in 0..mht::DATA_PER_BLK {
            if let Some(ke) = self.ke_buf.remove(&child_phy) {
                mht::set_ke(
                    blk,
                    mht::Index(i),
                    &ke,
                )?;
            }
            child_phy = mht::next_data_sibling_phy(child_phy);
        }

        Ok(())
    }
}
