use std::sync::{Arc, Mutex, RwLock};
use crate::bcache::*;
use crate::*;
use crate::crypto::*;
use std::mem;
use crate::storage::RWStorage;
use std::collections::HashMap;

/// This module provides data in blocks

pub mod mht {
    use crate::*;
    use crate::crypto::*;
    use std::io::Write;
    use std::ops::Deref;

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

    pub fn next_sibling_phy(child_phy: u64) -> u64 {
        child_phy + DATA_PER_BLK + 1
    }

    pub fn phy2idxphy(phy: u64) -> u64 {
        phy - phy % (DATA_PER_BLK + 1)
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

    pub enum EntryType {
        Index(u64),
        Data(u64)
    }
    pub use EntryType::*;

    pub fn get_key_entry(blk: &dyn Deref<Target = Block>, tp: EntryType) -> KeyEntry {
        let pos = match tp {
            Index(idx) => idx,
            Data(idx) => CHILD_PER_BLK + idx,
        };
        let mut ret: KeyEntry = [0u8; std::mem::size_of::<KeyEntry>()];
        let from = pos as usize * KEY_ENTRY_SZ;
        ret.copy_from_slice(&blk[from .. from + KEY_ENTRY_SZ]);
        ret
    }

    pub fn set_key_entry(blk: &mut Block, tp: EntryType, ke: &KeyEntry) -> FsResult<()> {
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
            let ke = mht::get_key_entry(
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

// need to lock this whole struct
pub struct RWHashTree {
    // in rw, every htree has its own cache
    cache: RWCache,
    backend: Box<dyn RWStorage>,
    length: u64, // in blocks
    encrypted: bool,
    cache_data: bool,
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
        cache_data: bool,
    ) -> Self {
        let encrypted = root_mode.is_encrypted();

        Self {
            cache,
            backend,
            length,
            encrypted,
            cache_data,
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
        if self.cache_data {
            if let Some(apay) = self.cache.get_blk_try(data_phy)? {
                return Ok(Some(apay))
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
                } else if let Some(apay) = self.cache.get_blk_try(idxphy)? {
                    break apay;
                } else if idxphy == 0 {
                    // root blk is not cached
                    break self.cache_miss(idxphy, Some(self.root_mode.clone()))?
                } else {
                    let (father, child_idx) = mht::idxphy2father(idxphy);
                    idx_stack.push((child_idx, idxphy));
                    idxphy = father;
                }
                safe_cnt += 1;
            }
        };

        // down the tree, use child_idx to get next idx blk, then final data blk
        let mut this_idx_apay = first_cached_idx;
        while !idx_stack.is_empty() {
            let (child_idx, child_phy) = idx_stack.pop().unwrap();
            let ke = mht::get_key_entry(
                &rwlock_read!(this_idx_apay),
                // &rwlock_read!(this_idx_apay),
                // if this is the last index, it's an data block
                if idx_stack.is_empty() {
                    mht::Data(child_idx)
                } else {
                    mht::Index(child_idx)
                }
            );
            let mode = if ke_is_zero(&ke) {
                // new block
                assert!(child_phy >= self.length);
                assert!(write);
                None
            } else {
                Some(FSMode::from_key_entry(ke, self.encrypted))
            };
            this_idx_apay = self.cache_miss(child_phy, mode)?;
        }
        let data_ablk = this_idx_apay;

        self.length = self.length.max(pos + 1);
        Ok(Some(data_ablk))
    }

    // mode == None means to create new block
    fn cache_miss(
        &mut self, pos: u64, mode: Option<FSMode>
    ) -> FsResult<Arc<RWPayLoad>> {
        let blk = if let Some(mode) = mode {
            self.backend_read(pos, mode)?
        } else {
            // create
            [0u8; BLK_SZ]
        };

        if !self.cache_data && !mht::is_idx(pos) {
            // not cachable
            return Ok(Arc::new(RwLock::new(blk)));
        }

        let (apay, wb) = self.cache.insert_and_get(pos, blk)?;
        if let Some((pos, blk)) = wb {
            // need write back
            self.write_back(pos, blk)?;
        }
        Ok(apay)
    }

    fn write_back(&mut self, pos: u64, blk: Block) -> FsResult<()> {
        let mode = if self.encrypted {
            // generate new aes key on every write_back
            let key = self.key_gen.gen_key(pos)?;
            self.backend_write(pos, blk, Some(key))?
        } else {
            self.backend_write(pos, blk, None)?
        };
        self.ke_buf.insert(pos, mode.into_key_entry());
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
        &mut self, pos: u64, mut blk: Block, key: Option<Key128>
    ) -> FsResult<FSMode> {
        let mode = if let Some(key) = key {
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
            self.backend.write_blk(k, &v)?;
        }
        Ok(())
    }
}
