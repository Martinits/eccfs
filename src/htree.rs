use std::sync::Arc;
use crate::bcache::*;
use crate::*;
use crate::crypto::*;
use std::mem;

/// This module provides data in blocks

mod mht {
    use crate::*;
    use crate::crypto::*;

    const ENTRY_PER_BLK: u64 = BLK_SZ / KEY_ENTRY_SZ as u64;
    const CHILD_PER_BLK: u64 = ENTRY_PER_BLK * 1 / 4;
    const DATA_PER_BLK: u64 = ENTRY_PER_BLK * 3 / 4;

    pub fn logi2phy(logi: u64) -> u64 {
        let idx = logi / DATA_PER_BLK;
        logi + idx + 1 + logi % DATA_PER_BLK
    }

    pub fn logi2dataidx(logi: u64) -> u64 {
        logi % DATA_PER_BLK
    }

    // pub fn logi2level(logi: u64) -> FsResult<u64> {
    //
    // }

    // // level starts at 0
    // pub fn phy2level(phy: u64) -> u64 {
    //     let idx1 = phy / (ENTRY_PER_BLK + 1) + 1;
    //     idx1.ilog128() as u64
    // }

    pub fn phy2idxphy(phy: u64) -> u64 {
        phy - phy % (DATA_PER_BLK + 1)
    }

    // get idxblk's father's phypos and child_idx in father blk
    pub fn idxphy2father(idxphy: u64) -> (u64, u64) {
        let idx1 = idxphy / (DATA_PER_BLK + 1) + 1;
        let father1 = idx1 / CHILD_PER_BLK;
        let fatherphy = (father1 - 1) * (DATA_PER_BLK + 1);
        let child_idx = father1 % CHILD_PER_BLK;
        (fatherphy, child_idx)
    }

    pub enum EntryType {
        Index(u64),
        Data(u64)
    }
    pub use EntryType::*;

    pub fn get_entry(blk: &Block, tp: EntryType) -> KeyEntry {
        let pos = match tp {
            Index(idx) => idx,
            Data(idx) => CHILD_PER_BLK + idx,
        };
        let mut ret: KeyEntry = [0u8; std::mem::size_of::<KeyEntry>()];
        let from = pos as usize * KEY_ENTRY_SZ;
        ret.copy_from_slice(&blk[from .. from + KEY_ENTRY_SZ]);
        ret
    }
}

// use features to separate impls for SGX and TDX+FUSE
// for TDX+FUSE deployment, only cache index blocks, kernel will handle the left cache
pub struct ROHashTree {
    backend: ROCache,
    start: u64,
    length: u64,
    encrypted: bool,
    cache_data: bool,
    root_hint: CacheMissHint,
}

impl ROHashTree {
    pub fn new(
        backend: ROCache,
        start: u64, // in blocks
        length: u64, // in blocks
        root_hint: CacheMissHint,
        cache_data: bool,
    ) -> Self {
        let encrypted = root_hint.is_encrypted();

        Self {
            backend,
            start,
            length,
            encrypted,
            cache_data,
            root_hint,
        }
    }

    // pos is by block
    pub fn get_blk(&mut self, pos: u64) -> FsResult<Arc<Block>> {
        if pos >= self.length {
            return Err(FsError::FileTooLarge)
        }

        let data_phy = mht::logi2phy(pos);
        if let Some(ablk) = self.backend.get_blk(data_phy, self.cache_data)? {
            return Ok(ablk)
        }

        // data blk not cached
        let mut idx_stack = Vec::new();
        let mut idxphy = mht::phy2idxphy(data_phy);
        idx_stack.push((mht::logi2dataidx(pos), data_phy));

        let first_cached_idx = if idxphy == 0 {
            // data is under root idx
            self.backend.get_blk_hint(idxphy, true, self.root_hint.clone())?
        } else {
            // find backward through the tree to the first cached idx blk
            let mut safe_cnt = 0;
            loop {
                if safe_cnt >= MAX_LOOP_CNT {
                    panic!("Loop exceeds MAX count!");
                } else if let Some(ablk) = self.backend.get_blk(idxphy, true)? {
                    break ablk;
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
            let key_entry = mht::get_entry(&this_idx_ablk, mht::Index(child_idx));
            let hint = if self.encrypted {
                let (key, mac): (Key128, MAC128) = unsafe {
                    mem::transmute(key_entry)
                };
                CacheMissHint::Encrypted(key, mac)
            } else {
                CacheMissHint::IntegrityOnly(key_entry)
            };
            this_idx_ablk = self.backend.get_blk_hint(child_phy, true, hint)?;
        }
        let data_ablk = this_idx_ablk;
        Ok(data_ablk)
    }

    // flush all blocks including root
    pub fn flush(&mut self) -> FsResult<()> {
        self.backend.flush()
    }
}

pub struct RWHashTree {
    backend: RWCache,
    start: u64,
    length: usize,
    encrypted: bool,
}

impl RWHashTree {
    pub fn new(
        backend: RWCache,
        start: u64,
        length: usize,
        encrypted: bool,
    ) -> Self {
        Self {
            backend,
            start,
            length,
            encrypted,
        }
    }

    pub fn validate_root(self) {

    }

    pub fn read(self, pos: u64, nblk: usize, to: &[u8]) {

    }

    pub fn write(self, pos: u64, nblk: usize, from: &mut [u8]) {

    }

    // flush all blocks including root
    pub fn flush(self) {

    }
}
