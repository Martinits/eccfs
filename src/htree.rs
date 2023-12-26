use std::sync::{Arc, Mutex};
use crate::bcache::*;
use crate::*;
use crate::crypto::*;
use std::mem;

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

    pub fn next_sibling_phy(child_phy: u64) -> u64 {
        child_phy + DATA_PER_BLK + 1
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
        idxphy * CHILD_PER_BLK + 1
    }

    pub fn get_phy_nr_blk(logi_nr_blk: u64) -> u64 {
        logi_nr_blk + logi_nr_blk.div_ceil(DATA_PER_BLK)
    }

    pub enum EntryType {
        Index(u64),
        Data(u64)
    }
    pub use EntryType::*;

    pub fn get_key_entry(blk: &Block, tp: EntryType) -> KeyEntry {
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

// use features to separate impls for SGX and TDX+FUSE
// for TDX+FUSE deployment, only cache index blocks, kernel will handle the left cache
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

        let data_phy = mht::logi2phy(pos);
        if let Some(ablk) = mutex_lock!(self.backend).get_blk_try(
            self.start + data_phy, self.cache_data
        )? {
            return Ok(ablk)
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
                } else if let Some(ablk) = mutex_lock!(self.backend).get_blk_try(
                    self.start + idxphy, true
                )? {
                    break ablk;
                } else if idxphy == 0 {
                    // root blk is not cached, fetch root block
                    break mutex_lock!(self.backend).get_blk_hint(
                        self.start + idxphy, true, self.root_hint.clone()
                    )?
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
            let key_entry = mht::get_key_entry(&this_idx_ablk, mht::Index(child_idx));
            let hint = if self.encrypted {
                let (key, mac): (Key128, MAC128) = unsafe {
                    mem::transmute(key_entry)
                };
                CacheMissHint::Encrypted(key, mac, child_phy)
            } else {
                CacheMissHint::IntegrityOnly(key_entry)
            };
            this_idx_ablk = mutex_lock!(self.backend).get_blk_hint(
                self.start + child_phy, true, hint
            )?;
        }
        let data_ablk = this_idx_ablk;
        Ok(data_ablk)
    }

    pub fn read_exact(&self, mut offset: usize, to: &mut [u8]) -> FsResult<usize> {
        let total = to.len();
        let mut done = 0;
        while done < total {
            let ablk = self.get_blk(( offset / BLK_SZ ) as u64)?;
            let round = (total - done).min(BLK_SZ - offset % BLK_SZ);
            let start = offset % BLK_SZ;
            to[offset..offset+round].copy_from_slice(&ablk[start..start+round]);
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
