use std::sync::{Arc, Mutex};
use crate::bcache::*;
use crate::*;
use super::*;


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
            return Err(new_error!(FsError::UnexpectedEof))
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
