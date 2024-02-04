use crate::*;
use alloc::collections::BTreeSet;
use alloc::vec::Vec;
use core::{mem, slice};

pub struct BitMap {
    used: BTreeSet<u64>,
    possible_free_pos: u64,
}

impl BitMap {
    pub fn new(raw_blks: Vec<Block>) -> FsResult<Self> {
        let bytes: &[u8] = unsafe {
            slice::from_raw_parts(
                raw_blks.as_ptr() as *const u8,
                blk2byte!(raw_blks.len()) as usize,
            )
        };
        let mut used = BTreeSet::new();
        let mut possible_free_pos = bytes.len() as u64 * 8;
        for (i, b) in bytes.iter().enumerate() {
            for off in 0..8 {
                let iid = (i * 8 + off) as u64;
                if (*b >> off) & 0x01 == 0x01 {
                    assert!(used.insert(iid));
                } else {
                    possible_free_pos = possible_free_pos.min(iid);
                }
            }
        }

        Ok(Self {
            used,
            possible_free_pos,
        })
    }

    pub fn alloc(&mut self) -> FsResult<u64> {
        let i = self.possible_free_pos;
        let safe_cnt = 0;
        loop {
            if safe_cnt > MAX_LOOP_CNT {
                panic!("Loop exceeds MAX count!");
            }
            if !self.used.contains(&i) {
                self.used.insert(i);
                self.possible_free_pos = i + 1;
                break;
            }
        }
        // debug!("bitmap alloc {}", i);
        Ok(i)
    }

    pub fn free(&mut self, pos: u64) -> FsResult<()> {
        if self.used.remove(&pos) {
            self.possible_free_pos = self.possible_free_pos.min(pos);
            Ok(())
        } else {
            Err(new_error!(FsError::NotFound))
        }
    }

    // after calling this function, this struct can not be used anymore
    pub fn write(&mut self) -> FsResult<Vec<Block>> {
        let pos_list: Vec<_> = mem::take(&mut self.used).into_iter().collect();

        Self::write_from_list(pos_list)
    }

    pub fn write_from_list(pos_list: Vec<u64>) -> FsResult<Vec<Block>> {
        // pos_list can not be empty, at least we have root inode
        let max_pos = *pos_list.iter().max().unwrap() as usize;
        let blks_needed = (max_pos + 1).div_ceil(BLK_SZ * 8);

        let mut blks = Vec::new();
        blks.resize(blks_needed, [0u8; BLK_SZ]);
        let bytes: &mut [u8] = unsafe {
            slice::from_raw_parts_mut(
                blks.as_mut_ptr() as *mut u8,
                blk2byte!(blks_needed) as usize,
            )
        };

        for pos in pos_list {
            let b = &mut bytes[pos as usize/8];
            *b = *b | (0x01u8 << (pos % 8));
        }

        Ok(blks)
    }
}
