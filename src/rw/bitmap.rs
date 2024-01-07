use crate::*;
use std::collections::HashSet;

pub struct BitMap {
    used: HashSet<u64>,
    possible_free_pos: u64,
}

impl BitMap {
    pub fn new(raw_blks: Vec<Block>) -> FsResult<Self> {
        let bytes: &[u8] = unsafe {
            std::slice::from_raw_parts(
                raw_blks.as_ptr() as *const u8,
                blk2byte!(raw_blks.len()) as usize,
            )
        };
        let mut used = HashSet::new();
        for (i, b) in bytes.iter().enumerate() {
            for off in 0..8 {
                if (*b >> off) & 0x01 == 0x01 {
                    assert!(used.insert((i * 8 + off) as u64));
                }
            }
        }

        Ok(Self {
            used,
            possible_free_pos: 0,
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
        Ok(i)
    }

    pub fn free(&mut self, pos: u64) -> FsResult<()> {
        if self.used.remove(&pos) {
            self.possible_free_pos = self.possible_free_pos.min(pos);
            Ok(())
        } else {
            Err(FsError::NotFound)
        }
    }

    // after calling this function, this struct can not be used anymore
    pub fn write(&mut self) -> FsResult<Vec<Block>> {
        let pos_list: Vec<_> = std::mem::take(&mut self.used).into_iter().collect();

        // pos_list can not be empty, at least we have root inode
        let max_pos = *pos_list.iter().max().unwrap() as usize;
        let blks_needed = (max_pos + 1).div_ceil(BLK_SZ * 8);

        let mut blks = vec![[0u8; BLK_SZ]; blks_needed];
        let bytes: &mut [u8] = unsafe {
            std::slice::from_raw_parts_mut(
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
