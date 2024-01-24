/// This module provides data in blocks
pub(crate) mod ro;
pub(crate) mod rw;
pub(crate) mod builder;

pub use ro::*;
pub use rw::*;
pub use builder::*;

pub const HTREE_ROOT_BLK_PHY_POS: u64 = 0;

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

    pub fn get_logi_nr_blk(phy_nr_blk: u64) -> u64 {
        phy_nr_blk - phy_nr_blk.div_ceil(DATA_PER_BLK + 1)
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
