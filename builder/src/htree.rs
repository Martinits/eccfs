use std::io::prelude::*;
use std::io::SeekFrom;
use std::path::PathBuf;
use crate::*;
use std::fs::{OpenOptions, self, File};
use crate::crypto::*;
use rand_core::RngCore;
use super::*;
use std::collections::HashMap;
use std::os::unix::fs::MetadataExt;

pub struct HTreeBuilder {
    key_gen: KeyGen,
    encrypted: bool,
}

impl HTreeBuilder {
    pub fn new(encrypted: bool) -> FsResult<Self> {
        // init kdk
        let mut kdk = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut kdk);

        Ok(Self {
            key_gen: KeyGen::new(),
            encrypted,
        })
    }

    fn crypto_process_blk(&mut self, blk: &mut Block, pos: u64) -> FsResult<KeyEntry> {
        let mode = crypto_out(blk,
            if self.encrypted {
                Some(self.key_gen.gen_key(pos)?)
            } else {
                None
            },
            pos
        )?;

        Ok(mode.into_key_entry())
    }

    // "from" need not to be padded to blocks
    pub fn build_htree(
        &mut self,
        to: &mut File,
        from: &PathBuf,
    ) -> FsResult<(usize, KeyEntry)> {
        // get file logical size
        let logi_nr_blk = io_try!(fs::symlink_metadata(from)).size().div_ceil(BLK_SZ as u64);
        // open source file
        let mut f = io_try!(OpenOptions::new().read(true).open(from));

        self.build_htree_file(to, &mut f, logi_nr_blk)
    }

    // "from" need not to be padded to blocks
    pub fn build_htree_file(
        &mut self,
        to: &mut File,
        from: &mut File,
        logi_nr_blk: u64,
    ) -> FsResult<(usize, KeyEntry)> {
        assert!(logi_nr_blk > 0);

        // get the htree start (in blocks)
        let mut to_start_blk = get_file_pos(to)?;
        assert!(to_start_blk % BLK_SZ as u64 == 0);
        to_start_blk /= BLK_SZ as u64;
        let htree_nr_blk = mht::get_phy_nr_blk(logi_nr_blk);

        let mut idx_blk = [0u8; BLK_SZ] as Block;
        // map idx_phy_pos to its ke
        let mut idx_ke = HashMap::new();

        for logi_pos in (0..logi_nr_blk).rev() {
            // read plain data block, padding 0 to integral block
            let mut d = [0u8; BLK_SZ] as Block;
            let _read = read_file_at(from, blk2byte!(logi_pos), &mut d)?;
            // process crypto
            let phy_pos = mht::logi2phy(logi_pos);
            let ke = self.crypto_process_blk(&mut d, phy_pos)?;
            // write data block
            write_file_at(to, blk2byte!(to_start_blk + phy_pos), &d)?;

            // write ke to idx_blk
            let ke_idx = mht::logi2dataidx(logi_pos);
            mht::set_ke(
                &mut idx_blk,
                mht::Data(ke_idx),
                &ke,
            )?;

            // if the written ke is the first data ke (0) in the idx_blk,
            // all its data block ke have been filled.
            if ke_idx != 0 {
                continue;
            }

            // all data blk of the idx_blk are filled, now process idx_blk
            let idx_phy_pos = mht::phy2idxphy(phy_pos);
            // fill child ke
            let mut child_phy = mht::get_first_idx_child_phy(idx_phy_pos);
            for i in 0..mht::CHILD_PER_BLK {
                if let Some(ke) = idx_ke.remove(&child_phy) {
                    mht::set_ke(
                        &mut idx_blk,
                        mht::Index(i),
                        &ke,
                    )?;
                } else {
                    break;
                }
                child_phy = mht::next_idx_sibling_phy(child_phy);
            }
            // process crypto
            let ke = self.crypto_process_blk(&mut idx_blk, idx_phy_pos)?;
            // add this idx_blk ke to the hashmap, for use of its father
            assert!(idx_ke.insert(idx_phy_pos, ke).is_none());
            // write idx block
            write_file_at(to, blk2byte!(to_start_blk + idx_phy_pos), &idx_blk)?;
            // switch to a new idx block
            idx_blk = [0u8; BLK_SZ];
        }

        let root_ke = idx_ke.remove(&HTREE_ROOT_BLK_PHY_POS).unwrap();
        // if idx_ke.len() != 0 {
        //     debug!("idx_ke keys:");
        //     let mut l: Vec<_> = idx_ke.keys().map(
        //         |k| {
        //             (*k, mht::idxphy2number(*k))
        //         }
        //     ).collect();
        //     l.sort();
        //     debug!("{l:?}");
        // }
        assert!(idx_ke.is_empty());

        // seek to end of this htree
        let file_end = blk2byte!(to_start_blk + htree_nr_blk);
        assert_eq!(io_try!(to.seek(SeekFrom::End(0))), file_end);

        // return size of htree in block, root block keys
        Ok((htree_nr_blk as usize, root_ke))
    }
}

