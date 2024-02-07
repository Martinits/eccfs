use aes_gcm::{
    aead::{AeadInPlace, Tag, KeyInit},
    Aes128Gcm, Nonce, Key
};
use sha3::{Digest, Sha3_256};
use crate::*;
use md4::Md4;

type Nonce96 = [u8; 12];
pub type Key128 = [u8; 16];
pub type MAC128 = [u8; 16];
pub type Hash256 = [u8; 32];
pub type KeyEntry = [u8; 32];

pub const KEY_ENTRY_SZ: usize = 32;

pub fn crypto_in(blk: &mut Block, hint: CryptoHint) -> FsResult<()> {
    match hint {
        CryptoHint::Encrypted(key, mac, pos) => {
            aes_gcm_128_blk_dec(blk, &key, &mac, pos)?;
        }
        CryptoHint::IntegrityOnly(hash) => {
            sha3_256_blk_check(blk, &hash)?;
        }
    }
    Ok(())
}

pub fn crypto_out(blk: &mut Block, encrypted: Option<Key128>, pos: u64) -> FsResult<FSMode> {
    let mode = if let Some(key) = encrypted {
        let mac = aes_gcm_128_blk_enc(blk, &key, pos)?;
        FSMode::Encrypted(key, mac)
    } else {
        let hash = sha3_256_blk(blk)?;
        FSMode::IntegrityOnly(hash)
    };
    Ok(mode)
}

pub fn sha3_256_blk(input: &Block) -> FsResult<Hash256> {
    sha3_256_any(input)
}

pub fn sha3_256_any(input: &[u8]) -> FsResult<Hash256> {
    let mut hasher = Sha3_256::new();

    hasher.update(input);

    let hash = hasher.finalize().try_into().map_err(
        |_| new_error!(FsError::UnknownError)
    )?;

    Ok(hash)
}

pub fn sha3_256_blk_check(input: &Block, hash: &Hash256) -> FsResult<()> {
    sha3_256_any_check(input, hash)
}

pub fn sha3_256_any_check(input: &[u8], hash: &Hash256) -> FsResult<()> {
    let actual = sha3_256_any(input)?;
    if actual != *hash {
        Err(new_error!(FsError::IntegrityCheckError))
    } else {
        Ok(())
    }
}

fn pos_to_nonce(pos: u64) -> Nonce96 {
    // nonce is 96 bit integer of block physical position (in block) (little endian)
    let posbyte = pos.to_le_bytes();
    let mut nonce = [0u8; 12];
    nonce[4..].copy_from_slice(&posbyte);
    nonce
}

pub fn aes_gcm_128_blk_enc(
    input: &mut Block,
    key: &Key128,
    pos_as_nonce: u64,
) -> FsResult<MAC128> {
    let k = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(&k);
    let nonce = pos_to_nonce(pos_as_nonce);
    let nonce = Nonce::from_slice(&nonce);

    // let mut buffer: Block = input.clone();
    let tag = cipher.encrypt_in_place_detached(
        &nonce, b"", input
    ).map_err(
        |_| new_error!(FsError::CryptoError)
    )?;

    Ok(tag.try_into().unwrap())
}

pub fn aes_gcm_128_blk_dec(
    input: &mut Block,
    key: &Key128,
    mac: &MAC128,
    pos_as_nonce: u64,
) -> FsResult<()> {
    let k = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(&k);

    let nonce = pos_to_nonce(pos_as_nonce);
    let nonce = Nonce::from_slice(&nonce);

    // let mut buffer: Block = input.clone();
    cipher.decrypt_in_place_detached(
        &nonce, b"", input, Tag::<Aes128Gcm>::from_slice(mac)
    ).map_err(
        |_| new_error!(FsError::IntegrityCheckError)
    )?;

    Ok(())
}

mod key_gen {
    use aes::Aes128;
    use cmac::{Cmac, Mac};
    use super::Key128;
    use crate::*;
    use rand_core::RngCore;

    #[cfg(not(feature = "std"))]
    use rand::SeedableRng;
    #[cfg(not(feature = "std"))]
    use rand::rngs::SmallRng;

    use crate::alloc::borrow::ToOwned;

    #[repr(C)]
    struct KdfInput {
        idx: u32,
        label: [u8; 64],
        context: u64,
        nonce: [u8; 16],
        out_len: u32, //in bits
    }
    rw_as_blob!(KdfInput);

    #[cfg(feature = "std")]
    fn random_16b() -> [u8; 16] {
        let mut ret = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut ret);
        ret
    }

    #[cfg(not(feature = "std"))]
    fn random_16b(seed: u64) -> [u8; 16] {
        let mut ret = [0u8; 16];
        let mut small_rng = SmallRng::seed_from_u64(seed);
        small_rng.fill_bytes(&mut ret);
        ret
    }

    pub fn generate_random_key(kdk: &Key128, counter: u32, pos: u64) -> FsResult<Key128> {
        #[cfg(not(feature = "std"))]
        let nonce = random_16b(pos);
        #[cfg(feature = "std")]
        let nonce = random_16b();

        let mut mac = Cmac::<Aes128>::new_from_slice(kdk).unwrap();
        let input = KdfInput {
            idx: counter,
            label: b"#ENCLAVE-CC-TEE-FS-SECURE-RANDOM-KEY-AES-128-CMAC-NIST-SP800-108".to_owned(),
            context: pos,
            nonce,
            out_len: 128,
        };
        mac.update(input.as_ref());
        Ok(mac.finalize().into_bytes().try_into().unwrap())
    }

    pub struct KeyGen {
        kdk: Key128,
        used_time: u32,
        key_gen_counter: u32,
    }

    impl KeyGen {
        #[cfg(feature = "std")]
        pub fn new() -> Self {
            let kdk = random_16b();
            Self {
                kdk,
                used_time: 0,
                key_gen_counter: 0,
            }
        }

        #[cfg(not(feature = "std"))]
        pub fn new(seed: u64) -> Self {
            let kdk = random_16b(seed);
            Self {
                kdk,
                used_time: 0,
                key_gen_counter: 0,
            }
        }

        pub fn gen_key(&mut self, pos_as_nonce: u64) -> FsResult<Key128> {
            #[cfg(not(feature = "std"))]
            if self.used_time >= 16 {
                self.kdk = random_16b(pos_as_nonce);
                self.used_time = 0;
            }

            #[cfg(feature = "std")]
            if self.used_time >= 16 {
                self.kdk = random_16b();
                self.used_time = 0;
            }

            let key = generate_random_key(&self.kdk, self.key_gen_counter, pos_as_nonce)?;
            self.key_gen_counter += 1;

            Ok(key)
        }
    }
}
pub use key_gen::*;

pub fn half_md4(buf: &[u8]) -> FsResult<u64> {
    let mut hasher = Md4::new();

    hasher.update(buf);

    let hash: [u8; 16] = hasher.finalize().try_into().map_err(
        |_| new_error!(FsError::UnknownError)
    )?;

    Ok(u64::from_le_bytes(hash[4..12].try_into().unwrap()))
}
