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

pub fn ke_is_zero(ke: &KeyEntry) -> bool {
    *ke == [0u8; 32]
}

pub const KEY_ENTRY_SZ: usize = 32;

pub fn sha3_256_blk(input: &Block) -> FsResult<Hash256> {
    let mut hasher = Sha3_256::new();

    hasher.update(input);

    let hash = hasher.finalize().try_into().map_err(
        |_| FsError::UnknownError
    )?;

    Ok(hash)
}

pub fn sha3_256_blk_check(input: &Block, hash: &Hash256) -> FsResult<()> {
    let actual = sha3_256_blk(input)?;
    if actual != *hash {
        Err(FsError::IntegrityCheckError)
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
        |_| FsError::CryptoError
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
        |_| FsError::IntegrityCheckError
    )?;

    Ok(())
}

mod key_gen {
    use aes::Aes128;
    use cmac::{Cmac, Mac};
    use super::Key128;
    use crate::*;
    use rand_core::RngCore;
    use std::mem::size_of;

    #[repr(C)]
    struct KdfInput {
        idx: u32,
        label: [u8; 64],
        context: u64,
        nonce: [u8; 16],
        out_len: u32, //in bits
    }
    rw_as_blob!(KdfInput);

    pub fn generate_random_key(kdk: &Key128, counter: u32, pos: u64) -> FsResult<Key128> {
        let mut nonce = [0u8; 16];
        rand::thread_rng().fill_bytes(&mut nonce);

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
        pub fn new() -> Self {
            let mut kdk = [0u8; size_of::<Key128>()];
            rand::thread_rng().fill_bytes(&mut kdk);
            Self {
                kdk,
                used_time: 0,
                key_gen_counter: 0,
            }
        }

        pub fn gen_key(&mut self, pos_as_nonce: u64) -> FsResult<Key128> {
            if self.used_time >= 16 {
                rand::thread_rng().fill_bytes(&mut self.kdk);
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
        |_| FsError::UnknownError
    )?;

    Ok(u64::from_le_bytes(hash[4..12].try_into().unwrap()))
}

mod tests {
    #[test]
    fn sha3_256() {
        use sha3::{Digest, Sha3_256};

        let mut hasher = Sha3_256::new();
        let input = "abcdefghijklmnopqrstuvwxyz";

        hasher.update(input);

        let result = hasher.finalize();

        println!("sha3 on {} results {:02X?}.", input, &result[..]);
    }

    #[test]
    fn aes_gcm_128_simple() {
        use aes_gcm::{
            aead::{Aead, KeyInit},
            Aes128Gcm, Nonce, Key
        };

        let key = Key::<Aes128Gcm>::from_slice(b"1234567890123456");
        let input = b"abc";

        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(b"123456789012");
        let ciphertext = cipher.encrypt(&nonce, input.as_ref()).unwrap();
        println!("{:02X?}", ciphertext);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, input);
    }

    #[test]
    fn aes_gcm_128() {
        use crate::*;
        use super::aes_gcm_128_blk_dec;
        use super::aes_gcm_128_blk_enc;
        use super::Key128;

        let plain: Block = [14; 4096];
        let mut buffer = plain.clone();
        let key: Key128 = [3; 16];

        let mac = aes_gcm_128_blk_enc(&mut buffer, &key, 123).unwrap();

        let _plain_out = aes_gcm_128_blk_dec(&mut buffer, &key, &mac, 123).unwrap();

        assert_eq!(plain, buffer);
    }

    #[test]
    fn test_half_md4() {
        use super::half_md4;

        let buf = "hello!";

        let rs = half_md4(buf.as_bytes()).unwrap();

        println!("half md4 on {:?} results {:02X}.", buf, rs);
    }
}
