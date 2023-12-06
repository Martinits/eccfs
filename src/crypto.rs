use aes_gcm::{
    aead::{Aead, AeadInPlace, Tag, AeadCore, KeyInit},
    Aes128Gcm, Nonce, Key
};
use sha3::{Digest, Sha3_256};
use crate::*;

pub type Nonce96 = [u8; 12];
pub type Key128 = [u8; 16];
pub type MAC128 = [u8; 16];
pub type Hash256 = [u8; 32];
pub type KeyEntry = [u8; 32];

pub const KEY_ENTRY_SZ: usize = 32;

pub fn sha3_256_blk(input: &Block) -> FsResult<Hash256> {
    let mut hasher = Sha3_256::new();

    hasher.update(input);

    let hash = hasher.finalize().try_into().map_err(
        |_| FsError::UnknownError
    )?;

    Ok(hash)
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

mod tests {
    use sha3::{Digest, Sha3_256};
    #[test]
    fn sha3_256() {
        let mut hasher = Sha3_256::new();
        let input = "abcdefghijklmnopqrstuvwxyz";

        hasher.update(input);

        let result = hasher.finalize();

        println!("sha3 on {} results {:02X?}.", input, &result[..]);
    }

    use aes_gcm::{
        aead::{Aead, AeadCore, KeyInit},
        Aes128Gcm, Nonce, Key
    };
    #[test]
    fn aes_gcm_128_simple() {

        let key = Key::<Aes128Gcm>::from_slice(b"1234567890123456");
        let input = b"abc";

        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(b"123456789012");
        let ciphertext = cipher.encrypt(&nonce, input.as_ref()).unwrap();
        println!("{:02X?}", ciphertext);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, input);
    }

    use crate::*;
    use super::aes_gcm_128_blk_dec;
    use super::aes_gcm_128_blk_enc;
    use super::Key128;
    use super::Nonce96;
    #[test]
    fn aes_gcm_128() {
        let plain: Block = [14; 4096];
        let mut buffer = plain.clone();
        let key: Key128 = [3; 16];

        let mac = aes_gcm_128_blk_enc(&mut buffer, &key, 123).unwrap();

        let plain_out = aes_gcm_128_blk_dec(&mut buffer, &key, &mac, 123).unwrap();

        assert_eq!(plain, buffer);
    }
}
