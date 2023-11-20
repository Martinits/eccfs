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

pub fn sha3_256_blk(input: &Block) -> Hash256 {
    let mut hasher = Sha3_256::new();

    hasher.update(input);

    hasher.finalize().try_into().unwrap()
}

pub fn aes_gcm_128_blk_enc(
    input: &Block,
    key: &Key128,
    nonce: &Nonce96
) -> FsResult<(Block, MAC128)> {
    let k = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(&k);
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Block = input.clone();
    let tag = cipher.encrypt_in_place_detached(
        &nonce, b"", &mut buffer
    ).map_err(
        |_| FsError::CryptoError
    )?;

    Ok((buffer, tag.try_into().unwrap()))
}

pub fn aes_gcm_128_blk_dec(
    input: &Block,
    key: &Key128,
    mac: &MAC128,
    nonce: &Nonce96
) -> FsResult<Block> {
    let k = Key::<Aes128Gcm>::from_slice(key);
    let cipher = Aes128Gcm::new(&k);
    let nonce = Nonce::from_slice(nonce);

    let mut buffer: Block = input.clone();
    cipher.decrypt_in_place_detached(
        &nonce, b"", &mut buffer, Tag::<Aes128Gcm>::from_slice(mac)
    ).map_err(
        |_| FsError::CryptoError
    )?;

    Ok(buffer)
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
        let key: Key128 = [3; 16];
        let nonce: Nonce96 = [5; 12];

        let (cipher, mac) = aes_gcm_128_blk_enc(&plain, &key, &nonce).unwrap();

        let plain_out = aes_gcm_128_blk_dec(&cipher, &key, &mac, &nonce).unwrap();

        assert_eq!(plain, plain_out);
    }
}
