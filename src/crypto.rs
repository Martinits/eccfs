pub type Key128 = [u8; 16];

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
    fn aes_gcm_128() {

        let key = Key::<Aes128Gcm>::from_slice(b"1234567890123456");
        let input = b"abc";

        let cipher = Aes128Gcm::new(&key);
        let nonce = Nonce::from_slice(b"123456789012");
        let ciphertext = cipher.encrypt(&nonce, input.as_ref()).unwrap();
        println!("{:02X?}", ciphertext);
        let plaintext = cipher.decrypt(&nonce, ciphertext.as_ref()).unwrap();
        assert_eq!(&plaintext, input);
    }
}
