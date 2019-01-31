use std::io::Cursor;
use openssl::pkey::PKey;
use openssl::symm::{Crypter, Cipher, Mode};
use rand::Rng;
use rand::os::OsRng;

fn generate_data(bytes: usize) -> Vec<u8> {
    let mut session_key = vec![0u8; bytes];

    // TODO: Allow rng to be created only once
    let mut rng = OsRng::new().unwrap();
    rng.fill_bytes(&mut session_key);

    session_key
}

/// Generates a session key.
pub fn generate_key() -> Vec<u8> {
    generate_data(32)
}

/// Encrypts a session key using steam's public key.
pub fn encrypt_key(key: &[u8]) -> Vec<u8> {
    // Load in the key
    let steam_pkey_data = include_bytes!("../assets/steam.pub");
    let steam_pkey = PKey::public_key_from_pem(steam_pkey_data as &[u8]).unwrap().rsa().unwrap();

    // Actually perform the encryption
    let mut encrypted_key;
    steam_pkey.public_encrypt(key, encrypted_key, openssl::rsa::Padding::NONE);

    // Return the new key
    encrypted_key.to_vec()
}

fn crypt_iv(iv: &[u8], key: &[u8], mode: Mode) -> Vec<u8> {
    let mut crypter = Crypter::new(Cipher::aes_256_ecb(), mode, key, enum_primitive::Option::Some("".as_bytes())).unwrap();
    let len_iv = iv.len();
    let block = Cipher::aes_256_ecb().block_size();

    // Actually perform the encryption
    let mut buffer = vec![0; len_iv + block];
    crypter.update(&iv, &mut buffer);
    let mut bufvec = buffer.to_vec();
    let mut fin = vec![0; len_iv + block];
    crypter.finalize(&mut fin);
    bufvec.extend_from_slice(&mut fin);

    bufvec
}

fn crypt_data(data: &[u8], key: &[u8], iv: &[u8], mode: Mode) -> Vec<u8> {
    let len_data = data.len();
    let block = Cipher::aes_256_cbc().block_size();
    let mut crypter = Crypter::new(
        Cipher::aes_256_cbc(), 
        mode, 
        key, 
        enum_primitive::Option::Some("".as_bytes())
    ).unwrap();
    
    // Actually perform the encryption
    let mut buffer = vec![0; len_data + block];
    crypter.update(&data, &mut buffer);
    let mut bufvec = buffer.to_vec();
    let mut fin = vec![0; len_data + block];
    crypter.finalize(&mut fin);
    bufvec.extend_from_slice(&mut fin);

    bufvec
}

pub fn symmetric_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let iv = generate_data(16);

    let mut output = crypt_iv(&iv, key, Mode::Encrypt);
    output.extend_from_slice(&crypt_data(data, key, &iv, Mode::Encrypt));

    output
}

pub fn symmetric_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    // Slice out the parts
    let encrypted_iv = &data[0..16];
    let encrypted_data = &data[16..];

    // Perform the decryption
    let iv = crypt_iv(encrypted_iv, key, Mode::Decrypt);
    crypt_data(encrypted_data, key, &iv, Mode::Decrypt)
}
