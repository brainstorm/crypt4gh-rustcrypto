use std::vec;

use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{self, ChaCha20Poly1305, KeyInit, consts::U12, consts::U32};

use crypto_kx::{ PublicKey, SecretKey, Keypair };

use crate::error::Crypt4GHError;

/// Decrypts using RustCrypto crates instead of sodiumoxide
pub fn decrypt_with_rustcrypto(
    encrypted_part: &[u8],
    privkey: &[u8],
    sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, Crypt4GHError> {
    let sk = SecretKey::from(privkey.into());
    let nonce = GenericArray::<u8, U12>::from_slice(crate::NONCE);

    let sender_pk_present = match sender_pubkey {
        Some(key) => key,
        _ => &vec![] // TODO: Handle properly
    };

    let sender_pk = PublicKey::from(sender_pk_present.as_slice());
    let client_pk = PublicKey::from(sender_pk);

    let keypair = Keypair::from(sk);
    let client_session_keys = keypair.session_keys_to(&client_pk);
    let shared_key = GenericArray::<u8, U32>::from_slice(&client_session_keys.rx.as_ref().as_slice());

    let cipher = ChaCha20Poly1305::new(shared_key);

    let plaintext = cipher.decrypt(nonce, encrypted_part)
        .map_err(|_| Crypt4GHError::UnableToDecryptBlock)?;

    Ok(plaintext)
}

/// Encrypts using RustCrypto crates instead of sodiumoxide
pub fn encrypt_with_rustcrypto(
	data: &[u8],
	seckey: &[u8],
	recipient_pubkey: &[u8],
) -> Result<Vec<u8>, Crypt4GHError> {
    let sk = SecretKey::from(seckey.into());
    let pk = sk.public_key().as_ref();
    let nonce = GenericArray::<u8, U12>::from_slice(crate::NONCE);

    let client_pk = PublicKey::from(recipient_pubkey);

    let keypair = Keypair::from(sk);
    let server_session_keys = keypair.session_keys_from(&client_pk);
    let shared_key = GenericArray::<u8, U32>::from_slice(&server_session_keys.tx.as_ref().as_slice());

    let cipher = ChaCha20Poly1305::new(shared_key);

    let ciphertext = cipher.decrypt(nonce, data)
        .map_err(|_| Crypt4GHError::UnableToDecryptBlock)?;

    Ok(vec![
        pk,
        nonce.as_slice(),
        ciphertext.as_slice()
    ].concat())
}