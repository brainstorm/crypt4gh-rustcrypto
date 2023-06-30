use chacha20poly1305::aead::Aead;
use chacha20poly1305::aead::generic_array::GenericArray;
use chacha20poly1305::{self, ChaCha20Poly1305, KeyInit, consts::U12, consts::U32};

use crate::error::Crypt4GHError;

/// Decrypts using RustCrypto crates instead of sodiumoxide
pub fn decrypt_with_rustcrypto(
    encrypted_part: &[u8],
    privkey: &[u8],
    _sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, Crypt4GHError> {
    let secret_key = GenericArray::<u8, U32>::from_slice(privkey);
    let cipher = ChaCha20Poly1305::new(secret_key);
    let nonce = GenericArray::<u8, U12>::from_slice(crate::NONCE);

    let plaintext = cipher.decrypt(nonce, encrypted_part)
        .map_err(|_| Crypt4GHError::UnableToDecryptBlock)?;

    Ok(plaintext)
}

/// Encrypts using RustCrypto crates instead of sodiumoxide
pub fn encrypt_with_rustcrypto(
	data: &[u8],
	seckey: &[u8],
	_recipient_pubkey: &[u8],
) -> Result<Vec<u8>, Crypt4GHError> {
    let secret_key = GenericArray::<u8, U32>::from_slice(seckey);
    let cipher = ChaCha20Poly1305::new(secret_key);
    let nonce = GenericArray::<u8, U12>::from_slice(crate::NONCE);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| Crypt4GHError::UnableToEncryptPacket)?;

    Ok(ciphertext)
}