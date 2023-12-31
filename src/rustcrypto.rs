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
	let peer_pubkey = &encrypted_part[4..PublicKey::BYTES+4];
	log::debug!("   RustCrypto decrypt() peer_pubkey({}): {:02x?}", peer_pubkey.len(), peer_pubkey.iter());
    log::debug!("   RustCrypto decrypt() sender_pubkey({}): {:02x?}", sender_pubkey.clone().unwrap().as_slice().len(), sender_pubkey.iter());

	if sender_pubkey.is_some() && sender_pubkey.clone().unwrap().as_slice() != peer_pubkey {
		return Err(Crypt4GHError::InvalidPeerPubPkey);
	}

    let nonce = GenericArray::<u8, U12>::from_slice(crate::NONCE);
    let packet_data = &encrypted_part[44+4..];

    let client_sk = SecretKey::try_from(&privkey[0..SecretKey::BYTES]).map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
    let server_pk = PublicKey::try_from(peer_pubkey).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

    let keypair = Keypair::from(client_sk);
    let client_session_keys = keypair.session_keys_to(&server_pk);
    let shared_key = GenericArray::<u8, U32>::from_slice(&client_session_keys.tx.as_ref().as_slice());

    let cipher = ChaCha20Poly1305::new(shared_key);

	log::debug!("    RustCrypto peer pubkey: {:02x?}", peer_pubkey.iter());
	log::debug!("    RustCrypto nonce: {:02x?}", nonce.iter());
	log::debug!(
		"    RustCrypto encrypted data ({}): {:02x?}",
		packet_data.len(),
		packet_data.iter()
	);

    let plaintext = cipher.decrypt(nonce, packet_data)
        .map_err(|_| Crypt4GHError::UnableToDecryptBlock)?;

    Ok(plaintext)
}

/// Encrypts using RustCrypto crates instead of sodiumoxide
pub fn encrypt_with_rustcrypto(
	data: &[u8],
	seckey: &[u8],
	recipient_pubkey: &[u8],
) -> Result<Vec<u8>, Crypt4GHError> {

    let server_sk = SecretKey::try_from(&seckey[0..SecretKey::BYTES]).map_err(|_| Crypt4GHError::BadClientPrivateKey)?;
    let client_pk = PublicKey::try_from(recipient_pubkey).map_err(|_| Crypt4GHError::BadServerPublicKey)?;

    let pubkey = server_sk.public_key();


	log::debug!("   RustCrypto encrypt() packed data({}): {:02x?}", data.len(), data.iter());
	log::debug!("   RustCrypto encrypt() public key({}): {:02x?}", pubkey.as_ref().len(), pubkey.as_ref().iter());
	log::debug!(
		"   RustCrypto encrypt() private key({}): {:02x?}",
		seckey[0..32].len(),
		&seckey[0..32].iter()
	);
	log::debug!(
		"   RustCrypto encrypt() recipient public key({}): {:02x?}",
		recipient_pubkey.len(),
		recipient_pubkey.iter()
	);


    let nonce = GenericArray::<u8, U12>::from_slice(crate::NONCE);

    let keypair = Keypair::from(server_sk);
    let server_session_keys = keypair.session_keys_from(&client_pk);
    let shared_key = GenericArray::<u8, U32>::from_slice(&server_session_keys.rx.as_ref().as_slice());

    log::debug!("   RustCrypto encrypt() shared key: {:02x?}", shared_key);

    let cipher = ChaCha20Poly1305::new(shared_key);

    let ciphertext = cipher.encrypt(nonce, data)
        .map_err(|_| Crypt4GHError::UnableToDecryptBlock)?;

    Ok(vec![
        [0,0,0,0].as_ref(),
        pubkey.as_ref(),
        nonce.as_slice(),
        ciphertext.as_slice()
    ].concat())
}