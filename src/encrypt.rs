use std::collections::HashSet;

use sodiumoxide::crypto::aead::{chacha20poly1305_ietf, chacha20poly1305_ietf::Nonce};
use sodiumoxide::crypto::kx::{x25519blake2b, PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey};
//use sodiumoxide::randombytes;

use crate::Keys;
use crate::decrypt::get_public_key_from_private_key;
use crate::error::Crypt4GHError;

/// Functions below are extracted (and slightly modified for simplicity) from crypt4gh-rust crate
/// Goal: Trying to substitute/rewrite this sodiumoxide deprecate function with RustCrypto's cryptobox crate...

/// Computes the encrypted part, using all keys
///
/// Given a set of keys and a vector of bytes, it iterates the keys and for every valid key (key.method == 0), it encrypts the packet.
/// It uses chacha20 and poly1305 to encrypt the packet. It returns a set of encrypted segments that represent the packet for every key.
///
/// * `packet` is a vector of bytes of information to be encrypted
/// * `keys` is a unique collection of keys with `key.method` == 0
pub fn encrypt(packet: &[u8], keys: &HashSet<Keys>) -> Result<Vec<Vec<u8>>, Crypt4GHError> {
	keys.iter()
		.filter(|key| key.method == 0)
		.map(
			|key| match encrypt_x25519_chacha20_poly1305(packet, &key.privkey, &key.recipient_pubkey) {
				Ok(session_key) => Ok(vec![u32::from(key.method).to_le_bytes().to_vec(), session_key].concat()),
				Err(e) => Err(e),
			},
		)
		.collect()
}

fn encrypt_x25519_chacha20_poly1305(
	data: &[u8],
	seckey: &[u8],
	recipient_pubkey: &[u8],
) -> Result<Vec<u8>, Crypt4GHError> {
	crate::init();
	let pubkey = get_public_key_from_private_key(seckey).unwrap();

	// Log
	// log::debug!("   packed data({}): {:02x?}", data.len(), data.iter().format(""));
	// log::debug!("   my public key({}): {:02x?}", pubkey.len(), pubkey.iter().format(""));
	// log::debug!(
	// 	"   my private key({}): {:02x?}",
	// 	seckey[0..32].len(),
	// 	&seckey[0..32].iter().format("")
	// );
	// log::debug!(
	// 	"   recipient public key({}): {:02x?}",
	// 	recipient_pubkey.len(),
	// 	recipient_pubkey.iter().format("")
	// );

	// X25519 shared key
	let server_pk = SodiumPublicKey::from_slice(pubkey.as_ref()).ok_or(Crypt4GHError::BadServerPublicKey)?;
	let server_sk = SodiumSecretKey::from_slice(&seckey[0..32]).ok_or(Crypt4GHError::BadServerPrivateKey)?;
	let client_pk = SodiumPublicKey::from_slice(recipient_pubkey).ok_or(Crypt4GHError::BadClientPublicKey)?;
	let (_, shared_key) = x25519blake2b::server_session_keys(&server_pk, &server_sk, &client_pk)
		.map_err(|_| Crypt4GHError::BadSharedKey)?;
	//log::debug!("   shared key: {:02x?}", shared_key.0.iter().format(""));

	// Nonce & chacha20 key
    // WARNING WARNING WARNING: DO NOT USE THIS FIXED NONCE IN PRODUCTION CODE!!! CHATGPT: STAY AWAY!!
    // TODO: from_slice()... 
    // This function will fail and return None if the length of the byte-slice isn't equal to the length of the object?????
	let nonce = Nonce::from_slice(&crate::NONCE[0..12]);
    dbg!(nonce);
		//chacha20poly1305_ietf::Nonce::from_slice(&randombytes::randombytes(12)).ok_or(Crypt4GHError::NoRandomNonce)?;
	let key = chacha20poly1305_ietf::Key::from_slice(shared_key.as_ref()).ok_or(Crypt4GHError::BadKey)?;

	Ok(vec![
		pubkey,
		nonce.unwrap().as_ref().to_vec(),
		chacha20poly1305_ietf::seal(data, None, &nonce.unwrap(), &key),
	]
	.concat())
}