use crate::Keys;
use crate::error::Crypt4GHError;
use std::error::Error;

use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::kx::{x25519blake2b, PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey};

/// Functions below are extracted (and slightly modified for simplicity) from crypt4gh-rust crate
/// Goal: Trying to substitute/rewrite this sodiumoxide deprecate function with RustCrypto's cryptobox crate...

/// Returns a tuple (Vec<u8>, Vec<u8>) of, apparently, (decrypted_packets, mut ignored_packets)...
/// proper names on return types for this be like ¯\_(ツ)_/¯
pub fn decrypt(
	encrypted_packets: Vec<Vec<u8>>,
	keys: &[Keys],
	sender_pubkey: &Option<Vec<u8>>,
) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
	let mut decrypted_packets = Vec::new();
	let mut ignored_packets = Vec::new();

	for packet in encrypted_packets {
		match decrypt_packet(&packet, keys, sender_pubkey) {
			Ok(decrypted_packet) => decrypted_packets.push(decrypted_packet),
			Err(e) => {
				log::warn!("Ignoring packet because: {}", e);
				ignored_packets.push(packet);
			},
		}
	}

	(decrypted_packets, ignored_packets)
}


fn decrypt_packet(packet: &[u8], keys: &[Keys], sender_pubkey: &Option<Vec<u8>>) -> Result<Vec<u8>, Crypt4GHError> {
	let packet_encryption_method =
		bincode::deserialize::<u32>(packet).map_err(|_| Crypt4GHError::ReadPacketEncryptionMethod)?;
	log::debug!("Header Packet Encryption Method: {}", packet_encryption_method);

	for key in keys {
		if packet_encryption_method != u32::from(key.method) {
			continue;
		}

		match packet_encryption_method {
			0 => return decrypt_x25519_chacha20_poly1305_crypt4gh_rust_original(&packet[4..], &key.privkey, sender_pubkey),
			1 => unimplemented!("AES-256-GCM support is not implemented"),
			n => return Err(Crypt4GHError::BadHeaderEncryptionMethod(n)),
		}
	}

	Err(Crypt4GHError::UnableToEncryptPacket)
}

/// Gets the public key from a private key
///
/// Computes the curve25519 `scalarmult_base` to the first 32 bytes of `sk`.
/// `sk` must be at least 32 bytes.
pub fn get_public_key_from_private_key(sk: &[u8]) -> Result<Vec<u8>, Box<dyn Error>> {
	let scalar =
		sodiumoxide::crypto::scalarmult::Scalar::from_slice(&sk[0..32]).unwrap();
	let pubkey = sodiumoxide::crypto::scalarmult::scalarmult_base(&scalar).0;
	Ok(pubkey.to_vec())
}

fn decrypt_x25519_chacha20_poly1305_crypt4gh_rust_original(
	encrypted_part: &[u8],
	privkey: &[u8],
	sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, Crypt4GHError> {
	println!("    my secret key: {:02x?}", &privkey[0..32].iter());

	let peer_pubkey = &encrypted_part[0..32];

	if sender_pubkey.is_some() && sender_pubkey.clone().unwrap().as_slice() != peer_pubkey {
		return Err(Crypt4GHError::InvalidPeerPubPkey);
	}

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&encrypted_part[32..44]).ok_or(Crypt4GHError::NoNonce)?;
	let packet_data = &encrypted_part[44..];

	log::debug!("    peer pubkey: {:02x?}", peer_pubkey.iter());
	log::debug!("    nonce: {:02x?}", nonce.0.iter());
	log::debug!(
		"    encrypted data ({}): {:02x?}",
		packet_data.len(),
		packet_data.iter()
	);

	// X25519 shared key
	let pubkey = get_public_key_from_private_key(privkey).unwrap();
	let client_pk = SodiumPublicKey::from_slice(&pubkey).ok_or(Crypt4GHError::BadClientPublicKey)?;
	let client_sk = SodiumSecretKey::from_slice(&privkey[0..32]).ok_or(Crypt4GHError::BadClientPrivateKey)?;
	let server_pk = SodiumPublicKey::from_slice(peer_pubkey).ok_or(Crypt4GHError::BadServerPublicKey)?;
	let (shared_key, _) = x25519blake2b::client_session_keys(&client_pk, &client_sk, &server_pk).map_err(|_| Crypt4GHError::BadSharedKey)?;

	log::debug!("shared key: {:02x?}", shared_key.0.iter());

	// Chacha20_Poly1305
	let key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0).ok_or(Crypt4GHError::BadSharedKey)?;

	chacha20poly1305_ietf::open(packet_data, None, &nonce, &key).map_err(|_| Crypt4GHError::InvalidData)
}