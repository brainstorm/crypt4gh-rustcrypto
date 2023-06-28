use crypto_box::{ChaChaBox, SecretKey, PublicKey, aead::Aead};
use std::error::Error;
use hex_literal::hex;

use sodiumoxide::crypto::aead::chacha20poly1305_ietf;
use sodiumoxide::crypto::kx::{x25519blake2b, PublicKey as SodiumPublicKey, SecretKey as SodiumSecretKey};

const _PLAINTEXT: &[u8] = &[
    0xbe, 0x07, 0x5f, 0xc5, 0x3c, 0x81, 0xf2, 0xd5, 0xcf, 0x14, 0x13, 0x16, 0xeb, 0xeb, 0x0c, 0x7b,
    0x52, 0x28, 0xc5, 0x2a, 0x4c, 0x62, 0xcb, 0xd4, 0x4b, 0x66, 0x84, 0x9b, 0x64, 0x24, 0x4f, 0xfc,
    0xe5, 0xec, 0xba, 0xaf, 0x33, 0xbd, 0x75, 0x1a, 0x1a, 0xc7, 0x28, 0xd4, 0x5e, 0x6c, 0x61, 0x29,
    0x6c, 0xdc, 0x3c, 0x01, 0x23, 0x35, 0x61, 0xf4, 0x1d, 0xb6, 0x6c, 0xce, 0x31, 0x4a, 0xdb, 0x31,
    0x0e, 0x3b, 0xe8, 0x25, 0x0c, 0x46, 0xf0, 0x6d, 0xce, 0xea, 0x3a, 0x7f, 0xa1, 0x34, 0x80, 0x57,
    0xe2, 0xf6, 0x55, 0x6a, 0xd6, 0xb1, 0x31, 0x8a, 0x02, 0x4a, 0x83, 0x8f, 0x21, 0xaf, 0x1f, 0xde,
    0x04, 0x89, 0x77, 0xeb, 0x48, 0xf5, 0x9f, 0xfd, 0x49, 0x24, 0xca, 0x1c, 0x60, 0x90, 0x2e, 0x52,
    0xf0, 0xa0, 0x89, 0xbc, 0x76, 0x89, 0x70, 0x40, 0xe0, 0x82, 0xf9, 0x37, 0x76, 0x38, 0x48, 0x64,
    0x5e, 0x07, 0x05,
    ];

const CIPHERTEXT: &[u8] = &hex!(
        "0cd5ed093de698c8e410d0d451df2f5283057376b947b9b7392b956e5d675f309218acce8cf85f6c"
        "f6a9e2e09ef8c5b0f97c661ee21b1b3418be566692634056a92b4034d5d0cf14c52420a488b7f0da"
        "0c5740dfc6b85397d3a8f679e84303e8d3f8b048abdb2dd79183b0a62683a1bc2a527fc9b82c5ffa"
        "c4a684bcfeadfdcd28930b2dbe597f4716a658ccfca5b44049e06c"
    );

const NONCE: &[u8; 24] = &hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");

// Alice's keypair
const ALICE_SECRET_KEY: [u8; 32] =
    hex!("68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c");
const _ALICE_PUBLIC_KEY: [u8; 32] =
    hex!("ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d");

// Bob's keypair
const _BOB_SECRET_KEY: [u8; 32] =
    hex!("b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b");
const BOB_PUBLIC_KEY: [u8; 32] =
    hex!("e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754");

fn decrypt_x25519_chacha20_poly1305(
    encrypted_part: &[u8],
    privkey: &[u8],
    sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, Box<dyn Error>> {
    let sender_pubkey_bytes = sender_pubkey.as_ref().unwrap();

    let secret_key = SecretKey::from_slice(privkey).unwrap();
    let public_key = PublicKey::from_slice(sender_pubkey_bytes.as_slice()).unwrap();

    let plaintext = ChaChaBox::new(&public_key, &secret_key)
        .decrypt(NONCE.into(), encrypted_part).unwrap();

    Ok(plaintext)
}

/// Functions below are extracted (and slightly modified for simplicity) from crypt4gh-rust crate
/// Goal: Trying to substitute/rewrite this sodiumoxide deprecate function with RustCrypto's cryptobox crate...

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
	_sender_pubkey: &Option<Vec<u8>>,
) -> Result<Vec<u8>, ()> {
	//log::debug!("    my secret key: {:02x?}", &privkey[0..32].iter().format(""));

	let peer_pubkey = &encrypted_part[0..32];

	// if sender_pubkey.is_some() && sender_pubkey.clone().unwrap().as_slice() != peer_pubkey {
	// 	return Err(Crypt4GHError::InvalidPeerPubPkey);
	// }

	let nonce = sodiumoxide::crypto::aead::chacha20poly1305_ietf::Nonce::from_slice(&encrypted_part[32..44]).unwrap();
		//.ok_or(Crypt4GHError::NoNonce)?;
	let packet_data = &encrypted_part[44..];

	// log::debug!("    peer pubkey: {:02x?}", peer_pubkey.iter().format(""));
	// log::debug!("    nonce: {:02x?}", nonce.0.iter().format(""));
	// log::debug!(
	// 	"    encrypted data ({}): {:02x?}",
	// 	packet_data.len(),
	// 	packet_data.iter().format("")
	// );

	// X25519 shared key
	let pubkey = get_public_key_from_private_key(privkey).unwrap();
	let client_pk = SodiumPublicKey::from_slice(&pubkey).unwrap();
	let client_sk = SodiumSecretKey::from_slice(&privkey[0..32]).unwrap();
	let server_pk = SodiumPublicKey::from_slice(peer_pubkey).unwrap();
	let (shared_key, _) = x25519blake2b::client_session_keys(&client_pk, &client_sk, &server_pk).unwrap();
	//log::debug!("shared key: {:02x?}", shared_key.0.iter().format(""));

	// Chacha20_Poly1305
	let key = chacha20poly1305_ietf::Key::from_slice(&shared_key.0).unwrap();

	chacha20poly1305_ietf::open(packet_data, None, &nonce, &key)
}

fn main() {
    let plaintext_rustcrypto = decrypt_x25519_chacha20_poly1305(CIPHERTEXT, &ALICE_SECRET_KEY, &Some(BOB_PUBLIC_KEY.to_vec())).unwrap();
    let plaintext_crypt4gh_sodiumoxide = decrypt_x25519_chacha20_poly1305_crypt4gh_rust_original(CIPHERTEXT, &ALICE_SECRET_KEY, &Some(BOB_PUBLIC_KEY.to_vec())).unwrap();

    assert_eq!(plaintext_rustcrypto, plaintext_crypt4gh_sodiumoxide);
}
