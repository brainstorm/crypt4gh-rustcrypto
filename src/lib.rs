pub mod error;
pub mod rustcrypto;
pub mod crypt4gh;

use std::sync::Once;

//use hex_literal::hex;

/// WARNING!!! Re-using the nonce for comparing/reproducibility, NEVER NEVER NEVER use this or make this (unintentional) mistake
/// in production code!!!
//pub const NONCE: &[u8; 24] = &hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");
//
// TODO: Shrinking to 12 elements to be compatible with Crypt4GH spec?
pub const NONCE: &[u8; 12] = &[1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

pub(crate) static SODIUM_INIT: Once = Once::new();

pub(crate) fn init() {
	pretty_env_logger::init();

	SODIUM_INIT.call_once(|| {
		sodiumoxide::init().expect("Unable to initialize libsodium");
	});
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
/// Key information.
pub struct Keys {
	/// Method used for the key encryption.
	/// > Only method 0 is supported.
	pub method: u8,
	/// Secret key of the encryptor / decryptor (your key).
	pub privkey: Vec<u8>,
	/// Public key of the recipient (the key you want to encrypt for).
	pub recipient_pubkey: Vec<u8>,
}