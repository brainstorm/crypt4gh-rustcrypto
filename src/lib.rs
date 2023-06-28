pub mod error;
pub mod decrypt;
pub mod encrypt;

use hex_literal::hex;

use std::sync::Once;

/// WARNING!!! Re-using the nonce for comparing/reproducibility, NEVER NEVER NEVER use this or make this (unintentional) mistake
/// in production code!!!
pub const NONCE: &[u8; 24] = &hex!("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37");

pub(crate) static SODIUM_INIT: Once = Once::new();

pub(crate) fn init() {
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