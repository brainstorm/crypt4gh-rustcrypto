use std::collections::HashSet;
use crypt4gh_de_sodiumoxide::crypt4gh::decrypt_with_crypt4gh;
use hex_literal::hex;

use crypt4gh_de_sodiumoxide::error::Crypt4GHError;
use crypt4gh_de_sodiumoxide::{Keys, rustcrypto, crypt4gh, libsodium_init};

const PLAINTEXT: &[u8] = &[
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

// Alice's keypair
const ALICE_SECRET_KEY: [u8; 32] =
    hex!("68f208412d8dd5db9d0c6d18512e86f0ec75665ab841372d57b042b27ef89d4c");
const ALICE_PUBLIC_KEY: [u8; 32] =
    hex!("ac3a70ba35df3c3fae427a7c72021d68f2c1e044040b75f17313c0c8b5d4241d");

// Bob's keypair
const BOB_SECRET_KEY: [u8; 32] =
    hex!("b581fb5ae182a16f603f39270d4e3b95bc008310b727a11dd4e784a0044d461b");
const BOB_PUBLIC_KEY: [u8; 32] =
    hex!("e8980c86e032f1eb2975052e8d65bddd15c3b59641174ec9678a53789d92c754");


fn main() -> Result<(), Crypt4GHError> {
    pretty_env_logger::init(); // Setup logger
    libsodium_init(); // Init libsodium

    // Define encrypting keypair
    let mut encrypt_keys = HashSet::new();
    encrypt_keys.insert(Keys { method: 0, privkey: ALICE_SECRET_KEY.to_vec(), recipient_pubkey: BOB_PUBLIC_KEY.to_vec()});

    print!("Encrypting...\n");

    // Encrypt one packet
    let cipher_rustcrypto = rustcrypto::encrypt_with_rustcrypto(PLAINTEXT, &ALICE_SECRET_KEY, &BOB_PUBLIC_KEY)?;
    let cipher_crypt4gh = &crypt4gh::encrypt_with_crypt4gh(PLAINTEXT, &encrypt_keys)?[0];

    assert_eq!(cipher_rustcrypto, cipher_crypt4gh.clone());

    // Define decrypting keypair
    let decrypt_keys = Keys { method: 0, privkey: BOB_SECRET_KEY.to_vec(), recipient_pubkey: BOB_PUBLIC_KEY.to_vec()};

    println!("Decrypting...");

    // Decrypt one packet
    let plaintext_crypt4gh_sodiumoxide = decrypt_with_crypt4gh(vec![cipher_crypt4gh.to_vec()], &[decrypt_keys], &Some(ALICE_PUBLIC_KEY.to_vec()));
    let plaintext_rustcrypto = rustcrypto::decrypt_with_rustcrypto(&cipher_rustcrypto, &BOB_SECRET_KEY, &Some(ALICE_PUBLIC_KEY.to_vec()))?;

    // Return sematics are (decrypted_packets, mut ignored_packets)...
    // so just get the decrypted_packets payload for a single packet because the PLAINTEXT is small?
    let comparable_crypt4gh_plaintext = plaintext_crypt4gh_sodiumoxide.0[0].clone();

    assert_eq!(plaintext_rustcrypto, comparable_crypt4gh_plaintext);
    assert_eq!(PLAINTEXT, plaintext_rustcrypto);
    assert_eq!(PLAINTEXT, comparable_crypt4gh_plaintext);

    println!("All clear!");

    Ok(())
}
