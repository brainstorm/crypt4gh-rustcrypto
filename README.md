# Purpose

This is an experimentation area for an eventual removal of [libsodium-sys][libsodium-sys] and [sodiumoxide][sodiumoxide] crypto crates from [crypt4gh-rust][crypt4gh-rust], with the goal of making the latter safer and not deprecated (the former crates are marked as deprecated, unmantained and vulnerable on various sources).

# Quickstart

```shell
$ RUST_LOG=debug cargo run
```

If all goes well you should see the following output:

```
    Finished dev [unoptimized + debuginfo] target(s) in 0.14s
     Running `target/debug/crypt4gh-de-sodiumoxide`
Encrypting...
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto encrypt() packed data(131): Iter([be, 07, 5f, c5, 3c, 81, f2, d5, cf, 14, 13, 16, eb, eb, 0c, 7b, 52, 28, c5, 2a, 4c, 62, cb, d4, 4b, 66, 84, 9b, 64, 24, 4f, fc, e5, ec, ba, af, 33, bd, 75, 1a, 1a, c7, 28, d4, 5e, 6c, 61, 29, 6c, dc, 3c, 01, 23, 35, 61, f4, 1d, b6, 6c, ce, 31, 4a, db, 31, 0e, 3b, e8, 25, 0c, 46, f0, 6d, ce, ea, 3a, 7f, a1, 34, 80, 57, e2, f6, 55, 6a, d6, b1, 31, 8a, 02, 4a, 83, 8f, 21, af, 1f, de, 04, 89, 77, eb, 48, f5, 9f, fd, 49, 24, ca, 1c, 60, 90, 2e, 52, f0, a0, 89, bc, 76, 89, 70, 40, e0, 82, f9, 37, 76, 38, 48, 64, 5e, 07, 05])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto encrypt() public key(32): Iter([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto encrypt() private key(32): Iter([68, f2, 08, 41, 2d, 8d, d5, db, 9d, 0c, 6d, 18, 51, 2e, 86, f0, ec, 75, 66, 5a, b8, 41, 37, 2d, 57, b0, 42, b2, 7e, f8, 9d, 4c])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto encrypt() recipient public key(32): Iter([e8, 98, 0c, 86, e0, 32, f1, eb, 29, 75, 05, 2e, 8d, 65, bd, dd, 15, c3, b5, 96, 41, 17, 4e, c9, 67, 8a, 53, 78, 9d, 92, c7, 54])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto encrypt() shared key: [74, aa, eb, 90, a3, 1d, a2, 9a, b7, c6, c7, 59, 59, ca, 1b, af, 35, 04, a8, d8, 88, a2, d8, 59, 91, ca, ce, 12, 5a, ee, 8e, 4f]
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH encrypt() packed data(131): Iter([be, 07, 5f, c5, 3c, 81, f2, d5, cf, 14, 13, 16, eb, eb, 0c, 7b, 52, 28, c5, 2a, 4c, 62, cb, d4, 4b, 66, 84, 9b, 64, 24, 4f, fc, e5, ec, ba, af, 33, bd, 75, 1a, 1a, c7, 28, d4, 5e, 6c, 61, 29, 6c, dc, 3c, 01, 23, 35, 61, f4, 1d, b6, 6c, ce, 31, 4a, db, 31, 0e, 3b, e8, 25, 0c, 46, f0, 6d, ce, ea, 3a, 7f, a1, 34, 80, 57, e2, f6, 55, 6a, d6, b1, 31, 8a, 02, 4a, 83, 8f, 21, af, 1f, de, 04, 89, 77, eb, 48, f5, 9f, fd, 49, 24, ca, 1c, 60, 90, 2e, 52, f0, a0, 89, bc, 76, 89, 70, 40, e0, 82, f9, 37, 76, 38, 48, 64, 5e, 07, 05])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH encrypt() public key(32): Iter([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH encrypt() private key(32): Iter([68, f2, 08, 41, 2d, 8d, d5, db, 9d, 0c, 6d, 18, 51, 2e, 86, f0, ec, 75, 66, 5a, b8, 41, 37, 2d, 57, b0, 42, b2, 7e, f8, 9d, 4c])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH encrypt() recipient public key(32): Iter([e8, 98, 0c, 86, e0, 32, f1, eb, 29, 75, 05, 2e, 8d, 65, bd, dd, 15, c3, b5, 96, 41, 17, 4e, c9, 67, 8a, 53, 78, 9d, 92, c7, 54])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH encrypt() shared key: Iter([74, aa, eb, 90, a3, 1d, a2, 9a, b7, c6, c7, 59, 59, ca, 1b, af, 35, 04, a8, d8, 88, a2, d8, 59, 91, ca, ce, 12, 5a, ee, 8e, 4f])
Decrypting...
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   > Header Packet Encryption Method: 0
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH secret key: Iter([b5, 81, fb, 5a, e1, 82, a1, 6f, 60, 3f, 39, 27, 0d, 4e, 3b, 95, bc, 00, 83, 10, b7, 27, a1, 1d, d4, e7, 84, a0, 04, 4d, 46, 1b])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >    Crypt4GH decrypt() peer_pubkey(32): Iter([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >     Crypt4GH peer pubkey: Iter([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >     Crypt4GH nonce: Iter([01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   >     Crypt4GH encrypted data (147): Iter([0c, 9a, 1b, fa, 07, 05, 85, ae, b8, cb, dd, 80, f3, 5d, b1, 55, 8b, 14, a9, a2, 11, c5, 28, 18, c0, 78, 69, 90, da, 61, 84, 63, db, 80, 9d, 3a, 93, 94, 76, 48, d1, 4b, 9f, a9, 17, 9a, f7, 8f, 20, 33, ef, 0f, 2a, e5, 8a, cf, 7f, 4b, 3d, 5e, 8e, 05, 9e, 96, 31, e3, c8, 86, 7d, 94, 3e, 90, 79, fa, 88, 87, ed, 01, 3c, b6, ba, 0a, 1a, ed, cb, 79, 5c, 65, 6b, fa, e5, b7, e4, f8, 65, 60, 5d, e3, 93, 12, 4b, 63, 18, e2, 61, c3, 94, 88, f3, 46, fc, a9, f9, e1, 9d, 34, b3, aa, b0, 56, 44, 3c, a5, dc, e2, 9a, f1, ba, f5, af, d2, 16, 34, 36, d8, 65, c7, 34, c5, 79, 4c, 4e, 7e, be, 88, e3, df])
 DEBUG crypt4gh_de_sodiumoxide::crypt4gh   > shared key: Iter([74, aa, eb, 90, a3, 1d, a2, 9a, b7, c6, c7, 59, 59, ca, 1b, af, 35, 04, a8, d8, 88, a2, d8, 59, 91, ca, ce, 12, 5a, ee, 8e, 4f])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto decrypt() peer_pubkey(32): Iter([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >    RustCrypto decrypt() sender_pubkey(32): Iter { inner: Item { opt: Some([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d]) } }
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >     RustCrypto peer pubkey: Iter([ac, 3a, 70, ba, 35, df, 3c, 3f, ae, 42, 7a, 7c, 72, 02, 1d, 68, f2, c1, e0, 44, 04, 0b, 75, f1, 73, 13, c0, c8, b5, d4, 24, 1d])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >     RustCrypto nonce: Iter([01, 02, 03, 04, 05, 06, 07, 08, 09, 0a, 0b, 0c])
 DEBUG crypt4gh_de_sodiumoxide::rustcrypto >     RustCrypto encrypted data (147): Iter([0c, 9a, 1b, fa, 07, 05, 85, ae, b8, cb, dd, 80, f3, 5d, b1, 55, 8b, 14, a9, a2, 11, c5, 28, 18, c0, 78, 69, 90, da, 61, 84, 63, db, 80, 9d, 3a, 93, 94, 76, 48, d1, 4b, 9f, a9, 17, 9a, f7, 8f, 20, 33, ef, 0f, 2a, e5, 8a, cf, 7f, 4b, 3d, 5e, 8e, 05, 9e, 96, 31, e3, c8, 86, 7d, 94, 3e, 90, 79, fa, 88, 87, ed, 01, 3c, b6, ba, 0a, 1a, ed, cb, 79, 5c, 65, 6b, fa, e5, b7, e4, f8, 65, 60, 5d, e3, 93, 12, 4b, 63, 18, e2, 61, c3, 94, 88, f3, 46, fc, a9, f9, e1, 9d, 34, b3, aa, b0, 56, 44, 3c, a5, dc, e2, 9a, f1, ba, f5, af, d2, 16, 34, 36, d8, 65, c7, 34, c5, 79, 4c, 4e, 7e, be, 88, e3, df])
All clear!
```

[libsodium-sys]: https://github.com/sodiumoxide/sodiumoxide/tree/master/libsodium-sys
[sodiumoxide]: https://github.com/sodiumoxide/sodiumoxide/tree/master
[crypt4gh-rust]: https://github.com/EGA-archive/crypt4gh-rust/
