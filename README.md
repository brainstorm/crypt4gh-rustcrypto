# Purpose

This is an experimentation area for an eventual removal of [libsodium-sys][libsodium-sys] and [sodiumoxide][sodiumoxide] crypto crates from [crypt4gh-rust][crypt4gh-rust], with the goal of making the latter safer and not deprecated (the former crates are marked as deprecated, unmantained and vulnerable on various sources).

# Quickstart

```shell
$ RUST_LOG=debug cargo run
```

[libsodium-sys]: https://github.com/sodiumoxide/sodiumoxide/tree/master/libsodium-sys
[sodiumoxide]: https://github.com/sodiumoxide/sodiumoxide/tree/master
[crypt4gh-rust]: https://github.com/EGA-archive/crypt4gh-rust/
