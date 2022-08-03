[![Cocoon](https://github.com/fadeevab/cocoon/workflows/Cocoon/badge.svg?event=push)](https://github.com/fadeevab/cocoon)
[![crates.io](https://img.shields.io/crates/v/cocoon.svg)](https://crates.io/crates/cocoon)
[![docs.rs](https://docs.rs/cocoon/badge.svg)](https://docs.rs/cocoon/)
[![license](https://img.shields.io/badge/license-MIT-blue.svg)](https://github.com/fadeevab/cocoon/LICENSE)
[![coverage](https://coveralls.io/repos/github/fadeevab/cocoon/badge.svg?branch=main)](https://coveralls.io/github/fadeevab/cocoon?branch=main)

# Cocoon

<img alt="Cocoon format" src="https://github.com/fadeevab/cocoon/raw/main/images/cocoon_format.svg" />

`MiniCocoon` and `Cocoon` are protected containers to wrap sensitive data with strong
[encryption](#cryptography) and format validation. A format of `MiniCocoon` and `Cocoon`
is developed for the following practical cases:

1. As an _encrypted file format_ to organize simple secure storage:
   1. Key store.
   2. Password store.
   3. Sensitive data store.
2. For _encrypted data transfer_:
   * As a secure in-memory container.

`Cocoon` is developed with security in mind. It aims to do the only one thing and do it
flawlessly. It has a minimal set of dependencies and a minimalist design to simplify control over
security aspects. It's a pure Rust implementation, and all dependencies are pure Rust
packages with disabled default features.

# Problem

Whenever you need to transmit and store data securely you reinvent the wheel: you have to
take care of how to encrypt data properly, how to handle randomly generated buffers,
then how to get data back, parse, and decrypt. Instead, you can use `MiniCocoon`
and `Cocoon`.

# Basic Usage

## 📌 Wrap/Unwrap

One party wraps private data into a container using `MiniCocoon::wrap`.
Another party (or the same one, or whoever knows the key) unwraps data
out of the container using `MiniCocoon::unwrap`.

`MiniCocoon` is preferred against `Cocoon` in a case of simple data encryption
because it generates a container with a smaller header without version control, and also
it allows to wrap data sequentially (wrap, wrap, wrap!) without performance drop
because of KDF calculation.
```rust
let cocoon = MiniCocoon::from_key(b"0123456789abcdef0123456789abcdef", &[0; 32]);

let wrapped = cocoon.wrap(b"my secret data")?;
assert_ne!(&wrapped, b"my secret data");

let unwrapped = cocoon.unwrap(&wrapped)?;
assert_eq!(unwrapped, b"my secret data");
```

## 📌 Dump/Parse

You can store data to file. Put data into `Vec` container, the data is going to be
encrypted _in place_ and stored in a file using the "cocoon" [format](#cocoon).

`Cocoon` is preferred as a long-time data storage, it has an extended header with a magic
number, options, and version control.
```rust
let mut data = b"my secret data".to_vec();
let cocoon = Cocoon::new(b"password");

cocoon.dump(data, &mut file)?;

let data = cocoon.parse(&mut file)?;
assert_eq!(&data, b"my secret data");
```

## 📌 Encrypt/Decrypt

You can encrypt data in place and avoid re-allocations. The method operates with a detached
meta-data (a container format prefix) in the array on the stack. It is suitable for "`no_std`"
build and whenever you want to evade re-allocations of a huge amount of data. You have to care
about how to store and transfer a data length and a container prefix though.

Both `MiniCocoon` and `Cocoon` have the same API, but prefixes are of different sizes.
`MiniCocoon` doesn't have the overhead of generating KDF on each encryption call, therefore
it's recommended for simple sequential encryption/decryption operations.
```rust
let mut data = "my secret data".to_owned().into_bytes();
let cocoon = MiniCocoon::from_key(b"0123456789abcdef0123456789abcdef", &[0; 32]);

let detached_prefix = cocoon.encrypt(&mut data)?;
assert_ne!(data, b"my secret data");

cocoon.decrypt(&mut data, &detached_prefix)?;
assert_eq!(data, b"my secret data");
```

# Study Case
You implement a database of secrets that must be stored in an encrypted file using a user
password. There are a lot of ways how your database can be represented in memory and how
it could be serialized. You handle these aspects on your own, e.g. you can use
`HashMap` to manage data and use `borsh`, or `bincode`,
to serialize the data. You can even compress a serialized buffer before encryption.

In the end, you use `Cocoon` to put the final image into an encrypted container.

```rust
use borsh::BorshSerialize;
use cocoon::{Cocoon, Error};

use std::collections::HashMap;
use std::fs::File;

// Your data can be represented in any way.
#[derive(BorshSerialize)]
struct Database {
    inner: HashMap<String, String>,
}

fn main() -> Result<(), Error> {
    let mut file = File::create("target/test.db")?;
    let mut db = Database { inner: HashMap::new() };

    // Over time you collect some kind of data.
    db.inner.insert("my.email@example.com".to_string(), "eKPV$PM8TV5A2".to_string());

    // You can choose how to serialize data. Also, you can compress it.
    let encoded = db.try_to_vec().unwrap();

    // Finally, you want to store your data secretly.
    // Supply some password to Cocoon: password is any byte array, basically.
    // Don't use a hard-coded password in real life!
    // It could be a user-supplied password.
    let cocoon = Cocoon::new(b"secret password");

    // Dump the serialized database into a file as an encrypted container.
    let container = cocoon.dump(encoded, &mut file)?;

    Ok(())
}
```

# Cryptography

256-bit cryptography is chosen as a `Cocoon` baseline.

| Cipher (AEAD)     | Key Derivation Function (KDF)    |
|-------------------|----------------------------------|
| Chacha20-Poly1305 | PBKDF2-SHA256: 100000 iterations |
| AES256-GCM        |                                  |

* Key: 256-bit.
* Salt for KDF: random 128-bit + predefined part.
* Nonce for encryption: random 96-bit.

Key derivation parameters comply with NIST SP 800-132 recommendations (salt, iterations),
and cipher parameters (key, nonce, length) fit requirements of a particular cipher.
AEAD is chosen in order to authenticate encrypted data together with an unencrypted header.

# Zeroization

Encryption key is wrapped into zeroizing container
(provided by `zeroize` crate), which means that the key is erased automatically once it is dropped.

# How It Works

See more implementation details on
[![docs.rs](https://docs.rs/cocoon/badge.svg)](https://docs.rs/cocoon/), e.g.
1. the process of [container creation](https://docs.rs/cocoon/#container-creation),
2. customizable [crate features](https://docs.rs/cocoon/#crate-features),
3. and of course [API](https://docs.rs/cocoon/#cocoon).