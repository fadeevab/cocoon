//! # Cocoon
//!
//! <img alt="Cocoon format" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_format.svg" />
//!
//! [`MiniCocoon`] and [`Cocoon`] are protected containers to wrap sensitive data with strong
//! [encryption](#cryptography) and format validation. A format of [`MiniCocoon`] and [`Cocoon`]
//! is developed for the following practical cases:
//!
//! 1. As an _encrypted file format_ to organize simple secure storage:
//!    1. Key store.
//!    2. Password store.
//!    3. Sensitive data store.
//! 2. For _encrypted data transfer_:
//!    * As a secure in-memory container.
//!
//! Cocoon is developed with security in mind. It aims to do the only one thing and do it
//! flawlessly. It has a minimal set of dependencies and a minimalist design to simplify control
//! over security aspects. It's a pure Rust implementation, and all dependencies are pure Rust
//! packages with disabled default features.
//!
//! # Problem
//!
//! Whenever you need to transmit and store data securely you reinvent the wheel: you have to
//! take care of how to encrypt data properly, how to handle randomly generated buffers,
//! then how to get data back, parse, and decrypt. Instead, you can use [`MiniCocoon`]
//! and [`Cocoon`].
//!
//! # Basic Usage
//!
//! ## Wrap/Unwrap
//! 📌 [`wrap`](MiniCocoon::wrap)/[`unwrap`](MiniCocoon::unwrap)
//!
//! One party wraps private data into a container using [`MiniCocoon::wrap`].
//! Another party (or the same one, or whoever knows the key) unwraps data
//! out of the container using [`MiniCocoon::unwrap`].
//!
//! [`MiniCocoon`] is preferred against [`Cocoon`] in a case of simple data encryption
//! because it generates a container with a smaller header without version control, and also
//! it allows to wrap data sequentially (wrap, wrap, wrap!) without performance drop
//! because of KDF calculation.
//!
//! ```
//! # use cocoon::{MiniCocoon, Error};
//! #
//! # fn main() -> Result<(), Error> {
//! let cocoon = MiniCocoon::from_key(b"0123456789abcdef0123456789abcdef", &[0; 32]);
//!
//! let wrapped = cocoon.wrap(b"my secret data")?;
//! assert_ne!(&wrapped, b"my secret data");
//!
//! let unwrapped = cocoon.unwrap(&wrapped)?;
//! assert_eq!(unwrapped, b"my secret data");
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Dump/Parse
//! 📌 [`dump`](Cocoon::dump)/[`parse`](Cocoon::parse)
//!
//! You can store data to file. Put data into [`Vec`] container, the data is going to be
//! encrypted _in place_ and stored in a file using the "cocoon" [format](#cocoon).
//!
//! [`Cocoon`] is preferred as a long-time data storage, it has an extended header with a magic
//! number, options, and version control.
//! ```
//! # use cocoon::{Cocoon, Error};
//! # use std::io::Cursor;
//! #
//! # fn main() -> Result<(), Error> {
//! let mut data = b"my secret data".to_vec();
//! let cocoon = Cocoon::new(b"password");
//! # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
//! # let mut file = Cursor::new(vec![0; 150]);
//!
//! cocoon.dump(data, &mut file)?;
//! # assert_ne!(file.get_ref(), b"my secret data");
//!
//! # file.set_position(0);
//! #
//! let data = cocoon.parse(&mut file)?;
//! assert_eq!(&data, b"my secret data");
//!
//! # Ok(())
//! # }
//! ```
//!
//! ## Encrypt/Decrypt
//! 📌 [`encrypt`](MiniCocoon::encrypt)/[`decrypt`](MiniCocoon::decrypt)
//!
//! You can encrypt data in place and avoid re-allocations. The method operates with a detached
//! meta-data (a container format prefix) in the array on the stack. It is suitable for "`no_std`"
//! build and whenever you want to evade re-allocations of a huge amount of data. You have to care
//! about how to store and transfer a data length and a container prefix though.
//!
//! Both [`MiniCocoon`] and [`Cocoon`] have the same API, but prefixes are of different sizes.
//! [`MiniCocoon`] doesn't have the overhead of generating KDF on each encryption call, therefore
//! it's recommended for simple sequential encryption/decryption operations.
//! ```
//! # use cocoon::{MiniCocoon, Error};
//! #
//! # fn main() -> Result<(), Error> {
//! let mut data = "my secret data".to_owned().into_bytes();
//! let cocoon = MiniCocoon::from_key(b"0123456789abcdef0123456789abcdef", &[0; 32]);
//!
//! let detached_prefix = cocoon.encrypt(&mut data)?;
//! assert_ne!(data, b"my secret data");
//!
//! cocoon.decrypt(&mut data, &detached_prefix)?;
//! assert_eq!(data, b"my secret data");
//!
//! # Ok(())
//! # }
//! ```
//!
//! # Study Case
//! You implement a database of secrets that must be stored in an encrypted file using a user
//! password. There are a lot of ways how your database can be represented in memory and how
//! it could be serialized. You handle these aspects on your own, e.g. you can use
//! [`HashMap`](std::collections::HashMap) to manage data and use `borsh`, or `bincode`,
//! to serialize the data. You can even compress a serialized buffer before encryption.
//!
//! In the end, you use [`Cocoon`] to put the final image into an encrypted container.
//!
//! ```
//! use borsh::BorshSerialize;
//! use cocoon::{Cocoon, Error};
//!
//! use std::collections::HashMap;
//! use std::fs::File;
//!
//! // Your data can be represented in any way.
//! #[derive(BorshSerialize)]
//! struct Database {
//!     inner: HashMap<String, String>,
//! }
//!
//! fn main() -> Result<(), Error> {
//!     let mut file = File::create("target/test.db")?;
//!     let mut db = Database { inner: HashMap::new() };
//!
//!     // Over time you collect some kind of data.
//!     db.inner.insert("my.email@example.com".to_string(), "eKPV$PM8TV5A2".to_string());
//!
//!     // You can choose how to serialize data. Also, you can compress it.
//!     let encoded = db.try_to_vec().unwrap();
//!
//!     // Finally, you want to store your data secretly.
//!     // Supply some password to Cocoon: it can be any byte array, basically.
//!     // Don't use a hard-coded password in real life!
//!     // It could be a user-supplied password.
//!     let cocoon = Cocoon::new(b"secret password");
//!
//!     // Dump the serialized database into a file as an encrypted container.
//!     let container = cocoon.dump(encoded, &mut file)?;
//!
//!     Ok(())
//! }
//! ```
//!
//! # Crate Features
//!
//! You can customize the package compilation with the following feature set:
//!
//! | Feature      | Description                                                                  |
//! |--------------|------------------------------------------------------------------------------|
//! | `std`        | Enables almost all API, including I/O, excluding `getrandom` feature.        |
//! | `alloc`      | Enables API with memory allocation, but without [`std`] dependency.          |
//! | `getrandom`  | Enables [`Cocoon::from_entropy`].                                            |
//! |  no features | Creation and decryption a cocoon on the stack with no thread RNG, I/O, heap. |
//!
//! `std` is enabled by default, so you can just link the `cocoon` to you project:
//! ```toml
//! [dependencies]
//! cocoon = "0"
//! ```
//! To use no features:
//! ```toml
//! [dependencies]
//! cocoon = { version = "0", default-features = false }
//! ```
//! To use only `alloc` feature:
//! ```toml
//! [dependencies]
//! cocoon = { version = "0", default-features = false, features = ['alloc'] }
//! ```
//!
//! # Cryptography
//!
//! 256-bit cryptography is chosen as a `Cocoon` baseline.
//!
//! | Cipher (AEAD)     | Key Derivation Function (KDF)    |
//! |-------------------|----------------------------------|
//! | Chacha20-Poly1305 | PBKDF2-SHA256: 100000 iterations |
//! | AES256-GCM        |                                  |
//!
//! * Key: 256-bit.
//! * Salt for KDF: random 128-bit + predefined part.
//! * Nonce for encryption: random 96-bit.
//!
//! Key derivation parameters comply with NIST SP 800-132 recommendations (salt, iterations),
//! and cipher parameters (key, nonce) fit requirements of a particular cipher.
//! AEAD is chosen in order to authenticate encrypted data together with an unencrypted header.
//!
//! # Zeroization
//!
//! The encryption key is wrapped into a zeroizing container
//! (provided by `zeroize` crate), which means that the key is erased automatically once it is dropped.
//!
//! # Container Creation
//! First, a random material is generated. A _salt_ is going to get mixed into a
//! master key, and a _nonce_ is used for AEAD encryption. All arrays are put
//! into a header which prefixes the final container.
//!
//! <img alt="Salt and nonce" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_creation_rng.svg" />
//!
//! Then a _master key_ is derived from a password using selected Key Derivation Function
//! (KDF, e.g. PBKDF2) and a random salt.
//!
//! <img alt="Master key" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_creation_key.svg" />
//!
//! At this moment we have everything to encrypt data and to create a container.
//! Authenticated Encryption with Associated Data (AEAD) is used to encrypt data and to produce
//! a _tag_ which controls integrity of both _header_ and _data_. The tag is deliberately
//! placed at the beginning that allows to detach the whole prefix (header and tag) which helps
//! certain cases, e.g. it allows to work on stack, makes API more flexible, gets additional
//! control over the container format.
//!
//! <img alt="Cocoon creation" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_encryption.svg" />
//!
//! Container can be dumped to file, or it can be kept in the buffer.
//!
//! ## Container Parsing
//!
//! It starts from header parsing because random material is needed to restore a master key in
//! order to decrypt a data.
//!
//! <img alt="Cocoon header parsing" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_header_parsing.svg" />
//!
//! Random generator is not needed in this case. (That's why [`Cocoon::parse_only`] is provided
//! as an alternative way to initialize [`Cocoon`] to only parse a container without necessity
//! to initialize RNG.)
//!
//! A master key is derived from a password and a salt.
//!
//! <img alt="Master key generation" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_creation_key.svg" />
//!
//! Finally, integrity of all parts is verified and data is decrypted.
//!
//! <img alt="Cocoon parsing" src="https://github.com/fadeevab/cocoon/raw/master/images/cocoon_parsing.svg" />

#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docs_rs, feature(doc_cfg))]

mod error;
mod format;
mod header;
mod kdf;
mod mini;

#[cfg(feature = "alloc")]
extern crate alloc;

use aes_gcm::{Aes256Gcm, KeyInit};
use chacha20poly1305::{
    aead::{generic_array::GenericArray, AeadInPlace},
    ChaCha20Poly1305,
};
#[cfg(feature = "std")]
use rand::rngs::ThreadRng;
use rand::{
    rngs::StdRng,
    {RngCore, SeedableRng},
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::io::{Read, Write};

use format::FormatPrefix;
use header::{CocoonConfig, CocoonHeader};

// Enumeration is needed to avoid dynamic allocation (important for "nostd" build).
#[allow(clippy::large_enum_variant)]
enum RngVariant {
    #[cfg(feature = "std")]
    Thread(ThreadRng),
    Std(StdRng),
    None,
}

pub use error::Error;
pub use header::{CocoonCipher, CocoonKdf};

/// Grouping creation methods via generics.
#[doc(hidden)]
pub struct Creation;

/// Grouping parsing methods via generics.
#[doc(hidden)]
pub struct Parsing;

/// The size of the cocoon prefix which appears in detached form in [`Cocoon::encrypt`].
pub const PREFIX_SIZE: usize = FormatPrefix::SERIALIZE_SIZE;

/// Re-export all MiniCocoon stuff.
pub use mini::*;

/// Creates an encrypted container to hide your data inside of it using a user-supplied password.
///
/// Every operation of [`Cocoon`] starts with an expensive key derivation from a password,
/// therefore prefer to use [`Cocoon`] to encrypt data at rest, and consider to use [`MiniCocoon`]
/// in order to wrap/encrypt/dump data often (e.g. in transit) withing a lightweight container
/// as a simple [`Vec`] (just wrap, wrap, wrap it!).
///
/// # Basic Usage
/// ```
/// # use cocoon::{Cocoon, Error};
/// #
/// # fn main() -> Result<(), Error> {
/// let cocoon = Cocoon::new(b"password");
/// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
///
/// let wrapped = cocoon.wrap(b"my secret data")?;
/// assert_ne!(&wrapped, b"my secret data");
///
/// let unwrapped = cocoon.unwrap(&wrapped)?;
/// assert_eq!(unwrapped, b"my secret data");
///
/// # Ok(())
/// # }
/// ```
///
/// Scroll down to [Features and Methods Mapping](#features-and-methods-mapping), and also see
/// crate's documentation for more use cases.
///
/// # Optimization
///
/// Whenever a new container is created a new encryption key is generated from a supplied password
/// using Key Derivation Function (KDF). By default, PBKDF2 is used with 100 000 iterations of
/// SHA256. The reason for that is security: slower KDF - slower attacker brute-forces the password.
/// However, you may find it a bit _slow_ for debugging during _development_. If you experience
/// a slower runtime, try to use one of the two approaches to speed it up.
///
/// ## Optimize Both `cocoon` And `sha2`
/// Add these lines to `Cargo.toml`:
/// ```toml
/// [profile.dev.package.cocoon]
/// opt-level = 3
///
/// [profile.dev.package.sha2]
/// opt-level = 3
/// ```
///
/// ## Use Less KDF Iterations
/// You can configure [`Cocoon`] to use fewer iterations for KDF with [`Cocoon::with_weak_kdf`].
/// Be careful, lower count of KDF iterations generate a _**weaker** encryption key_, therefore
/// try to use it in debug build only.
/// ```
/// # use cocoon::Cocoon;
/// // Attention: don't use a weak password in real life!
/// let password = [1, 2, 3, 4, 5, 6];
///
/// let mut cocoon = if cfg!(debug_assertions) {
///     Cocoon::new(&password).with_weak_kdf()
/// } else {
///     Cocoon::new(&password)
/// };
/// ```
///
/// # Using As a Struct Field
///
/// Currently, [`Cocoon`] is not supposed to be used within the data types as a structure member.
/// [`Cocoon`] doesn't clone a password, instead, it uses a password reference and
/// shares its lifetime. Also, [`Cocoon`] uses generics to evade dynamic dispatching and
/// resolve variants at compile-time, so it makes its declaration in structures a little bit tricky.
/// A convenient way to declare [`Cocoon`] as a structure member _could be introduced_ once it's
/// needed by semantic, e.g. with introducing of KDF caching.
///
/// # Default Configuration
/// | Option                      | Value                          |
/// |-----------------------------|--------------------------------|
/// | [Cipher](CocoonCipher)      | Chacha20Poly1305               |
/// | [Key derivation](CocoonKdf) | PBKDF2 with 100 000 iterations |
/// | Random generator            | [`ThreadRng`]                  |
///
/// * Cipher can be customized using [`Cocoon::with_cipher`] method.
/// * Key derivation (KDF): only PBKDF2 is supported.
/// * Random generator:
///   - [`ThreadRng`] in `std` build.
///   - [`StdRng`] in "no std" build: use [`Cocoon::from_rng`] and other `from_*` methods.
///   - [`Cocoon::from_entropy`] functions.
///
/// # Features and Methods Mapping
///
/// _Note: This is a not complete list of API methods. Please, refer to the current
/// documentation below to get familiarized with the full set of methods._
///
/// | Method ↓ / Feature →        | `std` | `alloc` | "no_std" |
/// |-----------------------------|:-----:|:-------:|:--------:|
/// | [`Cocoon::new`]             | ✔️    | ❌      | ❌      |
/// | [`Cocoon::from_seed`]       | ✔️    | ✔️      | ✔️      |
/// | [`Cocoon::from_entropy`]    | ✔️[^1]| ✔️[^1]  | ✔️[^1]  |
/// | [`Cocoon::parse_only`][^2]  | ✔️    | ✔️      | ✔️      |
/// | [`Cocoon::encrypt`]         | ✔️    | ✔️      | ✔️      |
/// | [`Cocoon::decrypt`][^2]     | ✔️    | ✔️      | ✔️      |
/// | [`Cocoon::wrap`]            | ✔️    | ✔️      | ❌      |
/// | [`Cocoon::unwrap`][^2]      | ✔️    | ✔️      | ❌      |
/// | [`Cocoon::dump`]            | ✔️    | ❌      | ❌      |
/// | [`Cocoon::parse`][^2]       | ✔️    | ❌      | ❌      |
///
/// [^1]: [`from_entropy`](Cocoon:from_entropy) is enabled when `getrandom` feature is enabled.
///
/// [^2]: [`parse_only`](Cocoon::parse_only) makes decryption API accessible only.
pub struct Cocoon<'a, M> {
    password: &'a [u8],
    rng: RngVariant,
    config: CocoonConfig,
    _methods_marker: PhantomData<M>,
}

#[cfg(feature = "std")]
#[cfg_attr(docs_rs, doc(cfg(feature = "std")))]
impl<'a> Cocoon<'a, Creation> {
    /// Creates a new [`Cocoon`] with [`ThreadRng`] random generator under the hood
    /// and a [Default Configuration](#default-configuration).
    ///
    /// * `password` - a shared reference to a password
    ///
    /// # Examples
    /// ```
    /// use cocoon::Cocoon;
    ///
    /// let cocoon = Cocoon::new(b"my secret password");
    /// ```
    pub fn new(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: RngVariant::Thread(ThreadRng::default()),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

impl<'a> Cocoon<'a, Creation> {
    /// Creates a new [`Cocoon`] seeding a random generator using the given buffer.
    ///
    /// * `password` - a shared reference to a password
    /// * `seed` - 32 bytes of a random seed obtained from an external RNG
    ///
    /// This method can be used when [`ThreadRng`] is not accessible with no [`std`].
    ///
    /// # Examples
    /// ```
    /// use cocoon::Cocoon;
    /// use rand::Rng;
    ///
    /// // Seed can be obtained by any cryptographically secure random generator.
    /// // ThreadRng is used just for example.
    /// let seed = rand::thread_rng().gen::<[u8; 32]>();
    ///
    /// let cocoon = Cocoon::from_seed(b"password", seed);
    /// ```
    ///
    /// **WARNING**: Use this method carefully, don't feed it with a static seed unless testing!
    /// See [`SeedableRng::from_seed`], which is under the hood, for more details.
    pub fn from_seed(password: &'a [u8], seed: [u8; 32]) -> Self {
        Cocoon {
            password,
            rng: RngVariant::Std(StdRng::from_seed(seed)),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }

    /// Creates a new [`Cocoon`] applying a third party random generator.
    ///
    /// * `password` - a shared reference to a password
    /// * `rng` - a source of random bytes
    ///
    /// This method can be used when [`ThreadRng`] is not accessible in build with no [`std`].
    ///
    /// # Examples
    /// ```
    /// use cocoon::Cocoon;
    /// use rand;
    ///
    /// # // [`ThreadRng`] is used here just as an example. It is supposed to apply some other
    /// # // cryptographically secure RNG when [`ThreadRng`] is not accessible.
    /// # let mut good_rng = rand::rngs::ThreadRng::default();
    /// let cocoon = Cocoon::from_rng(b"password", good_rng).unwrap();
    /// ```
    pub fn from_rng<R: RngCore>(password: &'a [u8], rng: R) -> Result<Self, rand::Error> {
        Ok(Cocoon {
            password,
            rng: RngVariant::Std(StdRng::from_rng(rng)?),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        })
    }

    /// Creates a new [`Cocoon`] with OS random generator using `getrandom` crate via
    /// [`SeedableRng::from_entropy`].
    ///
    /// * `password` - a shared reference to a password
    ///
    /// The method can be used to create [`Cocoon`] when [`ThreadRng`] is not accessible
    /// in build with no [`std`].
    ///
    /// # Examples
    /// ```
    /// use cocoon::Cocoon;
    ///
    /// let cocoon = Cocoon::from_entropy(b"password");
    /// ```
    #[cfg(any(feature = "getrandom", test))]
    #[cfg_attr(docs_rs, doc(cfg(feature = "getrandom")))]
    pub fn from_entropy(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: RngVariant::Std(StdRng::from_entropy()),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

impl<'a> Cocoon<'a, Parsing> {
    /// Creates a [`Cocoon`] instance allowing to only decrypt a container. It makes only decryption
    /// methods accessible at compile-time: [`Cocoon::unwrap`], [`Cocoon::parse`] and
    /// [`Cocoon::decrypt`].
    ///
    /// * `password` - a shared reference to a password
    ///
    /// All encryption methods need a cryptographic random generator to generate a salt and a nonce,
    /// at the same time the random generator is not needed for parsing.
    ///
    /// The [`wrap`](Cocoon::wrap)/[`encrypt`](Cocoon::encrypt)/[`dump`](Cocoon::dump) methods are
    /// **not** accessible _at compile-time_ when [`Cocoon::parse_only`] is used. Therefore the
    /// compilation of the following code snippet fails.
    /// ```compile_fail
    /// use cocoon::Cocoon;
    ///
    /// let cocoon = Cocoon::parse_only(b"password");
    ///
    /// // The compilation process fails here denying to use any encryption method.
    /// cocoon.wrap(b"my data");
    /// ```
    ///
    /// Meanwhile, decryption methods are accessible.
    /// ```
    /// use cocoon::{Cocoon, Error};
    ///
    /// # fn main() -> Result<(), Error> {
    /// let cocoon = Cocoon::parse_only(b"password");
    ///
    /// # let mut data = [
    /// #     244, 85, 222, 144, 119, 169, 144, 11, 178, 216, 4, 57, 17, 47, 0,
    /// # ];
    /// # let detached_prefix = [
    /// #     127, 192, 10, 1, 1, 1, 1, 0, 118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229,
    /// #     83, 134, 189, 40, 189, 210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 0, 0, 0, 0,
    /// #     0, 0, 0, 14, 53, 9, 86, 247, 53, 186, 123, 217, 156, 132, 173, 200, 208, 134, 179, 12,
    /// # ];
    /// #
    /// cocoon.decrypt(&mut data, &detached_prefix)?;
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn parse_only(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: RngVariant::None,
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

// Wrapping/encryption methods are accessible only when random generator is accessible.
impl<'a> Cocoon<'a, Creation> {
    /// Sets an encryption algorithm to wrap data on.
    ///
    /// # Examples
    /// ```
    /// use cocoon::{Cocoon, CocoonCipher};
    ///
    /// let cocoon = Cocoon::new(b"password").with_cipher(CocoonCipher::Aes256Gcm);
    /// cocoon.wrap(b"my secret data");
    /// ```
    pub fn with_cipher(mut self, cipher: CocoonCipher) -> Self {
        self.config = self.config.with_cipher(cipher);
        self
    }

    /// Reduces the number of iterations for key derivation function (KDF).
    ///
    /// ⚠️ This modifier could be used for testing in debug mode, and it should not be used
    /// in production and release builds.
    ///
    /// # Examples
    /// ```
    /// use cocoon::Cocoon;
    ///
    /// let cocoon = Cocoon::new(b"password").with_weak_kdf();
    /// cocoon.wrap(b"my secret data").expect("New container");
    /// ```
    pub fn with_weak_kdf(mut self) -> Self {
        self.config = self.config.with_weak_kdf();
        self
    }

    /// Wraps data to an encrypted container.
    ///
    /// * `data` - a sensitive user data
    ///
    /// Examples:
    /// ```
    /// # use cocoon::{Cocoon, Error};
    /// #
    /// # fn main() -> Result<(), Error> {
    /// let cocoon = Cocoon::new(b"password");
    /// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
    ///
    /// let wrapped = cocoon.wrap(b"my secret data")?;
    /// assert_ne!(&wrapped, b"my secret data");
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docs_rs, doc(cfg(any(feature = "alloc", feature = "std"))))]
    pub fn wrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // Allocation is needed because there is no way to prefix encrypted
        // data with a header without an allocation. It means that we need
        // to copy data at least once. It's necessary to avoid any further copying.
        let mut container = Vec::with_capacity(PREFIX_SIZE + data.len());
        container.extend_from_slice(&[0; PREFIX_SIZE]);
        container.extend_from_slice(data);

        let body = &mut container[PREFIX_SIZE..];

        // Encrypt in place and get a prefix part.
        let detached_prefix = self.encrypt(body)?;

        container[..PREFIX_SIZE].copy_from_slice(&detached_prefix);

        Ok(container)
    }

    /// Encrypts data in place, taking ownership over the buffer, and dumps the container
    /// into [`File`](std::fs::File), [`Cursor`](std::io::Cursor), or any other writer.
    /// * `data` - a sensitive data inside of [`Vec`] to be encrypted in place
    /// * `writer` - [`File`](std::fs::File), [`Cursor`](`std::io::Cursor`), or any other output
    ///
    /// A data is going to be encrypted in place and stored in a file using the "cocoon"
    /// [format](#format).
    ///
    /// # Examples
    /// ```
    /// # use cocoon::{Cocoon, Error};
    /// # use std::io::Cursor;
    /// #
    /// # fn main() -> Result<(), Error> {
    /// let mut data = b"my secret data".to_vec();
    /// let cocoon = Cocoon::new(b"password");
    /// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
    /// # let mut file = Cursor::new(vec![0; 150]);
    ///
    /// cocoon.dump(data, &mut file)?;
    /// # assert_ne!(file.get_ref(), b"my secret data");
    ///
    /// # Ok(())
    /// # }
    #[cfg(feature = "std")]
    #[cfg_attr(docs_rs, doc(cfg(feature = "std")))]
    pub fn dump(&self, mut data: Vec<u8>, writer: &mut impl Write) -> Result<(), Error> {
        let detached_prefix = self.encrypt(&mut data)?;

        writer.write_all(&detached_prefix)?;
        writer.write_all(&data)?;

        Ok(())
    }

    /// Encrypts data in place and returns a detached prefix of the container.
    ///
    /// The prefix is needed to decrypt data with [`Cocoon::decrypt`].
    /// This method doesn't use memory allocation and it is suitable in the build
    /// with no [`std`] and no [`alloc`].
    ///
    /// <img src="../../../images/cocoon_detached_prefix.svg" />
    ///
    /// # Examples
    /// ```
    /// # use cocoon::{Cocoon, Error};
    /// #
    /// # fn main() -> Result<(), Error> {
    /// # // [`ThreadRng`] is used here just as an example. It is supposed to apply some other
    /// # // cryptographically secure RNG when [`ThreadRng`] is not accessible.
    /// # let mut good_rng = rand::rngs::ThreadRng::default();
    /// let mut data = "my secret data".to_owned().into_bytes();
    /// let cocoon = Cocoon::from_rng(b"password", good_rng).unwrap();
    /// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
    ///
    /// let detached_prefix = cocoon.encrypt(&mut data)?;
    /// assert_ne!(data, b"my secret data");
    /// # Ok(())
    /// # }
    /// ```
    pub fn encrypt(&self, data: &mut [u8]) -> Result<[u8; PREFIX_SIZE], Error> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];

        match &self.rng {
            #[cfg(feature = "std")]
            RngVariant::Thread(rng) => {
                let mut rng = rng.clone();
                rng.fill_bytes(&mut salt);
                rng.fill_bytes(&mut nonce);
            }
            RngVariant::Std(rng) => {
                let mut rng = rng.clone();
                rng.fill_bytes(&mut salt);
                rng.fill_bytes(&mut nonce);
            }
            RngVariant::None => unreachable!(),
        }

        let header = CocoonHeader::new(self.config.clone(), salt, nonce, data.len());
        let prefix = FormatPrefix::new(header);

        let master_key = match self.config.kdf() {
            CocoonKdf::Pbkdf2 => {
                kdf::pbkdf2::derive(&salt, self.password, self.config.kdf_iterations())
            }
        };

        let nonce = GenericArray::from_slice(&nonce);
        let master_key = GenericArray::clone_from_slice(master_key.as_ref());

        let tag: [u8; 16] = match self.config.cipher() {
            CocoonCipher::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(&master_key);
                cipher.encrypt_in_place_detached(nonce, &prefix.prefix(), data)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(&master_key);
                cipher.encrypt_in_place_detached(nonce, &prefix.prefix(), data)
            }
        }
        .map_err(|_| Error::Cryptography)?
        .into();

        Ok(prefix.serialize(&tag))
    }
}

/// Parsing methods are always accessible. They don't need random generator in general.
impl<'a, M> Cocoon<'a, M> {
    /// Unwraps data from the encrypted container (see [`Cocoon::wrap`]).
    ///
    /// # Examples
    /// ```
    /// # use cocoon::{Cocoon, Error};
    /// #
    /// # fn main() -> Result<(), Error> {
    /// let cocoon = Cocoon::new(b"password");
    /// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
    ///
    /// # let wrapped = cocoon.wrap(b"my secret data")?;
    /// # assert_ne!(&wrapped, b"my secret data");
    /// #
    /// let unwrapped = cocoon.unwrap(&wrapped)?;
    /// assert_eq!(unwrapped, b"my secret data");
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "alloc")]
    #[cfg_attr(docs_rs, doc(cfg(any(feature = "alloc", feature = "std"))))]
    pub fn unwrap(&self, container: &[u8]) -> Result<Vec<u8>, Error> {
        let prefix = FormatPrefix::deserialize(container)?;
        let header = prefix.header();

        if container.len() < prefix.size() + header.data_length() {
            return Err(Error::TooShort);
        }

        let mut body = Vec::with_capacity(header.data_length());
        body.extend_from_slice(&container[prefix.size()..prefix.size() + body.capacity()]);

        self.decrypt_parsed(&mut body, &prefix)?;

        Ok(body)
    }

    /// Parses container from the reader (file, cursor, etc.), validates format,
    /// allocates memory and places decrypted data there.
    ///
    /// * `reader` - [`File`](std::fs::File), [`Cursor`](`std::io::Cursor`), or any other input
    ///
    /// # Examples
    /// ```
    /// # use cocoon::{Cocoon, Error};
    /// # use std::io::Cursor;
    /// #
    /// # fn main() -> Result<(), Error> {
    /// let mut data = b"my secret data".to_vec();
    /// let cocoon = Cocoon::new(b"password");
    /// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
    /// # let mut file = Cursor::new(vec![0; 150]);
    ///
    /// # cocoon.dump(data, &mut file)?;
    /// # assert_ne!(file.get_ref(), b"my secret data");
    /// #
    /// # file.set_position(0);
    /// #
    /// let data = cocoon.parse(&mut file)?;
    /// assert_eq!(&data, b"my secret data");
    ///
    /// # Ok(())
    /// # }
    /// ```
    #[cfg(feature = "std")]
    #[cfg_attr(docs_rs, doc(cfg(feature = "std")))]
    pub fn parse(&self, reader: &mut impl Read) -> Result<Vec<u8>, Error> {
        let prefix = FormatPrefix::deserialize_from(reader)?;
        let mut body = Vec::with_capacity(prefix.header().data_length());
        body.resize(body.capacity(), 0);

        // Too short error can be thrown right from here.
        reader.read_exact(&mut body)?;

        self.decrypt_parsed(&mut body, &prefix)?;

        Ok(body)
    }

    /// Decrypts data in place using the parts returned by [`Cocoon::encrypt`] method.
    ///
    /// The method doesn't use memory allocation and is suitable for "no std" and "no alloc" build.
    ///
    /// # Examples
    /// ```
    /// # use cocoon::{Cocoon, Error};
    /// #
    /// # fn main() -> Result<(), Error> {
    /// # // [`ThreadRng`] is used here just as an example. It is supposed to apply some other
    /// # // cryptographically secure RNG when [`ThreadRng`] is not accessible.
    /// # let mut good_rng = rand::rngs::ThreadRng::default();
    /// let mut data = "my secret data".to_owned().into_bytes();
    /// let cocoon = Cocoon::from_rng(b"password", good_rng).unwrap();
    /// # let cocoon = cocoon.with_weak_kdf(); // Speed up doc tests.
    ///
    /// let detached_prefix = cocoon.encrypt(&mut data)?;
    /// assert_ne!(data, b"my secret data");
    ///
    /// cocoon.decrypt(&mut data, &detached_prefix)?;
    /// assert_eq!(data, b"my secret data");
    /// #
    /// # Ok(())
    /// # }
    /// ```
    pub fn decrypt(&self, data: &mut [u8], detached_prefix: &[u8]) -> Result<(), Error> {
        let prefix = FormatPrefix::deserialize(detached_prefix)?;

        self.decrypt_parsed(data, &prefix)
    }

    fn decrypt_parsed(&self, data: &mut [u8], detached_prefix: &FormatPrefix) -> Result<(), Error> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];

        let header = detached_prefix.header();

        if data.len() < header.data_length() {
            return Err(Error::TooShort);
        }

        let data = &mut data[..header.data_length()];

        salt.copy_from_slice(header.salt());
        nonce.copy_from_slice(header.nonce());

        let master_key = match header.config().kdf() {
            CocoonKdf::Pbkdf2 => {
                kdf::pbkdf2::derive(&salt, self.password, header.config().kdf_iterations())
            }
        };

        let nonce = GenericArray::from_slice(&nonce);
        let master_key = GenericArray::clone_from_slice(master_key.as_ref());
        let tag = GenericArray::from_slice(&detached_prefix.tag());

        match header.config().cipher() {
            CocoonCipher::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(&master_key);
                cipher.decrypt_in_place_detached(nonce, &detached_prefix.prefix(), data, tag)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(&master_key);
                cipher.decrypt_in_place_detached(nonce, &detached_prefix.prefix(), data, tag)
            }
        }
        .map_err(|_| Error::Cryptography)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use std::fs::File;
    use std::io::Cursor;

    use super::*;

    #[test]
    fn cocoon_create() {
        Cocoon::new(b"password").with_cipher(CocoonCipher::Aes256Gcm);
        Cocoon::from_seed(b"another password", [0; 32]).with_weak_kdf();
        Cocoon::from_entropy(b"new password");
        Cocoon::from_rng(b"password", rand::thread_rng()).unwrap();
        Cocoon::parse_only(b"password");
    }

    #[test]
    fn cocoon_encrypt() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]).with_weak_kdf();
        let mut data = "my secret data".to_owned().into_bytes();

        let detached_prefix = cocoon.encrypt(&mut data).unwrap();

        assert_eq!(
            &[
                127, 192, 10, 1, 1, 1, 2, 0, 155, 244, 154, 106, 7, 85, 249, 83, 129, 31, 206, 18,
                95, 38, 131, 213, 4, 41, 195, 187, 73, 224, 116, 20, 126, 0, 137, 165, 0, 0, 0, 0,
                0, 0, 0, 14, 114, 102, 232, 234, 188, 49, 190, 30, 41, 136, 238, 190, 46, 182, 211,
                244
            ][..],
            &detached_prefix[..]
        );

        assert_eq!(
            &[186, 240, 214, 29, 4, 147, 205, 72, 210, 7, 167, 234, 199, 53],
            &data[..]
        );
    }

    #[test]
    fn cocoon_encrypt_aes() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32])
            .with_weak_kdf()
            .with_cipher(CocoonCipher::Aes256Gcm);
        let mut data = "my secret data".to_owned().into_bytes();

        let detached_prefix = cocoon.encrypt(&mut data).unwrap();

        assert_eq!(
            &[
                127, 192, 10, 1, 2, 1, 2, 0, 155, 244, 154, 106, 7, 85, 249, 83, 129, 31, 206, 18,
                95, 38, 131, 213, 4, 41, 195, 187, 73, 224, 116, 20, 126, 0, 137, 165, 0, 0, 0, 0,
                0, 0, 0, 14, 103, 127, 175, 154, 15, 80, 248, 145, 128, 241, 138, 15, 154, 128,
                201, 157
            ][..],
            &detached_prefix[..]
        );

        assert_eq!(
            &[88, 183, 11, 7, 192, 224, 203, 107, 144, 162, 48, 78, 61, 223],
            &data[..]
        );
    }

    #[test]
    fn cocoon_decrypt() {
        let detached_prefix = [
            127, 192, 10, 1, 1, 1, 1, 0, 118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229,
            83, 134, 189, 40, 189, 210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 0, 0, 0, 0,
            0, 0, 0, 14, 53, 9, 86, 247, 53, 186, 123, 217, 156, 132, 173, 200, 208, 134, 179, 12,
        ];
        let mut data = [
            244, 85, 222, 144, 119, 169, 144, 11, 178, 216, 4, 57, 17, 47,
        ];
        let cocoon = Cocoon::parse_only(b"password");

        cocoon
            .decrypt(&mut data, &detached_prefix)
            .expect("Decrypted data");

        assert_eq!(b"my secret data", &data);
    }

    #[test]
    fn cocoon_wrap() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]);
        let wrapped = cocoon.wrap(b"data").expect("Wrapped container");

        assert_eq!(wrapped[wrapped.len() - 4..], [27, 107, 178, 181]);
    }

    #[test]
    fn cocoon_wrap_unwrap() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]);
        let wrapped = cocoon.wrap(b"data").expect("Wrapped container");
        let original = cocoon.unwrap(&wrapped).expect("Unwrapped container");

        assert_eq!(original, b"data");
    }

    #[test]
    fn cocoon_wrap_unwrap_corrupted() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]);
        let mut wrapped = cocoon.wrap(b"data").expect("Wrapped container");

        let last = wrapped.len() - 1;
        wrapped[last] = wrapped[last] + 1;
        cocoon.unwrap(&wrapped).expect_err("Unwrapped container");
    }

    #[test]
    fn cocoon_unwrap_larger_is_ok() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]);
        let mut wrapped = cocoon.wrap(b"data").expect("Wrapped container");

        wrapped.push(0);
        let original = cocoon.unwrap(&wrapped).expect("Unwrapped container");

        assert_eq!(original, b"data");
    }

    #[test]
    fn cocoon_unwrap_too_short() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]);
        let mut wrapped = cocoon.wrap(b"data").expect("Wrapped container");

        wrapped.pop();
        cocoon.unwrap(&wrapped).expect_err("Too short");
    }

    #[test]
    fn cocoon_decrypt_wrong_sizes() {
        let detached_prefix = [
            127, 192, 10, 1, 1, 1, 1, 0, 118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106, 229,
            83, 134, 189, 40, 189, 210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 0, 0, 0, 0,
            0, 0, 0, 14, 53, 9, 86, 247, 53, 186, 123, 217, 156, 132, 173, 200, 208, 134, 179, 12,
        ];
        let mut data = [
            244, 85, 222, 144, 119, 169, 144, 11, 178, 216, 4, 57, 17, 47, 0,
        ];
        let cocoon = Cocoon::parse_only(b"password");

        cocoon
            .decrypt(&mut data, &detached_prefix)
            .expect("Decrypted data");

        assert_eq!(b"my secret data\0", &data);

        cocoon
            .decrypt(&mut data[..4], &detached_prefix)
            .expect_err("Too short");
    }

    #[test]
    fn cocoon_dump_parse() {
        let buf = vec![0; 100];
        let mut file = Cursor::new(buf);
        let cocoon = Cocoon::from_seed(b"password", [0; 32]).with_weak_kdf();

        // Prepare data inside of `Vec` container.
        let data = b"my data".to_vec();

        cocoon.dump(data, &mut file).expect("Dumped container");
        assert_ne!(b"my data", file.get_ref().as_slice());

        // "Re-open" the file.
        file.set_position(0);

        let original = cocoon.parse(&mut file).expect("Parsed container");
        assert_eq!(b"my data", original.as_slice());
    }

    #[test]
    fn cocoon_dump_io_error() {
        let read_only_file =
            std::env::var("CARGO_TARGET_DIR").unwrap_or("target".into()) + "/read_only.txt";

        File::create(read_only_file.clone()).expect("Test file");
        let mut file = File::open(read_only_file).expect("Test file");

        let cocoon = Cocoon::from_seed(b"password", [0; 32]).with_weak_kdf();

        // Prepare data inside of `Vec` container.
        let data = b"my data".to_vec();

        match cocoon.dump(data, &mut file) {
            Err(e) => match e {
                Error::Io(_) => (),
                _ => panic!("Only unexpected I/O error is expected :)"),
            },
            _ => panic!("Success is not expected"),
        }
    }

    #[test]
    fn cocoon_parse_io_error() {
        let read_only_file =
            std::env::var("CARGO_TARGET_DIR").unwrap_or("target".into()) + "/read_only.txt";

        File::create(read_only_file.clone()).expect("Test file");
        let mut file = File::open(read_only_file).expect("Test file");

        let cocoon = Cocoon::from_seed(b"password", [0; 32]).with_weak_kdf();

        match cocoon.parse(&mut file) {
            Err(e) => match e {
                Error::TooShort => (),
                _ => panic!("TooShort is expected for an empty file"),
            },
            _ => panic!("Success is not expected"),
        }
    }
}
