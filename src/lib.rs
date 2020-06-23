//! # Cocoon 🦋
//!
//! [`Cocoon`] is a protected container to wrap sensitive data with a strong encryption
//! and format validation. A format of the [`Cocoon`] is developed for the following
//! practical cases:
//!
//! 1. As a _file format_ to organize a simple secure storage:
//!    1. Key store.
//!    2. Password store.
//!    3. Sensitive data store.
//! 2. _Encrypted data transfer_:
//!    * As a secure in-memory container.

#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(docs_rs, feature(doc_cfg))]

mod error;
mod format;
mod header;
mod kdf;

#[cfg(feature = "alloc")]
extern crate alloc;

use aes_gcm::Aes256Gcm;
use chacha20poly1305::{
    aead::{generic_array::GenericArray, Aead, NewAead},
    ChaCha20Poly1305,
};
#[cfg(feature = "std")]
use rand::rngs::ThreadRng;
use rand::{
    rngs::StdRng,
    {CryptoRng, RngCore, SeedableRng},
};

#[cfg(feature = "alloc")]
use alloc::vec::Vec;
use core::marker::PhantomData;
#[cfg(feature = "std")]
use std::io::{Read, Write};

use format::FormatPrefix;
use header::{CocoonConfig, CocoonHeader};

pub use error::Error;
pub use header::{CocoonCipher, CocoonKdf};

struct Creation;
struct Parsing;

/// The size of the cocoon prefix which appears in detached form in [`Cocoon::encrypt`].
pub const PREFIX_SIZE: usize = FormatPrefix::SERIALIZE_SIZE;

/// Stores data securely inside of encrypted container.
///
/// # Basic Usage
/// ### Wrap a cocoon
/// One party stores a private data into a container.
/// ```
/// # use cocoon::{Cocoon, Error};
/// #
/// # fn main() -> Result<(), Error> {
/// let cocoon = Cocoon::new(b"password");
///
/// let wrapped = cocoon.wrap(b"my secret data")?;
/// assert_ne!(&wrapped, b"my secret data");
///
/// # Ok(())
/// # }
/// ```
///
/// ### Unwrap the cocoon
/// Another party (or the same one, or whoever knows the password) loads a private data
/// from the container.
/// ```
/// # use cocoon::{Cocoon, Error};
/// #
/// # fn main() -> Result<(), Error> {
/// let cocoon = Cocoon::new(b"password");
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
///
/// # Default Configuration
/// | Option           | Value                          |
/// |------------------|--------------------------------|
/// | Cipher           | Chacha20Poly1305               |
/// | Key derivation   | PBKDF2 with 100 000 iterations |
/// | Random generator | [`ThreadRng`]                  |
///
/// * Cipher can be customized using [`with_cipher`](Cocoon::with_cipher) method.
/// * Key derivation (KDF): only PBKDF2 is supported.
/// * Random generator:
///   - [`ThreadRng`] in `std` build.
///   - [`StdRng`] in "no std" build: use [`from_rng`](Cocoon::from_rng) and
///   - [`from_entropy`](Cocoon::from_entropy) functions.
///
/// # Wrap/Unwrap
///
/// # Dump/Parse
///
/// # Encrypt/Decrypt
///
/// # Features
///
/// You can customize the package compilation with the following feature set:
///
/// | Feature      | Description                                                                  |
/// |--------------|------------------------------------------------------------------------------|
/// | `std`        | Enables almost all API, including I/O, excluding `getrandom` feature.        |
/// | `alloc`      | Enables API with memory allocation, but without [`std`] dependency.          |
/// | `getrandom`  | Enables [`Cocoon::from_entropy`].                                            |
/// |  no features | Creation and decryption a cocoon on the stack with no thread RNG, I/O, heap. |
///
/// `std` is enabled by default, so you can just link the `cocoon` to you project:
/// ```toml
/// [dependencies]
/// cocoon = "0"
/// ```
/// To use no features:
/// ```toml
/// [dependencies]
/// cocoon = { version = "0", default-features = false }
/// ```
/// To use only `alloc` feature:
/// ```toml
/// [dependencies]
/// cocoon = { version = "0", default-features = false, features = ['alloc'] }
/// ```
/// # Features and Methods Mapping
///
/// _Note: The following is not a complete set of the API. Please, refer a current
/// documentation below to familiarize with the full set of methods._
///
/// | Method ↓ / Feature →        | `std` | `alloc` | "no_std" |
/// |-----------------------------|:-----:|:-------:|:--------:|
/// | [`Cocoon::new`]             | ✔️    | ❌      | ❌      |
/// | [`Cocoon::from_seed`]       | ✔️    | ✔️      | ✔️      |
/// | [`Cocoon::from_crypto_rng`] | ✔️    | ✔️      | ✔️      |
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
pub struct Cocoon<'a, R: CryptoRng + RngCore + Clone, M> {
    password: &'a [u8],
    rng: R,
    config: CocoonConfig,
    _methods_marker: PhantomData<M>,
}

#[cfg(feature = "std")]
#[cfg_attr(docs_rs, doc(cfg(feature = "std")))]
impl<'a> Cocoon<'a, ThreadRng, Creation> {
    /// Creates a new `Cocoon` with [`ThreadRng`] random generator under the hood
    /// and a [Default Configuration](#default-configuration).
    ///
    /// * `password` - a shared reference to a password.
    ///
    pub fn new(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: ThreadRng::default(),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

impl<'a> Cocoon<'a, StdRng, Creation> {
    /// Creates a new `Cocoon` with a seeded random generator.
    ///
    /// This method can be used when [`ThreadRng`] is not accessible in "no [`std`]" build.
    ///
    /// **WARNING**: Use this method carefully, don't feed it with a static seed unless testing!
    pub fn from_seed(password: &'a [u8], seed: [u8; 32]) -> Self {
        Cocoon {
            password,
            rng: StdRng::from_seed(seed),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }

    /// Creates a new `Cocoon` applying a third party random generator.
    ///
    /// This method can be used when [`ThreadRng`] is not accessible in "no [`std`]" build.
    pub fn from_rng<R: RngCore>(password: &'a [u8], rng: R) -> Result<Self, rand::Error> {
        Ok(Cocoon {
            password,
            rng: StdRng::from_rng(rng)?,
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        })
    }

    /// Creates a new `Cocoon` with OS random generator from [`SeedableRng::from_entropy`].
    ///
    /// The method can be used to create a `Cocoon` when [`ThreadRng`] is not accessible
    /// in "no [`std`]" build.
    #[cfg(any(feature = "getrandom", test))]
    #[cfg_attr(docs_rs, doc(cfg(feature = "getrandom")))]
    pub fn from_entropy(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: StdRng::from_entropy(),
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

impl<'a> Cocoon<'a, NoRng, Parsing> {
    /// Creates a [`Cocoon`] instance with no accessible creation methods like [`Cocoon::wrap`],
    /// [`Cocoon::dump`] and [`Cocoon::encrypt`].
    ///
    /// This method is needed if you don't need to encrypt a container, and to only decrypt one.
    /// All encryption methods need a cryptographic random generator to generate a salt and nonces,
    /// and parsing gets the from the container, therefore [`Cocoon::parse_only`] can be suitable
    /// to simply unwrap a cocoon, and it works in a limited embedded environment.
    pub fn parse_only(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: NoRng,
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

impl<'a, R: CryptoRng + RngCore + Clone> Cocoon<'a, R, Creation> {
    /// Creates a new `Cocoon` using any third party random generator.
    pub fn from_crypto_rng(password: &'a [u8], rng: R) -> Self {
        Cocoon {
            password,
            rng,
            config: CocoonConfig::default(),
            _methods_marker: PhantomData,
        }
    }
}

// Wrapping/encryption methods are accessible only when random generator is accessible.
impl<'a, R: CryptoRng + RngCore + Clone> Cocoon<'a, R, Creation> {
    /// Sets an encryption algorithm to wrap data on.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// //let cocoon = Cocoon::new(b"password").with_cipher(CocoonCipher::Aes256Gcm);
    /// //cocoon.wrap(b"my secret data");
    ///
    /// //let cocoon = Cocoon::new(b"password").with_cipher(CocoonCipher::Chacha20Poly1305);
    /// //cocoon.wrap(b"my secret data");
    /// ```
    pub fn with_cipher(mut self, cipher: CocoonCipher) -> Self {
        self.config = self.config.with_cipher(cipher);
        self
    }

    /// Reduces a number of iterations for key derivation function (KDF).
    ///
    /// This modifier could be used for testing in debug mode, and should not be used
    /// in a production and release builds.
    pub fn with_weak_kdf(mut self) -> Self {
        self.config = self.config.with_weak_kdf();
        self
    }

    /// Wraps data into an encrypted container.
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

    /// Encrypts data in place and dumps the container into the writer ([`std::fs::File`],
    /// [`std::io::Cursor`], etc).
    #[cfg(feature = "std")]
    #[cfg_attr(docs_rs, doc(cfg(feature = "std")))]
    pub fn dump(&mut self, mut data: Vec<u8>, writer: &mut impl Write) -> Result<(), Error> {
        let detached_prefix = self.encrypt(&mut data)?;

        writer.write_all(&detached_prefix)?;
        writer.write_all(&data)?;

        Ok(())
    }

    /// Encrypts data in place and returns a formatted prefix of the container.
    ///
    /// The prefix is needed to decrypt data with [`Cocoon::decrypt`].
    /// This method doesn't use memory allocation and it is suitable with no [`std`]
    /// and no [`alloc`] build.
    pub fn encrypt(&self, data: &mut [u8]) -> Result<[u8; PREFIX_SIZE], Error> {
        let mut rng = self.rng.clone();

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];

        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

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
                let cipher = ChaCha20Poly1305::new(master_key);
                cipher.encrypt_in_place_detached(nonce, &prefix.prefix(), data)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(master_key);
                cipher.encrypt_in_place_detached(nonce, &prefix.prefix(), data)
            }
        }
        .map_err(|_| Error::Cryptography)?
        .into();

        Ok(prefix.serialize(&tag))
    }
}

/// Parsing methods are always accessible. They don't need random generator in general.
impl<'a, R: CryptoRng + RngCore + Clone, M> Cocoon<'a, R, M> {
    /// Unwraps data from the wrapped format (see [`Cocoon::wrap`]).
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
    #[cfg(feature = "std")]
    #[cfg_attr(docs_rs, doc(cfg(feature = "std")))]
    pub fn parse(&self, reader: &mut impl Read) -> Result<Vec<u8>, Error> {
        let prefix = FormatPrefix::deserialize_from(reader)?;
        let mut body = Vec::with_capacity(prefix.header().data_length());

        // Too short error can be thrown right from here.
        reader.read_exact(&mut body)?;

        self.decrypt_parsed(&mut body, &prefix)?;

        Ok(body)
    }

    /// Decrypts data in place using the parts returned by `encrypt` method.
    ///
    /// The method doesn't use memory allocation and is suitable for "no std" and "no alloc" build.
    pub fn decrypt(&self, data: &mut [u8], prefix: &[u8]) -> Result<(), Error> {
        let prefix = FormatPrefix::deserialize(prefix)?;

        self.decrypt_parsed(data, &prefix)
    }

    fn decrypt_parsed(&self, data: &mut [u8], prefix: &FormatPrefix) -> Result<(), Error> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];

        let header = prefix.header();

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
        let tag = GenericArray::from_slice(&prefix.tag());

        match header.config().cipher() {
            CocoonCipher::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(master_key);
                cipher.decrypt_in_place_detached(nonce, &prefix.prefix(), data, tag)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(master_key);
                cipher.decrypt_in_place_detached(nonce, &prefix.prefix(), data, tag)
            }
        }
        .map_err(|_| Error::Cryptography)?;

        Ok(())
    }
}

#[derive(Clone)]
struct NoRng;

impl CryptoRng for NoRng {}
impl RngCore for NoRng {
    fn next_u32(&mut self) -> u32 {
        unreachable!();
    }
    fn next_u64(&mut self) -> u64 {
        unreachable!();
    }
    fn fill_bytes(&mut self, _dest: &mut [u8]) {
        unreachable!();
    }
    fn try_fill_bytes(&mut self, _dest: &mut [u8]) -> Result<(), rand::Error> {
        unreachable!();
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn cocoon_create() {
        Cocoon::new(b"password").with_cipher(CocoonCipher::Aes256Gcm);
        Cocoon::from_seed(b"another password", [0; 32]).with_weak_kdf();
        Cocoon::from_entropy(b"new password");
        Cocoon::from_rng(b"password", rand::thread_rng()).unwrap();
        Cocoon::from_crypto_rng(b"password", NoRng);
        Cocoon::parse_only(b"password");
    }

    #[test]
    fn cocoon_encrypt() {
        let cocoon = Cocoon::from_seed(b"password", [0; 32]).with_weak_kdf();
        let mut data = "my secret data".to_owned().into_bytes();

        let detached_prefix = cocoon.encrypt(&mut data).unwrap();

        assert_eq!(
            &[
                127, 192, 10, 1, 1, 1, 2, 0, 118, 184, 224, 173, 160, 241, 61, 144, 64, 93, 106,
                229, 83, 134, 189, 40, 189, 210, 25, 184, 160, 141, 237, 26, 168, 54, 239, 204, 0,
                0, 0, 0, 0, 0, 0, 14, 245, 24, 39, 167, 173, 32, 174, 247, 250, 85, 17, 250, 119,
                96, 187, 207
            ][..],
            &detached_prefix[..]
        );

        assert_eq!(
            &[168, 128, 133, 25, 121, 30, 206, 73, 191, 115, 252, 164, 158, 240],
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

        assert_eq!(wrapped[wrapped.len() - 4..], [253, 77, 138, 130]);
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
        cocoon
            .unwrap(&wrapped)
            .expect_err("Too short");
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
}
