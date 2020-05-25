//! # Cocoon 🦋
//!
//! [`Cocoon`] is a protected container to wrap sensitive data with a strong encryption
//! and format validation. The format of the [`Cocoon`] is developed to be used for the following
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
#[cfg(feature = "std")]
use std::io::{Read, Write};

use format::{FormatParser, FormatVersion1};
use header::{CocoonConfig, CocoonHeader, CocoonVersion};

pub use error::Error;
pub use header::{CocoonCipher, CocoonKdf};

/// Hides data into encrypted container.
///
/// # Basic Usage
/// ```
/// use cocoon::Cocoon;
///
/// let cocoon = Cocoon::new(b"password");
///
/// let wrapped = cocoon.wrap(b"my secret data")?;
/// let unwrapped = cocoon.unwrap(&wrapped)?;
///
/// assert_ne(&wrapped, b"my secret_data");
/// assert_eq(unwrapped, b"my secret_data");
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
///     [`from_entropy`](Cocoon::from_entropy) functions.
pub struct Cocoon<'a, R: CryptoRng + RngCore + Clone> {
    password: &'a [u8],
    rng: R,
    config: CocoonConfig,
}

#[cfg(feature = "std")]
impl<'a> Cocoon<'a, ThreadRng> {
    /// Creates a new `Cocoon` with [`ThreadRng`] random generator
    /// and a [Default Configuration](#default-configuration).
    ///
    /// # Arguments
    ///
    /// `password` - a shared reference to a password.
    ///
    pub fn new(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: ThreadRng::default(),
            config: CocoonConfig::default(),
        }
    }
}

impl<'a> Cocoon<'a, StdRng> {
    /// Creates a new `Cocoon` using a [third party] random generator.
    ///
    /// The method can be used when ThreadRnd is not accessible in "no std" build.
    pub fn from_rng<R: RngCore>(password: &'a [u8], rng: R) -> Result<Self, rand::Error> {
        Ok(Cocoon {
            password,
            rng: StdRng::from_rng(rng)?,
            config: CocoonConfig::default(),
        })
    }

    #[cfg(feature = "getrandom")]
    /// Creates a new `Cocoon` using OS random generator from [`SeedableRng::from_entropy`].
    ///
    /// The method can be used to create a `Cocoon` when [`ThreadRng`] is not accessible
    /// in "no std" build.
    pub fn from_entropy(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: StdRng::from_entropy(),
            config: CocoonConfig::default(),
        }
    }
}

impl<'a, R: CryptoRng + RngCore + Clone> Cocoon<'a, R> {
    /// Sets encryption algorithm to wrap data on.
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

    /// Wraps data into an encrypted container.
    ///
    /// # Format
    ///   `[header][encrypted data][authentication tag]`
    #[cfg(feature = "alloc")]
    pub fn wrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        const PREFIX_SIZE: usize = FormatVersion1::size();

        // Allocation is needed because there is no way to prefix encrypted
        // data with a header without an allocation. It means that we need
        // to copy data at least once. It's necessary to avoid any further copying.
        let mut container = Vec::with_capacity(PREFIX_SIZE + data.len());
        container.extend_from_slice(&[0; PREFIX_SIZE]);
        container.extend_from_slice(data);

        let body = &mut container[PREFIX_SIZE..];

        // Encrypt in place and get a prefix part.
        let prefix = self.encrypt(body)?;

        container[..PREFIX_SIZE].copy_from_slice(&prefix);

        Ok(container)
    }

    /// Encrypts data in place and dumps the container into the writer ([`std::fs::File`],
    /// [`std::io::Cursor`], etc).
    #[cfg(feature = "std")]
    pub fn dump(&mut self, mut data: Vec<u8>, writer: &mut impl Write) -> Result<(), Error> {
        let prefix = self.encrypt(&mut data)?;

        writer.write_all(&prefix)?;
        writer.write_all(&data)?;

        Ok(())
    }

    /// Encrypts data in place and returns a formatted prefix of the container.
    ///
    /// The prefix is needed to decrypt data with [`Cocoon::decrypt`].
    /// This method doesn't use memory allocation and it is suitable with no [`std`]
    /// and no [`alloc`] build.
    pub fn encrypt(&self, data: &mut [u8]) -> Result<[u8; FormatVersion1::size()], Error> {
        let mut rng = self.rng.clone();

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];

        rng.fill_bytes(&mut salt);
        rng.fill_bytes(&mut nonce);

        let header =
            CocoonHeader::new(self.config.clone(), salt, nonce, data.len() as u64).serialize();

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
                cipher.encrypt_in_place_detached(nonce, &header, data)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(master_key);
                cipher.encrypt_in_place_detached(nonce, &header, data)
            }
        }
        .map_err(|_| Error::Cryptography)?
        .into();

        Ok(FormatVersion1::serialize(&header, &tag))
    }

    /// Unwraps data from the wrapped format (see [`Cocoon::wrap`]).
    #[cfg(feature = "alloc")]
    pub fn unwrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let header = CocoonHeader::deserialize(&data)?;
        let mut body = Vec::with_capacity(header.data_length() as usize);

        self.decrypt(&mut body, &data)?;

        Ok(body)
    }

    /// Parses container from the reader (file, cursor, etc.), validates format,
    /// allocates memory and places decrypted data there.
    #[cfg(feature = "std")]
    pub fn parse(&self, reader: &mut impl Read) -> Result<Vec<u8>, Error> {
        let header = CocoonHeader::deserialize_from(reader)?;
        let prefix_size = match header.version() {
            CocoonVersion::Version1 => FormatVersion1::size(),
        };

        let mut prefix = Vec::with_capacity(prefix_size);
        let mut body = Vec::with_capacity(header.data_length() as usize);

        reader.read_exact(&mut prefix)?;
        reader.read_exact(&mut body)?;

        self.decrypt(&mut body, &prefix)?;

        Ok(body)
    }

    /// Decrypts data in place using the parts returned by `encrypt` method.
    ///
    /// The method doesn't use memory allocation and is suitable for "no std" and "no alloc" build.
    pub fn decrypt(&self, data: &mut [u8], prefix: &[u8]) -> Result<(), Error> {
        let header = CocoonHeader::deserialize(&prefix)?;

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        salt.copy_from_slice(header.salt());
        nonce.copy_from_slice(header.nonce());

        let master_key = match header.config().kdf() {
            CocoonKdf::Pbkdf2 => {
                kdf::pbkdf2::derive(&salt, self.password, header.config().kdf_iterations())
            }
        };

        let nonce = GenericArray::from_slice(&nonce);
        let master_key = GenericArray::clone_from_slice(master_key.as_ref());
        let parser = FormatParser::new(prefix);
        let tag = parser.tag();
        let tag = GenericArray::from_slice(&tag);

        match header.config().cipher() {
            CocoonCipher::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(master_key);
                cipher.decrypt_in_place_detached(nonce, &parser.header(), data, tag)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(master_key);
                cipher.decrypt_in_place_detached(nonce, &parser.header(), data, tag)
            }
        }
        .map_err(|_| Error::Cryptography)?;

        Ok(())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn asdf() {
        Cocoon::new(b"password");
    }
}
