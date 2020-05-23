//! A protected container to wrap sensitive data with a strong encryption and format validation.

#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]
#![cfg_attr(not(feature = "std"), no_std)]

mod error;
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

use header::{CocoonConfig, CocoonHeader};

pub use chacha20poly1305::aead::Buffer;
pub use error::Error;
pub use header::{CocoonCipher, CocoonKdf};

/// A header size which prefixes the encrypted data.
const HEADER_SIZE: usize = CocoonHeader::SIZE;
/// All currently supported AEAD algorithms declare tag size as 16 bytes.
const TAG_SIZE: usize = 16;

/// Detached parts contain header and tag (signature).
///
/// The structure is used in the `encrypt` and `decrypt` methods,
/// and it is useful with no `std` and no `alloc` build configuration.
pub struct CocoonDetachedParts {
    /// Serialized opaque header.
    ///
    /// It is needed to derive master key from a password and decrypt data.
    pub header: [u8; HEADER_SIZE],
    /// Authentication tag.
    ///
    /// It is needed to verify integrity of the whole container.
    pub tag: [u8; TAG_SIZE],
}

/// Cocoon is a simple encrypted container suitable
pub struct Cocoon<'a, R: CryptoRng + RngCore> {
    password: &'a [u8],
    rng: R,
    config: CocoonConfig,
}

#[cfg(feature = "std")]
impl<'a> Cocoon<'a, ThreadRng> {
    /// Allocates random generator and prepares configuration.
    pub fn new(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: ThreadRng::default(),
            config: CocoonConfig::default(),
        }
    }
}

impl<'a> Cocoon<'a, StdRng> {
    /// Creates a new `Cocoon` using a third party random generator.
    ///
    /// The method can be used when ThreadRnd is not accessible in "no std" build.
    pub fn from_rng<R: RngCore>(password: &'a [u8], rng: R) -> Result<Self, rand::Error> {
        Ok(Cocoon {
            password,
            rng: StdRng::from_rng(rng)?,
            config: CocoonConfig::default(),
        })
    }

    /// Creates a new `Cocoon` using a `getrandom` crate (`OsRng`).
    ///
    /// The method can be used to create a `Cocoon` when ThreadRnd is not accessible
    /// in "no std" build.
    #[cfg(feature = "getrandom")]
    pub fn from_entropy(password: &'a [u8]) -> Self {
        Cocoon {
            password,
            rng: StdRng::from_entropy(),
            config: CocoonConfig::default(),
        }
    }
}

impl<'a, R: CryptoRng + RngCore> Cocoon<'a, R> {
    /// Sets encryption algorithm to wrap data on.
    ///
    /// # Examples
    ///
    /// Basic usage:
    /// ```
    /// let cocoon = Cocoon::new(b"password").with_cipher(CocoonCipher::Aes256Gcm);
    /// cocoon.wrap(b"my secret data");
    ///
    /// let cocoon = Cocoon::new(b"password").with_cipher(CocoonCipher::Chacha20Poly1305);
    /// cocoon.wrap(b"my secret data");
    /// ```
    pub fn with_cipher(mut self, cipher: CocoonCipher) -> Self {
        self.config.cipher = cipher;
        self
    }

    /// Wraps data into encrypted container using random nonce and a
    /// master key derived from a password with random salt.
    ///
    /// Cocoon format: [header | data | tag].
    #[cfg(feature = "alloc")]
    pub fn wrap(&mut self, data: &[u8]) -> Result<Vec<u8>, Error> {
        // Allocation is needed because there is no way to prefix encrypted
        // data with a header without an allocation. It means that we need
        // to copy data at least once. It's necessary to avoid any further copying.
        let mut container = Vec::with_capacity(HEADER_SIZE + data.len() + TAG_SIZE);

        let header_offset = 0;
        let body_offset = HEADER_SIZE;
        let tag_offset = HEADER_SIZE + data.len();

        // Encrypted data starts right after the header.
        let body = &mut container[body_offset..tag_offset];
        body.copy_from_slice(data);

        // Encrypt in place and get other parts.
        let parts = self.encrypt(body)?;

        // Copy header before encrypted data.
        container[header_offset..body_offset].copy_from_slice(&parts.header);
        // Copy tag after encrypted data.
        container[tag_offset..].copy_from_slice(&parts.tag);

        Ok(container)
    }

    /// Encrypts data in place and dumps the container into the writer (file, cursor, etc).
    #[cfg(feature = "std")]
    pub fn dump(&mut self, mut data: Vec<u8>, mut writer: impl Write) -> Result<(), Error> {
        let parts = self.encrypt(&mut data)?;

        writer.write_all(&parts.header)?;
        writer.write_all(&data)?;
        writer.write_all(&parts.tag)?;

        Ok(())
    }

    /// Encrypts data in place, avoiding unnecessary copying, and returns the rest
    /// parts of the container.
    ///
    /// The parts (header and tag) are needed to decrypt data with `Cocoon::decrypt()`.
    /// The method doesn't use memory allocation and is suitable for "no std" and "no alloc" build.
    pub fn encrypt(&mut self, data: &mut [u8]) -> Result<CocoonDetachedParts, Error> {
        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        self.rng.fill_bytes(&mut salt);
        self.rng.fill_bytes(&mut nonce);

        let header = CocoonHeader::new(&self.config, salt, nonce, data.len() as u64).serialize();

        let master_key = match self.config.kdf {
            CocoonKdf::Pbkdf2 => {
                kdf::pbkdf2::derive(&salt, self.password, self.config.kdf_iterations())
            }
        };

        let nonce = GenericArray::from_slice(&nonce);
        let master_key = GenericArray::clone_from_slice(master_key.as_ref());

        let tag: [u8; 16] = match self.config.cipher {
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

        Ok(CocoonDetachedParts { header, tag })
    }

    /// Unwraps data from the encrypted container.
    #[cfg(feature = "alloc")]
    pub fn unwrap(&self, data: &[u8]) -> Result<Vec<u8>, Error> {
        let header = CocoonHeader::deserialize(&data)?;
        let mut body = Vec::with_capacity(header.data_length());

        let mut parts = CocoonDetachedParts {
            header: [0; HEADER_SIZE],
            tag: [0; TAG_SIZE],
        };

        let header_offset = 0;
        let body_offset = HEADER_SIZE;
        let tag_offset = HEADER_SIZE + header.data_length();

        parts.header.copy_from_slice(&data[..header_offset]);
        body.copy_from_slice(&data[body_offset..tag_offset]);
        parts.tag.copy_from_slice(&data[tag_offset..]);

        self.decrypt(&mut body, parts)?;

        Ok(body)
    }

    /// Parses container from the reader (file, cursor, etc.), validates format,
    /// allocates memory and places decrypted data there.
    #[cfg(feature = "std")]
    pub fn parse(&self, reader: &mut impl Read) -> Result<Vec<u8>, Error> {
        let mut parts = CocoonDetachedParts {
            header: [0; HEADER_SIZE],
            tag: [0; TAG_SIZE],
        };

        reader.read_exact(&mut parts.header)?;

        let header = CocoonHeader::deserialize(&parts.header)?;
        let mut body = Vec::with_capacity(header.data_length());

        reader.read_exact(&mut body)?;
        reader.read_exact(&mut parts.tag)?;

        self.decrypt(&mut body, parts)?;

        Ok(body)
    }

    /// Decrypts data in place using the parts returned by `encrypt` method.
    ///
    /// The method doesn't use memory allocation and is suitable for "no std" and "no alloc" build.
    pub fn decrypt(&self, data: &mut [u8], parts: CocoonDetachedParts) -> Result<(), Error> {
        let header = CocoonHeader::deserialize(&parts.header)?;

        let mut salt = [0u8; 16];
        let mut nonce = [0u8; 12];
        salt.copy_from_slice(header.salt());
        nonce.copy_from_slice(header.nonce());

        let master_key = match header.config().kdf {
            CocoonKdf::Pbkdf2 => {
                kdf::pbkdf2::derive(&salt, self.password, header.config().kdf_iterations())
            }
        };

        let nonce = GenericArray::from_slice(&nonce);
        let master_key = GenericArray::clone_from_slice(master_key.as_ref());
        let tag = GenericArray::from_slice(&parts.tag);

        match header.config().cipher {
            CocoonCipher::Chacha20Poly1305 => {
                let cipher = ChaCha20Poly1305::new(master_key);
                cipher.decrypt_in_place_detached(nonce, &parts.header, data, tag)
            }
            CocoonCipher::Aes256Gcm => {
                let cipher = Aes256Gcm::new(master_key);
                cipher.decrypt_in_place_detached(nonce, &parts.header, data, tag)
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
