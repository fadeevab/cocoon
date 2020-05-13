//! A protected container to wrap sensitive data with a strong encryption and format validation.

#![forbid(unsafe_code)]
#![warn(missing_docs, unused_qualifications)]

use core::convert::TryInto;

/// Error variants produced by the Cocoon API.
#[derive(Debug, Clone, Copy)]
pub enum Error {
    /// Format is not recognized (probably, corrupted).
    UnrecognizedFormat,
    /// Cryptographic error. There could be a few reasons:
    /// 1. Integrity is compromised.
    /// 2. Password is invalid.
    Cryptography,
}

/// Supported AEAD (Authenticated Encryption with Associated Data) ciphers.
/// Only 256-bit AEAD algorithms.
#[derive(Clone, Copy)]
pub enum Aead {
    /// Chacha20-Poly1305.
    Chacha20Poly1305 = 1,
    /// AES256-GCM.
    Aes256Gcm,
}

/// Supported key derivation functions (KDF) which are used to derive a master key
/// from a user password.
#[derive(Clone, Copy)]
pub enum Kdf {
    /// PBKDF2 with NIST SP 800-132 recommended parameters:
    /// 1. Salt: 16 bytes (128-bit) + predefined salt.
    /// 2. Iterations: 100 000 (1000 when "debug" feature is enabled).
    Pbkdf2 = 1,
    /// Argon2i.
    Argon2i,
}

/// A set of `Cocoon` container capabilities.
/// Config is embedded to a container with a header.
struct CocoonConfig {
    /// Cipher.
    cipher: Aead,
    /// Key derivation function.
    kdf: Kdf,
    /// Reserved.
    reserved1: [u8; 2],
    /// KDF iterations.
    kdf_iterations: u32,
    /// Reserved.
    reserved2: [u8; 4],
}

impl Default for CocoonConfig {
    fn default() -> CocoonConfig {
        CocoonConfig {
            cipher: Aead::Chacha20Poly1305,
            kdf: Kdf::Pbkdf2,
            reserved1: [0u8; 2],
            kdf_iterations: if cfg!(debug) {
                // 1000 is the minimum according to NIST SP 800-132. 100_000 iterations is
                // extremely slow in debug builds. `debug_assertions` is not used to prevent
                // unintentional container incompatibility, so `debug` feature has to be
                // explicitly specified.
                1000
            } else {
                // NIST SP 800-132 (PBKDF2) recommends to choose an iteration count
                // somewhere between 1000 and 10_000_000, so the password derivation function
                // can not be brute forced easily.
                100_000
            },
            reserved2: [0u8; 4],
        }
    }
}

impl CocoonConfig {
    fn serialize(&self) -> [u8; 12] {
        let mut buf = [0u8; 12];
        buf[0] = self.cipher as u8;
        buf[1] = self.kdf as u8;
        buf[2..4].copy_from_slice(&self.reserved1);
        buf[4..8].copy_from_slice(&self.kdf_iterations.to_be_bytes());
        buf[9..12].copy_from_slice(&self.reserved2);
        buf
    }

    fn deserialize(buf: &[u8]) -> Result<Self, Error> {
        let mut this = CocoonConfig::default();
        this.cipher = match buf[0] {
            cipher if cipher == Aead::Chacha20Poly1305 as u8 => Aead::Chacha20Poly1305,
            cipher if cipher == Aead::Aes256Gcm as u8 => Aead::Aes256Gcm,
            _ => return Err(Error::UnrecognizedFormat),
        };
        this.kdf = match buf[1] {
            kdf if kdf == Kdf::Pbkdf2 as u8 => Kdf::Pbkdf2,
            kdf if kdf == Kdf::Argon2i as u8 => Kdf::Argon2i,
            _ => return Err(Error::UnrecognizedFormat),
        };
        this.kdf_iterations = u32::from_be_bytes(buf[4..8].try_into().unwrap());
        Ok(this)
    }
}

/// Header of the protected container.
///
/// 1. A magic number.
/// 2. A version.
/// 3. A randomly generated salt for a master key.
/// 4. A set of container options.
/// 5. A length of encrypted data.
///
/// ```
/// Header {
///    3 bytes: 0x7f 0xc0 '\n'
///    1 byte : 0x01
///   16 bytes: <salt>
///   12 bytes: 0x01 0x01 0x00 0x00 0x00 0x01 0x86 0xa0 0x00 0x00 0x00 0x00
///    8 bytes: <length>
///  }
/// ```
pub struct Header {
    /// A magic number makes a container suitable for storing in file,
    /// and basically it is to prevent an unintended processing of incompatible data structure.
    magic: [u8; 3],
    /// A version allows to upgrade the format in future.
    version: u8,
    /// 16 bytes of salt (128-bit) is a minimum for PBKDF2 according to NIST recommendations.
    salt: [u8; 16],
    /// Container settings.
    config: CocoonConfig,
    /// 8 bytes of length (64-bit) allows to handle up to 256GB of Chacha20/AES256 cipher data.
    length: usize,
}

impl Default for Header {
    fn default() -> Self {
        Header {
            magic: Header::MAGIC,
            version: Header::VERSION,
            salt: Default::default(),
            config: CocoonConfig::default(),
            length: Default::default(),
        }
    }
}

impl Header {
    const MAGIC: [u8; 3] = [0x7f, 0xc0, b'\n'];
    const VERSION: u8 = 1;

    fn serialize(&self) -> [u8; 40] {
        let mut buf = [0u8; 40];
        buf[..3].copy_from_slice(&self.magic);
        buf[3] = self.version;
        buf[4..20].copy_from_slice(&self.salt);
        buf[20..32].copy_from_slice(&self.config.serialize());
        buf[32..40].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    fn deserialize(buf: [u8; 40]) -> Result<Header, Error> {
        let mut this = Header::default();
        this.magic.copy_from_slice(&buf[..3]);
        this.version = buf[3];
        this.salt.copy_from_slice(&buf[4..20]);
        this.config = CocoonConfig::deserialize(&buf[20..32])?;
        this.length = usize::from_be_bytes(buf[32..40].try_into().unwrap());
        Ok(this)
    }
}
