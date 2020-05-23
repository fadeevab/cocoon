use core::convert::TryInto;

use super::error::Error;

/// Supported AEAD (Authenticated Encryption with Associated Data) ciphers.
/// Only 256-bit AEAD algorithms.
#[derive(Clone, Copy)]
pub enum CocoonCipher {
    /// Chacha20-Poly1305.
    Chacha20Poly1305 = 1,
    /// AES256-GCM.
    Aes256Gcm,
}

/// Key derivation functions (KDF) which are supported to derive a master key
/// from a user password. PBKDF2 is selected by default.
#[derive(Clone, Copy)]
pub enum CocoonKdf {
    /// PBKDF2 with NIST SP 800-132 recommended parameters:
    /// 1. Salt: 16 bytes (128-bit) + predefined salt.
    /// 2. Iterations: 100 000 (1000 when "debug" feature is enabled).
    Pbkdf2 = 1,
}

#[derive(Copy, Clone)]
enum CocoonKdfVariant {
    Strong = 1,
    Weak,
}

/// A set of `Cocoon` container capabilities. Config is embedded to a container inside the header.
#[derive(Clone)]
pub struct CocoonConfig {
    /// Cipher.
    pub cipher: CocoonCipher,
    /// Key derivation function.
    pub kdf: CocoonKdf,
    /// Not configurable from outside of the crate field.
    kdf_variant: CocoonKdfVariant,
    /// Reserved. It is for explicit structure aligning for now,
    /// and for possible format upgrade in future.
    reserved: u8,
}

impl Default for CocoonConfig {
    fn default() -> CocoonConfig {
        CocoonConfig {
            cipher: CocoonCipher::Chacha20Poly1305,
            kdf: CocoonKdf::Pbkdf2,
            kdf_variant: if cfg!(feature = "debug") {
                // `Weak` is needed for debug purposes, because a "strong" variant
                // generates key for a kind of 10 seconds, and more. `debug_assertions` is not
                // used here in order to prevent unintentional container incompatibility,
                // so `debug` feature has to be explicitly specified.
                CocoonKdfVariant::Weak
            } else {
                CocoonKdfVariant::Strong
            },
            reserved: Default::default(),
        }
    }
}

impl CocoonConfig {
    const SIZE: usize = 4;

    pub fn kdf_iterations(&self) -> u32 {
        match self.kdf {
            CocoonKdf::Pbkdf2 => match self.kdf_variant {
                // 1000 is the minimum according to NIST SP 800-132, however this recommendation
                // is 20 years old at this moment.
                // 100_000 iterations are extremely slow in debug builds.
                CocoonKdfVariant::Weak => 2000,
                // NIST SP 800-132 (PBKDF2) recommends to choose an iteration count
                // somewhere between 1000 and 10_000_000, so the password derivation function
                // can not be brute forced easily.
                CocoonKdfVariant::Strong => 100_000,
            },
        }
    }

    fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[0] = self.cipher as u8;
        buf[1] = self.kdf as u8;
        buf[2] = self.kdf_variant as u8;
        buf[3] = Default::default();
        buf
    }

    fn deserialize(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < Self::SIZE {
            return Err(Error::UnrecognizedFormat);
        }

        let cipher = match buf[0] {
            cipher if cipher == CocoonCipher::Chacha20Poly1305 as u8 => {
                CocoonCipher::Chacha20Poly1305
            }
            cipher if cipher == CocoonCipher::Aes256Gcm as u8 => CocoonCipher::Aes256Gcm,
            _ => return Err(Error::UnrecognizedFormat),
        };
        let kdf = match buf[1] {
            kdf if kdf == CocoonKdf::Pbkdf2 as u8 => CocoonKdf::Pbkdf2,
            _ => return Err(Error::UnrecognizedFormat),
        };
        let kdf_variant = match buf[2] {
            variant if variant == CocoonKdfVariant::Weak as u8 => CocoonKdfVariant::Weak,
            variant if variant == CocoonKdfVariant::Strong as u8 => CocoonKdfVariant::Strong,
            _ => return Err(Error::UnrecognizedFormat),
        };

        Ok(CocoonConfig {
            cipher,
            kdf,
            kdf_variant,
            reserved: Default::default(),
        })
    }
}

/// Header of the protected container.
///
/// | Field              | Length   | Value               | Notes                                  |
/// |--------------------|----------|---------------------|----------------------------------------|
/// | Magic number       |  3 Bytes | 0x7f 0xc0 '\n'      | Constant                               |
/// | Version            |  1 Byte  | 0x01                | Version 1                              |
/// | Options            |  4 Bytes | 0x01 0x01 0x01 0x00 | Chacha20Poly1304, PBKDF2, 100_000 iter.|
/// | Random salt        | 16 Bytes | <salt>              | A salt is used to derive a master key  |
/// | Random nonce       | 12 Bytes | <nonce>             | A nonce is used for AEAD encryption    |
/// | Payload length     |  8 Bytes | <length>            | A length of encrypted (wrapped) data   |
pub struct CocoonHeader {
    /// A magic number: 0x7f 0xc0 b'\n'.
    ///
    /// It makes a container suitable to get stored in a file,
    /// and basically it is to prevent an unintended processing of incompatible data structure.
    magic: [u8; 3],
    /// A version.
    ///
    /// Version is a hidden not configurable field, it allows to upgrade the format in the future.
    version: u8,
    /// Container settings.
    config: CocoonConfig,
    /// 16 bytes of randomly generated salt.
    ///
    /// 128-bit is a minimum for PBKDF2 according to NIST recommendations.
    /// Salt is used to generate a master key from a password. Salt itself is not a secret value.
    salt: [u8; 16],
    /// 12 bytes of a randomly generated nonce.
    ///
    /// A nonce is used to seed AEAD ciphers and to encrypt data. Nonce is not a secret value.
    nonce: [u8; 12],
    /// 8 bytes of data length.
    ///
    /// 64-bit of length allows to handle up to 256GB of Chacha20/AES256 cipher data.
    length: u64,
}

impl CocoonHeader {
    const MAGIC: [u8; 3] = [0x7f, 0xc0, b'\n'];
    const VERSION: u8 = 1;

    pub const SIZE: usize = 44;

    pub fn new(config: &CocoonConfig, salt: [u8; 16], nonce: [u8; 12], length: u64) -> Self {
        CocoonHeader {
            magic: CocoonHeader::MAGIC,
            version: CocoonHeader::VERSION,
            config: config.clone(),
            salt,
            nonce,
            length,
        }
    }

    pub fn config(&self) -> &CocoonConfig {
        &self.config
    }

    pub fn data_length(&self) -> usize {
        self.length as usize
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..3].copy_from_slice(&self.magic);
        buf[3] = self.version;
        buf[4..8].copy_from_slice(&self.config.serialize());
        buf[8..24].copy_from_slice(&self.salt);
        buf[24..36].copy_from_slice(&self.nonce);
        buf[36..44].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Result<CocoonHeader, Error> {
        if buf.len() < Self::SIZE {
            return Err(Error::UnrecognizedFormat);
        }

        let mut magic = [0u8; 3];
        magic.copy_from_slice(&buf[..3]);
        let version = buf[3];
        let config = CocoonConfig::deserialize(&buf[4..8])?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[8..24]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[24..36]);
        let length = u64::from_be_bytes(buf[36..44].try_into().unwrap());

        Ok(CocoonHeader {
            magic,
            version,
            config,
            salt,
            nonce,
            length,
        })
    }
}
