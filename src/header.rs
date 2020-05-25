#[cfg(feature = "std")]
use std::io::Read;

use core::convert::TryInto;

use super::error::Error;

/// Safe deserializing from byte to enum.
macro_rules! match_enum {
    ($m:expr, $($variant:expr),+) => {
        match $m {
            $(v if v == $variant as u8 => $variant),+,
            _ => return Err(Error::UnrecognizedFormat),
        }
    };
}

/// Supported 256-bit AEAD ciphers (Authenticated Encryption with Associated Data).
#[derive(Clone, Copy)]
pub enum CocoonCipher {
    /// Chacha20-Poly1305.
    Chacha20Poly1305 = 1,
    /// AES256-GCM.
    Aes256Gcm,
}

/// Supported key derivation functions (KDF) to derive master key
/// from user password. PBKDF2 by default.
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

#[derive(Copy, Clone)]
pub enum CocoonVersion {
    Version1 = 1,
}

/// A set of `Cocoon` container capabilities. Config is embedded to a container in the header.
#[derive(Clone)]
pub struct CocoonConfig {
    /// Cipher.
    cipher: CocoonCipher,
    /// Key derivation function (KDF).
    kdf: CocoonKdf,
    /// KDF variant. Not configurable from outside of the crate field.
    kdf_variant: CocoonKdfVariant,
    /// Reserved byte is for the explicit structure aligning
    /// as well as for possible format upgrade in future.
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
    pub fn cipher(&self) -> CocoonCipher {
        self.cipher
    }

    pub fn kdf(&self) -> CocoonKdf {
        self.kdf
    }

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

    pub fn with_cipher(mut self, cipher: CocoonCipher) -> Self {
        self.cipher = cipher;
        self
    }

    fn serialize(&self) -> [u8; 4] {
        let mut buf = [0u8; 4];
        buf[0] = self.cipher as u8;
        buf[1] = self.kdf as u8;
        buf[2] = self.kdf_variant as u8;
        buf[3] = Default::default();
        buf
    }

    fn deserialize(buf: &[u8]) -> Result<Self, Error> {
        if buf.len() < 4 {
            return Err(Error::UnrecognizedFormat);
        }

        #[rustfmt::skip]
        let cipher = match_enum!(buf[0], CocoonCipher::Chacha20Poly1305, CocoonCipher::Aes256Gcm);
        let kdf = match_enum!(buf[1], CocoonKdf::Pbkdf2);
        let kdf_variant = match_enum!(buf[2], CocoonKdfVariant::Weak, CocoonKdfVariant::Strong);

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
/// |:-------------------|:---------|:--------------------|:---------------------------------------|
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
    version: CocoonVersion,
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

    pub const SIZE: usize = core::mem::size_of::<Self>();

    pub fn new(config: CocoonConfig, salt: [u8; 16], nonce: [u8; 12], length: u64) -> Self {
        CocoonHeader {
            magic: CocoonHeader::MAGIC,
            version: CocoonVersion::Version1,
            config,
            salt,
            nonce,
            length,
        }
    }

    pub fn config(&self) -> &CocoonConfig {
        &self.config
    }

    pub fn data_length(&self) -> u64 {
        self.length
    }

    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    pub fn nonce(&self) -> &[u8] {
        &self.nonce
    }

    pub fn version(&self) -> CocoonVersion {
        self.version
    }

    pub fn serialize(&self) -> [u8; Self::SIZE] {
        let mut buf = [0u8; Self::SIZE];
        buf[..3].copy_from_slice(&self.magic);
        buf[3] = self.version as u8;
        buf[4..8].copy_from_slice(&self.config.serialize());
        buf[8..24].copy_from_slice(&self.salt);
        buf[24..36].copy_from_slice(&self.nonce);
        buf[36..Self::SIZE].copy_from_slice(&self.length.to_be_bytes());
        buf
    }

    pub fn deserialize(buf: &[u8]) -> Result<CocoonHeader, Error> {
        if buf.len() < Self::SIZE {
            return Err(Error::UnrecognizedFormat);
        }

        let mut magic = [0u8; 3];
        magic.copy_from_slice(&buf[..3]);
        if magic != Self::MAGIC {
            return Err(Error::UnrecognizedFormat);
        }

        let version = match_enum!(buf[3], CocoonVersion::Version1);
        let config = CocoonConfig::deserialize(&buf[4..8])?;
        let mut salt = [0u8; 16];
        salt.copy_from_slice(&buf[8..24]);
        let mut nonce = [0u8; 12];
        nonce.copy_from_slice(&buf[24..36]);
        let length = u64::from_be_bytes(buf[36..Self::SIZE].try_into().unwrap());

        Ok(CocoonHeader {
            magic,
            version,
            config,
            salt,
            nonce,
            length,
        })
    }

    #[cfg(feature = "std")]
    pub fn deserialize_from(reader: &mut impl Read) -> Result<CocoonHeader, Error> {
        let mut buf = [0u8; Self::SIZE];
        reader.read_exact(&mut buf)?;
        CocoonHeader::deserialize(&buf)
    }
}
