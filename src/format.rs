#[cfg(feature = "std")]
use std::io::Read;

use super::{
    error::Error,
    header::{CocoonHeader, CocoonVersion, MiniCocoonHeader},
};

const HEADER_SIZE: usize = CocoonHeader::SIZE;
const TAG_SIZE: usize = 16;
const MAX_SIZE: usize = HEADER_SIZE + TAG_SIZE;

const MINI_HEADER_SIZE: usize = MiniCocoonHeader::SIZE;
const MINI_SIZE: usize = MINI_HEADER_SIZE + TAG_SIZE;

pub struct FormatPrefix {
    header: CocoonHeader,
    raw: [u8; MAX_SIZE],
}

impl FormatPrefix {
    pub const SERIALIZE_SIZE: usize = MAX_SIZE;

    // The idea is that having additional extensions we shell put them in the constructor.
    // Meanwhile `tag` will be calculated later and it appears right on serialization.
    // Also parameters are moved into the object to evade additional copying.
    pub fn new(header: CocoonHeader) -> Self {
        let mut raw = [0u8; MAX_SIZE];

        match header.version() {
            CocoonVersion::Version1 => {
                header.serialize_into(&mut raw);
            }
        };

        FormatPrefix { header, raw }
    }

    pub fn serialize(mut self, tag: &[u8; TAG_SIZE]) -> [u8; Self::SERIALIZE_SIZE] {
        match self.header().version() {
            CocoonVersion::Version1 => (),
            // _ => panic!("Prefix can be serialized into the latest version only!"),
        }

        self.raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE].copy_from_slice(tag);
        self.raw
    }

    pub fn deserialize(start: &[u8]) -> Result<Self, Error> {
        let header = CocoonHeader::deserialize(start)?;

        let mut raw = [0u8; MAX_SIZE];

        match header.version() {
            CocoonVersion::Version1 => {
                if start.len() < HEADER_SIZE + TAG_SIZE {
                    return Err(Error::UnrecognizedFormat);
                }

                raw[..HEADER_SIZE].copy_from_slice(&start[..HEADER_SIZE]);
                raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]
                    .copy_from_slice(&start[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]);
            }
        }

        Ok(FormatPrefix { header, raw })
    }

    #[cfg(feature = "std")]
    pub fn deserialize_from(reader: &mut impl Read) -> Result<Self, Error> {
        let mut raw = [0u8; MAX_SIZE];

        reader.read_exact(&mut raw[..HEADER_SIZE])?;
        let header = CocoonHeader::deserialize(&raw)?;

        match header.version() {
            CocoonVersion::Version1 => {
                reader.read_exact(&mut raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE])?;
            }
        }

        Ok(FormatPrefix { header, raw })
    }

    pub fn header(&self) -> &CocoonHeader {
        &self.header
    }

    pub fn prefix(&self) -> &[u8] {
        &self.raw[..HEADER_SIZE]
    }

    pub fn tag(&self) -> &[u8] {
        &self.raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]
    }

    #[cfg(feature = "alloc")]
    pub fn size(&self) -> usize {
        match self.header.version() {
            CocoonVersion::Version1 => HEADER_SIZE + TAG_SIZE,
        }
    }
}

pub struct MiniFormatPrefix {
    header: MiniCocoonHeader,
    raw: [u8; MINI_SIZE],
}

impl MiniFormatPrefix {
    pub const SERIALIZE_SIZE: usize = MINI_SIZE;

    pub fn new(header: MiniCocoonHeader) -> Self {
        let mut raw = [0u8; MINI_SIZE];

        header.serialize_into(&mut raw);

        MiniFormatPrefix { header, raw }
    }

    pub fn serialize(mut self, tag: &[u8; TAG_SIZE]) -> [u8; Self::SERIALIZE_SIZE] {
        self.raw[MINI_HEADER_SIZE..MINI_HEADER_SIZE + TAG_SIZE].copy_from_slice(tag);
        self.raw
    }

    pub fn deserialize(start: &[u8]) -> Result<Self, Error> {
        let header = MiniCocoonHeader::deserialize(start)?;

        let mut raw = [0u8; MINI_SIZE];

        if start.len() < MINI_SIZE {
            return Err(Error::UnrecognizedFormat);
        }

        raw[..MINI_HEADER_SIZE].copy_from_slice(&start[..MINI_HEADER_SIZE]);
        raw[MINI_HEADER_SIZE..MINI_HEADER_SIZE + TAG_SIZE]
            .copy_from_slice(&start[MINI_HEADER_SIZE..MINI_HEADER_SIZE + TAG_SIZE]);

        Ok(MiniFormatPrefix { header, raw })
    }

    #[cfg(feature = "std")]
    pub fn deserialize_from(reader: &mut impl Read) -> Result<Self, Error> {
        let mut raw = [0u8; MINI_SIZE];

        reader.read_exact(&mut raw[..MINI_HEADER_SIZE])?;
        let header = MiniCocoonHeader::deserialize(&raw)?;

        reader.read_exact(&mut raw[MINI_HEADER_SIZE..MINI_HEADER_SIZE + TAG_SIZE])?;

        Ok(MiniFormatPrefix { header, raw })
    }

    pub fn header(&self) -> &MiniCocoonHeader {
        &self.header
    }

    pub fn prefix(&self) -> &[u8] {
        &self.raw[..MINI_HEADER_SIZE]
    }

    pub fn tag(&self) -> &[u8] {
        &self.raw[MINI_HEADER_SIZE..MINI_HEADER_SIZE + TAG_SIZE]
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use std::io::Cursor;

    use crate::header::{CocoonConfig, CocoonHeader, MiniCocoonHeader};

    #[test]
    fn format_prefix_good() {
        const RANDOM_ADD: usize = 12;
        let mut raw = [1u8; FormatPrefix::SERIALIZE_SIZE + RANDOM_ADD];

        CocoonHeader::new(CocoonConfig::default(), [0; 16], [0; 12], 0).serialize_into(&mut raw);

        let prefix = FormatPrefix::deserialize(&raw).expect("Deserialized container's prefix");

        assert_eq!(&raw[..HEADER_SIZE], prefix.prefix());
        assert_eq!(&raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE], prefix.tag());
        assert_eq!(prefix.size(), FormatPrefix::SERIALIZE_SIZE);
    }

    #[test]
    fn format_prefix_short() {
        let mut raw = [1u8; FormatPrefix::SERIALIZE_SIZE];

        CocoonHeader::new(CocoonConfig::default(), [0; 16], [0; 12], 0).serialize_into(&mut raw);
        FormatPrefix::deserialize(&raw).expect("Deserialized container's prefix");

        match FormatPrefix::deserialize(&raw[0..FormatPrefix::SERIALIZE_SIZE - 1]) {
            Err(err) => match err {
                Error::UnrecognizedFormat => (),
                _ => panic!("Invalid error"),
            },
            Ok(_) => panic!("Cocoon prefix has not to be parsed"),
        };
    }

    #[test]
    fn format_version1() {
        assert_eq!(44 + 16, FormatPrefix::SERIALIZE_SIZE);

        let header = CocoonHeader::new(CocoonConfig::default(), [1; 16], [2; 12], 50);
        let prefix = FormatPrefix::new(header);
        let tag = [3; 16];

        assert_eq!(
            [
                127, 192, 10, 1, 1, 1, 1, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 2, 2,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 50, 3, 3, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3
            ][..],
            prefix.serialize(&tag)[..]
        );
    }

    #[test]
    fn format_prefix_deserialize_from() {
        let mut raw = [1u8; FormatPrefix::SERIALIZE_SIZE];

        CocoonHeader::new(CocoonConfig::default(), [0; 16], [0; 12], 0).serialize_into(&mut raw);

        let mut file = Cursor::new(&raw[..]);

        FormatPrefix::deserialize_from(&mut file).expect("Deserialized prefix");

        for i in 0..raw.len() - 1 {
            let mut file = Cursor::new(&raw[0..i]);
            match FormatPrefix::deserialize_from(&mut file) {
                Err(_) => (),
                _ => panic!("Short file cannot be deserialized"),
            }
        }
    }

    #[test]
    fn format_prefix_bad_prefix() {
        let raw = [1u8; FormatPrefix::SERIALIZE_SIZE];

        match FormatPrefix::deserialize(&raw) {
            Err(_) => (),
            _ => panic!("Bad prefix is expected"),
        }

        let mut file = Cursor::new(&raw[..]);

        match FormatPrefix::deserialize_from(&mut file) {
            Err(_) => (),
            _ => panic!("Bad prefix is expected"),
        }
    }

    #[test]
    fn mini_format_prefix_good() {
        const RANDOM_ADD: usize = 12;
        let mut raw = [1u8; MiniFormatPrefix::SERIALIZE_SIZE + RANDOM_ADD];

        MiniCocoonHeader::new([1; 12], 13).serialize_into(&mut raw);

        let prefix = MiniFormatPrefix::deserialize(&raw).expect("Deserialized container's prefix");

        assert_eq!(&raw[..MINI_HEADER_SIZE], prefix.prefix());
        assert_eq!(
            &raw[MINI_HEADER_SIZE..MINI_HEADER_SIZE + TAG_SIZE],
            prefix.tag()
        );
    }

    #[test]
    fn mini_format_prefix_short() {
        let mut raw = [1u8; MiniFormatPrefix::SERIALIZE_SIZE];

        MiniCocoonHeader::new([1; 12], 13).serialize_into(&mut raw);
        MiniFormatPrefix::deserialize(&raw).expect("Deserialized container's prefix");

        match MiniFormatPrefix::deserialize(&raw[0..MiniFormatPrefix::SERIALIZE_SIZE - 1]) {
            Err(err) => match err {
                Error::UnrecognizedFormat => (),
                _ => panic!("Invalid error"),
            },
            Ok(_) => panic!("Cocoon prefix has not to be parsed"),
        };
    }

    #[test]
    fn mini_format_prefix_deserialize_from() {
        let mut raw = [1u8; MiniFormatPrefix::SERIALIZE_SIZE];

        MiniCocoonHeader::new([1; 12], 13).serialize_into(&mut raw);

        let mut file = Cursor::new(&raw[..]);

        MiniFormatPrefix::deserialize_from(&mut file).expect("Deserialized prefix");

        for i in 0..raw.len() - 1 {
            let mut file = Cursor::new(&raw[0..i]);
            match FormatPrefix::deserialize_from(&mut file) {
                Err(_) => (),
                _ => panic!("Short file cannot be deserialized"),
            }
        }
    }
}
