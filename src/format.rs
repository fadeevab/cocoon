#[cfg(feature = "std")]
use std::io::Read;

use super::{
    error::Error,
    header::{CocoonHeader, CocoonVersion},
};

const HEADER_SIZE: usize = CocoonHeader::SIZE;
const TAG_SIZE: usize = 16;
const MAX_SIZE: usize = HEADER_SIZE + TAG_SIZE;

pub struct FormatPrefix {
    header: CocoonHeader,
    raw: [u8; MAX_SIZE],
    size: usize,
}

impl FormatPrefix {
    pub const SERIALIZE_SIZE: usize = MAX_SIZE;

    // The idea is that having additional extensions we shell put them in the constructor.
    // Meanwhile `tag` will be calculated later and it appears right on serialization.
    // Also parameters are moved into the object to evade additional copying.
    pub fn new(header: CocoonHeader) -> Self {
        let mut raw = [0u8; MAX_SIZE];
        let size;

        match header.version() {
            CocoonVersion::Version1 => {
                header.serialize_into(&mut raw);
                size = HEADER_SIZE + TAG_SIZE;
            }
        };

        FormatPrefix { header, raw, size }
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
        let header = CocoonHeader::deserialize(&start)?;

        let mut raw = [0u8; MAX_SIZE];
        let size: usize;

        match header.version() {
            CocoonVersion::Version1 => {
                if start.len() < HEADER_SIZE + TAG_SIZE {
                    return Err(Error::UnrecognizedFormat);
                }

                raw[..HEADER_SIZE].copy_from_slice(&start[..HEADER_SIZE]);
                raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]
                    .copy_from_slice(&start[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]);

                size = HEADER_SIZE + TAG_SIZE;
            }
        }

        Ok(FormatPrefix { header, raw, size })
    }

    #[cfg(feature = "std")]
    pub fn deserialize_from(reader: &mut impl Read) -> Result<Self, Error> {
        let mut raw = [0u8; MAX_SIZE];
        let size: usize;

        reader.read_exact(&mut raw[..HEADER_SIZE])?;
        let header = CocoonHeader::deserialize(&raw)?;

        match header.version() {
            CocoonVersion::Version1 => {
                reader.read_exact(&mut raw[HEADER_SIZE..HEADER_SIZE + TAG_SIZE])?;
                size = HEADER_SIZE + TAG_SIZE;
            }
        }

        Ok(FormatPrefix { header, raw, size })
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

    pub fn size(&self) -> usize {
        self.size
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{CocoonConfig, CocoonHeader};

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

        let prefix = FormatPrefix::deserialize(&raw).expect("Deserialized container's prefix");

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
}
