#[cfg(feature = "std")]
use std::io::Read;

use super::error::Error;

const HEADER_SIZE: usize = super::header::CocoonHeader::SIZE;
const TAG_SIZE: usize = 16;

pub struct FormatPrefix {
    header: [u8; HEADER_SIZE],
    tag: [u8; TAG_SIZE],
}

impl<'a> FormatPrefix {
    pub fn deserialize(start: &[u8]) -> Result<Self, Error> {
        if start.len() < HEADER_SIZE + TAG_SIZE {
            return Err(Error::UnrecognizedFormat);
        };

        let mut header = [0u8; HEADER_SIZE];
        let mut tag = [0u8; TAG_SIZE];

        header.copy_from_slice(&start[..HEADER_SIZE]);
        tag.copy_from_slice(&start[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]);

        Ok(FormatPrefix { header, tag })
    }

    #[cfg(feature = "std")]
    pub fn deserialize_from(reader: &mut impl Read) -> Result<Self, Error> {
        let mut header = [0u8; HEADER_SIZE];
        let mut tag = [0u8; TAG_SIZE];

        reader.read_exact(&mut header)?;
        reader.read_exact(&mut tag)?;

        Ok(FormatPrefix { header, tag })
    }

    pub fn header(&self) -> &[u8] {
        &self.header
    }

    pub fn tag(&self) -> &[u8] {
        &self.tag
    }
}

pub struct FormatVersion1;

impl FormatVersion1 {
    pub const fn size() -> usize {
        HEADER_SIZE + TAG_SIZE
    }

    pub fn serialize(
        header: &[u8; HEADER_SIZE],
        tag: &[u8; TAG_SIZE],
    ) -> [u8; HEADER_SIZE + TAG_SIZE] {
        let mut prefix = [0u8; HEADER_SIZE + TAG_SIZE];
        prefix[..HEADER_SIZE].copy_from_slice(header);
        prefix[HEADER_SIZE..HEADER_SIZE + TAG_SIZE].copy_from_slice(tag);
        prefix
    }
}

#[cfg(test)]
mod test {
    use super::*;

    use crate::{CocoonConfig, CocoonHeader};

    #[test]
    fn format_version1() {
        let variant = if cfg!(feature = "debug") { 0x02 } else { 0x01 };

        assert_eq!(44 + 16, FormatVersion1::size());

        let header = CocoonHeader::new(CocoonConfig::default(), [1; 16], [2; 12], 50).serialize();
        let tag = [3; 16];

        assert_eq!(
            [
                127, 192, 10, 1, 1, 1, variant, 0, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1,
                2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 0, 0, 0, 0, 0, 0, 0, 50, 3, 3, 3, 3, 3, 3, 3,
                3, 3, 3, 3, 3, 3, 3, 3, 3
            ][..],
            FormatVersion1::serialize(&header, &tag)[..]
        );
    }
}
