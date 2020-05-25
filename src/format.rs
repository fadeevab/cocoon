const HEADER_SIZE: usize = super::header::CocoonHeader::SIZE;
const TAG_SIZE: usize = 16;

pub struct FormatParser<'a> {
    start: &'a [u8],
}

impl<'a> FormatParser<'a> {
    pub fn new(start: &'a [u8]) -> Self {
        FormatParser { start }
    }

    pub fn header(&self) -> [u8; HEADER_SIZE] {
        let mut buf = [0u8; HEADER_SIZE];
        buf.copy_from_slice(&self.start[..HEADER_SIZE]);
        buf
    }

    pub fn tag(&self) -> [u8; TAG_SIZE] {
        let mut buf = [0u8; TAG_SIZE];
        buf.copy_from_slice(&self.start[HEADER_SIZE..HEADER_SIZE + TAG_SIZE]);
        buf
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
