/// Error variants produced by the Cocoon API.
#[derive(Debug)]
pub enum Error {
    /// I/o error during read/write operation (`Cocoon::dump`, `Cocoon::parse`).
    #[cfg(feature = "std")]
    Io(std::io::Error),
    /// Format is not recognized. Probably corrupted.
    UnrecognizedFormat,
    /// Cryptographic error. There could be a few reasons:
    /// 1. Integrity is compromised.
    /// 2. Password is invalid.
    Cryptography,
    /// Container is too large to get processed on the current architecture.
    /// E.g. it's not possible to process a container larger than 4 GB on 32-bit architecture.
    TooLarge,
    /// Buffer is too short and barely holds all data to decrypt, inconsistent length
    /// encoded to the header.
    TooShort,
}

#[cfg(feature = "std")]
impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        match err.kind() {
            std::io::ErrorKind::UnexpectedEof => Error::TooShort,
            _ => Error::Io(err),
        }
    }
}
