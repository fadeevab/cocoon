/// Error variants produced by the Cocoon API.
#[derive(Debug)]
pub enum Error {
    /// I/o error during read/write operation (`Cocoon::dump`, `Cocoon::parse`).
    Io(std::io::Error),
    /// Format is not recognized. Probably corrupted.
    UnrecognizedFormat,
    /// Cryptographic error. There could be a few reasons:
    /// 1. Integrity is compromised.
    /// 2. Password is invalid.
    Cryptography,
}

impl From<std::io::Error> for Error {
    fn from(err: std::io::Error) -> Self {
        Error::Io(err)
    }
}
