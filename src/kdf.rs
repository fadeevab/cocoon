pub const KEY_SIZE: usize = 32;
pub const SALT_MIN_SIZE: usize = 16;

/// A 256-bit key derived from a password using PBKDF2 (HMAC-SHA256) with guaranteed zeroization.
pub mod pbkdf2 {
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    use super::{KEY_SIZE, SALT_MIN_SIZE};

    /// Derives a 256-bit symmetric key from a byte array (password or another key) using PBKDF2.
    pub fn derive(salt: &[u8], password: &[u8], iterations: u32) -> Zeroizing<[u8; KEY_SIZE]> {
        debug_assert!(salt.len() >= SALT_MIN_SIZE);

        // NIST SP 800-132 (PBKDF2) recommends to concatenate a constant purpose to the random part
        // in order to narrow down a key usage domain to the scope of the current application.
        // Salt = [constant string || random value].
        let ext_salt = [b"cocoon", salt].concat();

        // Prepare an output buffer.
        let mut derived_key = [0u8; KEY_SIZE];

        pbkdf2::<Hmac<Sha256>>(password, &ext_salt, iterations, &mut derived_key);

        Zeroizing::new(derived_key)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encryption_key_new_salt0() {
        let password = b"password";
        let salt = vec![0u8; 16];
        let key = pbkdf2::derive(&salt, password, 1000);

        assert_eq!(
            key.as_ref(),
            &[
                110, 120, 137, 247, 90, 238, 41, 97, 25, 140, 207, 38, 9, 49, 201, 243, 10, 228,
                78, 48, 37, 238, 52, 193, 171, 157, 125, 89, 215, 246, 71, 6
            ]
        );
    }

    #[test]
    fn encryption_key_new_salt16() {
        let password = b"password";
        let salt = vec![0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15];
        let key = pbkdf2::derive(&salt, &password[..], 1000);

        assert_eq!(
            key.as_ref(),
            &[
                128, 112, 58, 101, 232, 184, 2, 133, 16, 237, 161, 220, 75, 102, 29, 102, 211, 88,
                204, 1, 46, 119, 49, 83, 180, 4, 67, 54, 14, 206, 250, 240
            ]
        );
    }
}
