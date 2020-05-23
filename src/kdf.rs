/// A 256-bit key derived from a password using PBKDF2 (HMAC-SHA256) with guaranteed zeroization.
pub mod pbkdf2 {
    use hmac::Hmac;
    use pbkdf2::pbkdf2;
    use sha2::Sha256;
    use zeroize::Zeroizing;

    const KEY_SIZE: usize = 32;

    /// Derives a 256-bit symmetric key from a byte array (password or another key) using PBKDF2.
    pub fn derive(salt: &[u8], password: &[u8], iterations: u32) -> Zeroizing<[u8; KEY_SIZE]> {
        // NIST SP 800-132 (PBKDF2) recommends to concatenate a constant purpose to the random part
        // in order to narrow down a key usage domain to the scope of the current application.
        // Salt = [constant string || random value].
        let ext_salt = [b"cocoon", salt].concat();

        // Prepare an output buffer.
        let mut derived_key = [0u8; KEY_SIZE];

        pbkdf2::<Hmac<Sha256>>(password, &ext_salt, iterations as usize, &mut derived_key);

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
        let key = pbkdf2::derive(&salt, &password[..], 1000);

        assert_eq!(
            key.as_ref(),
            &[
                207, 82, 98, 39, 208, 161, 92, 199, 136, 199, 121, 65, 242, 33, 106, 220, 113, 55,
                223, 250, 130, 201, 111, 201, 128, 57, 31, 77, 37, 147, 202, 173
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
                119, 156, 55, 55, 165, 161, 237, 97, 146, 33, 13, 225, 14, 218, 244, 41, 194, 221,
                18, 59, 120, 71, 71, 46, 119, 30, 239, 7, 22, 68, 88, 242
            ]
        );
    }
}
