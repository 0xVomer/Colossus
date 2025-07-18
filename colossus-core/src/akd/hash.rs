//! This module contains all the hashing utilities needed for the AKD directory
//! and verification operations

use alloc::format;
use alloc::string::String;

/// A hash digest of a specified number of bytes
pub type Digest = [u8; DIGEST_BYTES];
/// Represents an empty digest, with no data contained
pub const EMPTY_DIGEST: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];
/// The number of bytes in a digest
pub const DIGEST_BYTES: usize = 32;

/// Try and parse a digest from an unknown length of bytes. Helpful for converting a `Vec<u8>`
/// to a [Digest]
pub fn try_parse_digest(value: &[u8]) -> Result<Digest, String> {
    if value.len() != DIGEST_BYTES {
        Err(format!(
            "Failed to parse Digest. Expected {} bytes but the value has {} bytes",
            DIGEST_BYTES,
            value.len()
        ))
    } else {
        let mut arr = EMPTY_DIGEST;
        arr.copy_from_slice(value);
        Ok(arr)
    }
}

mod test {
    //! Tests for hashing

    #[test]
    fn test_try_parse_digest() {
        let mut data = super::EMPTY_DIGEST;
        let digest = super::try_parse_digest(&data).unwrap();
        assert_eq!(super::EMPTY_DIGEST, digest);
        data[0] = 1;
        let digest = super::try_parse_digest(&data).unwrap();
        assert_ne!(super::EMPTY_DIGEST, digest);

        let data_bad_length = vec![0u8; super::DIGEST_BYTES + 1];
        assert!(super::try_parse_digest(&data_bad_length).is_err());
    }
}
