use alloc::format;
use alloc::string::String;

pub type Digest = [u8; DIGEST_BYTES];

pub const EMPTY_DIGEST: [u8; DIGEST_BYTES] = [0u8; DIGEST_BYTES];

pub const DIGEST_BYTES: usize = 32;

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
