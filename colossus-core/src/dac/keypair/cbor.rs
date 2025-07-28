pub trait CBORCodec {
    fn to_cbor(&self) -> Result<Vec<u8>, crate::dac::error::Error>
    where
        Self: Sized + serde::Serialize,
    {
        let mut bytes = Vec::new();
        match ciborium::into_writer(&self, &mut bytes) {
            Ok(_) => Ok(bytes),
            Err(e) => Err(crate::dac::error::Error::CBORError(format!(
                "CBORCodec Error serializing to bytes: {}",
                e
            ))),
        }
    }

    fn from_cbor(bytes: &[u8]) -> Result<Self, crate::dac::error::Error>
    where
        for<'a> Self: Sized + serde::Deserialize<'a>,
    {
        match ciborium::from_reader(&bytes[..]) {
            Ok(item) => Ok(item),
            Err(e) => Err(crate::dac::error::Error::CBORError(format!(
                "CBORCodec Error deserializing from bytes: {}",
                e
            ))),
        }
    }
}
