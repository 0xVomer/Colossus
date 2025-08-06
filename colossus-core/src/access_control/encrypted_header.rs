use crate::{
    access_control::{
        AccessControl, CapabilityAuthorityPublicKey,
        capability::AccessCapabilityToken,
        cryptography::{SHARED_SECRET_LENGTH, XEnc, traits::KemAc},
    },
    policy::{AccessPolicy, Error},
};
use cosmian_crypto_core::{
    CryptoCoreError, Dem, FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, Secret,
    SymmetricKey, XChaCha20Poly1305, kdf256,
};

#[derive(Debug, PartialEq, Eq)]
pub struct CleartextHeader {
    pub secret: Secret<SHARED_SECRET_LENGTH>,
    pub metadata: Option<Vec<u8>>,
}

#[derive(Debug, PartialEq)]
pub struct EncryptedHeader {
    pub encapsulation: XEnc,
    pub encrypted_metadata: Option<Vec<u8>>,
}

impl EncryptedHeader {
    pub fn generate(
        api: &AccessControl,
        auth_pk: &CapabilityAuthorityPublicKey,
        ap: &AccessPolicy,
        metadata: Option<&[u8]>,
        authentication_data: Option<&[u8]>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self), Error> {
        let (seed, encapsulation) = api.encaps(auth_pk, ap)?;

        let encrypted_metadata = metadata
            .map(|bytes| {
                let key = SymmetricKey::derive(&seed, &[0u8])?;
                let nonce = Nonce::new(&mut *api.rng());
                let ctx =
                    XChaCha20Poly1305::new(&key).encrypt(&nonce, bytes, authentication_data)?;
                Ok::<_, Error>([nonce.as_bytes(), &ctx].concat())
            })
            .transpose()?;

        let mut secret = Secret::default();
        kdf256!(&mut *secret, &*seed, &[1u8]);

        Ok((secret, Self { encapsulation, encrypted_metadata }))
    }

    pub fn decrypt(
        &self,
        api: &AccessControl,
        cap_token: &AccessCapabilityToken,
        authentication_data: Option<&[u8]>,
    ) -> Result<Option<CleartextHeader>, Error> {
        api.decaps(cap_token, &self.encapsulation)?
            .map(|seed| {
                let metadata = self
                    .encrypted_metadata
                    .as_ref()
                    .map(|ctx| {
                        if ctx.len() < XChaCha20Poly1305::NONCE_LENGTH {
                            Err(CryptoCoreError::CiphertextTooSmallError {
                                ciphertext_len: ctx.len(),
                                min: XChaCha20Poly1305::NONCE_LENGTH as u64,
                            })
                        } else {
                            let key = SymmetricKey::derive(&seed, &[0u8])?;
                            XChaCha20Poly1305::new(&key).decrypt(
                                &Nonce::try_from_slice(&ctx[..XChaCha20Poly1305::NONCE_LENGTH])?,
                                &ctx[XChaCha20Poly1305::NONCE_LENGTH..],
                                authentication_data,
                            )
                        }
                    })
                    .transpose()?;

                let mut secret = Secret::<SHARED_SECRET_LENGTH>::default();
                kdf256!(&mut *secret, &*seed, &[1u8]);

                Ok(CleartextHeader { secret, metadata })
            })
            .transpose()
    }
}

mod serialization {

    use super::*;
    use cosmian_crypto_core::bytes_ser_de::{
        Deserializer, Serializable, Serializer, to_leb128_len,
    };

    impl Serializable for EncryptedHeader {
        type Error = Error;

        fn length(&self) -> usize {
            self.encapsulation.length()
                + if let Some(metadata) = &self.encrypted_metadata {
                    to_leb128_len(metadata.len()) + metadata.len()
                } else {
                    1
                }
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = self.encapsulation.write(ser)?;
            match &self.encrypted_metadata {
                Some(bytes) => n += ser.write_vec(bytes)?,
                None => n += ser.write_vec(&[])?,
            }
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let encapsulation = de.read::<XEnc>()?;
            let ciphertext = de.read_vec()?;
            let encrypted_metadata = if ciphertext.is_empty() { None } else { Some(ciphertext) };
            Ok(Self { encapsulation, encrypted_metadata })
        }
    }

    impl Serializable for CleartextHeader {
        type Error = Error;

        fn length(&self) -> usize {
            SHARED_SECRET_LENGTH
                + to_leb128_len(self.metadata.as_ref().map(std::vec::Vec::len).unwrap_or_default())
                + self.metadata.as_ref().map(std::vec::Vec::len).unwrap_or_default()
        }

        fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
            let mut n = ser.write_array(&self.secret[..SHARED_SECRET_LENGTH])?;
            match &self.metadata {
                Some(bytes) => n += ser.write_vec(bytes)?,
                None => n += ser.write_vec(&[])?,
            }
            Ok(n)
        }

        fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
            let seed =
                Secret::from_unprotected_bytes(&mut de.read_array::<SHARED_SECRET_LENGTH>()?);
            let metadata = de.read_vec()?;
            let metadata = if metadata.is_empty() { None } else { Some(metadata) };
            Ok(Self { secret: seed, metadata })
        }
    }

    #[test]
    fn test_ser() {
        use crate::access_control::test_utils::gen_auth;
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let api = AccessControl::default();
        let (mut msk, mpk) = gen_auth(&api, false).unwrap();

        let ap = AccessPolicy::parse("(DPT::MKG || DPT::FIN) && SEC::TOP").unwrap();
        let usk = api.grant_unsafe_capability(&mut msk, &ap).unwrap();

        let test_encrypted_header = |ap, metadata, authentication_data| {
            let (secret, encrypted_header) =
                EncryptedHeader::generate(&api, &mpk, &ap, metadata, authentication_data).unwrap();
            test_serialization(&encrypted_header)
                .expect("failed serialization test for the encrypted header");
            let decrypted_header =
                encrypted_header.decrypt(&api, &usk, authentication_data).unwrap();
            let decrypted_header = decrypted_header.unwrap();
            test_serialization(&decrypted_header)
                .expect("failed serialization test for the cleartext header");
            assert_eq!(secret, decrypted_header.secret, "failed secret equality test");
            assert_eq!(
                metadata,
                decrypted_header.metadata.as_deref(),
                "failed metadata equality test"
            );
        };

        test_encrypted_header(AccessPolicy::parse("DPT::MKG").unwrap(), None, None);
        test_encrypted_header(
            AccessPolicy::parse("DPT::MKG").unwrap(),
            Some("metadata".as_bytes()),
            None,
        );
        test_encrypted_header(
            AccessPolicy::parse("DPT::MKG").unwrap(),
            Some("metadata".as_bytes()),
            Some("authentication data".as_bytes()),
        );
        test_encrypted_header(
            AccessPolicy::parse("DPT::MKG").unwrap(),
            None,
            Some("authentication data".as_bytes()),
        );
    }
}
