mod access_right;
mod authority;
mod token;
mod tracing;

pub use crate::dac::{Attributes, keypair::CredProof, zkp::Nonce};
pub use access_right::{AccessRightPublicKey, AccessRightSecretKey};
pub use authority::{
    CapabilityAuthority, CapabilityAuthorityPublicKey, create_capability_token,
    create_unsafe_capability_token, prune_capability_authority, refresh_access_rights,
    refresh_capability_authority, refresh_capability_token, update_capability_authority,
};
pub use token::AccessCapabilityToken;
pub use tracing::TracingPublicKey;

use crate::{
    access_control::cryptography::{
        ElGamal, Encapsulations, G_hash, H_hash, J_hash, KmacSignature, MIN_TRACING_LEVEL, MlKem,
        SHARED_SECRET_LENGTH, SIGNATURE_LENGTH, SIGNING_KEY_LENGTH, XEnc, shuffle,
        traits::{Kem, Nike, Sampling, Zero},
        xor_2, xor_in_place,
    },
    policy::{AccessStructure, AttributeStatus, Error, RevisionMap, RevisionVec, Right},
};

use cosmian_crypto_core::{
    FixedSizeCBytes, RandomFixedSizeCBytes, Secret, SymmetricKey,
    bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len},
    reexport::rand_core::CryptoRngCore,
};
pub use secrecy::zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};
pub use secrecy::{ExposeSecret, SecretBox};
use std::{
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
};
use tiny_keccak::{Hasher, Kmac, Sha3};

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct AccessCapabilityId(pub LinkedList<<ElGamal as Nike>::SecretKey>);

impl AccessCapabilityId {
    fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }

    fn iter(&self) -> impl Iterator<Item = &<ElGamal as Nike>::SecretKey> {
        self.0.iter()
    }
}

impl Serializable for AccessCapabilityId {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len()) + self.iter().map(|marker| marker.length()).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for marker in &self.0 {
            n += ser.write(marker)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let length = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut id = LinkedList::new();
        for _ in 0..length {
            let marker = de.read()?;
            id.push_back(marker);
        }
        Ok(Self(id))
    }
}

pub struct AccessClaim {
    pub issuer_id: usize,
    pub cred_proof: CredProof,
    pub attributes: Vec<Attributes>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access_control::{AccessControl, cryptography::traits::KemAc, test_utils::gen_auth},
        policy::AccessPolicy,
    };
    use cosmian_crypto_core::{
        CsRng, bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng,
    };
    use std::collections::HashMap;

    #[test]
    fn test_serializations() {
        {
            let mut rng = CsRng::from_entropy();
            let access_right_1 = Right::random(&mut rng);
            let access_right_2 = Right::random(&mut rng);
            let access_right_3 = Right::random(&mut rng);

            let universe = HashMap::from([
                (access_right_1.clone(), AttributeStatus::EncryptDecrypt),
                (access_right_2.clone(), AttributeStatus::EncryptDecrypt),
                (access_right_3.clone(), AttributeStatus::EncryptDecrypt),
            ]);

            let user_set = HashSet::from([access_right_1.clone(), access_right_3.clone()]);
            let target_set = HashSet::from([access_right_1, access_right_3]);
            let mut rng = CsRng::from_entropy();

            let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL + 2, &mut rng).unwrap();
            update_capability_authority(&mut rng, &mut auth, universe.clone()).unwrap();
            let rpk = auth.rpk().unwrap();
            let cap_token = create_unsafe_capability_token(&mut rng, &mut auth, user_set).unwrap();
            let (_, enc) = rpk.encapsulate(&mut rng, &target_set).unwrap();

            test_serialization(&auth).unwrap();
            test_serialization(&rpk).unwrap();
            test_serialization(&cap_token).unwrap();
            test_serialization(&enc).unwrap();

            refresh_capability_authority(&mut rng, &mut auth, universe.keys().cloned().collect())
                .unwrap();
            test_serialization(&auth).unwrap();
        }

        {
            let api = AccessControl::default();
            let (mut msk, mpk) = gen_auth(&api, false).unwrap();
            let cap_token = api
                .grant_unsafe_capability(&mut msk, &AccessPolicy::parse("SEC::TOP").unwrap())
                .unwrap();
            let (_, enc) = api.encaps(&mpk, &AccessPolicy::parse("DPT::MKG").unwrap()).unwrap();

            test_serialization(&msk).unwrap();
            test_serialization(&mpk).unwrap();
            test_serialization(&cap_token).unwrap();
            test_serialization(&enc).unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        access_control::{
            AccessControl,
            cryptography::{
                MIN_TRACING_LEVEL,
                traits::{KemAc, PkeAc},
            },
            test_utils::gen_auth,
        },
        policy::{AccessPolicy, AttributeStatus, Right},
    };
    use cosmian_crypto_core::{CsRng, XChaCha20Poly1305, reexport::rand_core::SeedableRng};
    use std::collections::{HashMap, HashSet};

    #[test]
    fn test_encapsulation() {
        let mut rng = CsRng::from_entropy();
        let other_coordinate = Right::random(&mut rng);
        let target_coordinate = Right::random(&mut rng);

        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from_iter([
                (other_coordinate.clone(), AttributeStatus::EncryptDecrypt),
                (target_coordinate.clone(), AttributeStatus::EncryptDecrypt),
            ]),
        )
        .unwrap();
        let rpk = auth.rpk().unwrap();

        let (key, enc) = rpk
            .encapsulate(&mut rng, &HashSet::from_iter([target_coordinate.clone()]))
            .unwrap();
        assert_eq!(enc.count(), 1);

        for _ in 0..3 {
            let cap_token = create_unsafe_capability_token(
                &mut rng,
                &mut auth,
                HashSet::from_iter([target_coordinate.clone()]),
            )
            .unwrap();
            assert_eq!(cap_token.count(), 1);
            assert_eq!(Some(&key), cap_token.decapsulate(&mut rng, &enc).unwrap().as_ref());
        }

        let cap_token = create_unsafe_capability_token(
            &mut rng,
            &mut auth,
            HashSet::from_iter([other_coordinate.clone()]),
        )
        .unwrap();
        assert_eq!(cap_token.count(), 1);
        assert_eq!(None, cap_token.decapsulate(&mut rng, &enc).unwrap().as_ref());
    }

    #[test]
    fn test_update() {
        let mut rng = CsRng::from_entropy();

        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        assert_eq!(auth.tracing_level(), MIN_TRACING_LEVEL);
        assert_eq!(auth.count(), 0);

        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.tpk.tracing_level(), MIN_TRACING_LEVEL);
        assert_eq!(rpk.count(), 0);

        let mut coordinates = (0..30)
            .map(|_| (Right::random(&mut rng), AttributeStatus::EncryptDecrypt))
            .collect::<HashMap<_, _>>();
        update_capability_authority(&mut rng, &mut auth, coordinates.clone()).unwrap();
        assert_eq!(auth.count(), 30);

        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.count(), 30);

        coordinates.iter_mut().enumerate().for_each(|(i, (_, status))| {
            if i % 2 == 0 {
                *status = AttributeStatus::DecryptOnly;
            }
        });
        update_capability_authority(&mut rng, &mut auth, coordinates.clone()).unwrap();
        assert_eq!(auth.count(), 30);
        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.count(), 15);

        let coordinates = coordinates.into_iter().take(10).collect::<HashMap<_, _>>();
        update_capability_authority(&mut rng, &mut auth, coordinates).unwrap();
        assert_eq!(auth.count(), 10);
        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.count(), 5);
    }

    #[test]
    fn test_refresh_capability_authority() {
        let mut rng = CsRng::from_entropy();
        let coordinate_1 = Right::random(&mut rng);
        let coordinate_2 = Right::random(&mut rng);
        let subspace_1 = HashSet::from_iter([coordinate_1.clone()]);
        let subspace_2 = HashSet::from_iter([coordinate_2.clone()]);
        let universe = HashSet::from_iter([coordinate_1.clone(), coordinate_2.clone()]);

        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from_iter([
                (coordinate_1.clone(), AttributeStatus::EncryptDecrypt),
                (coordinate_2.clone(), AttributeStatus::EncryptDecrypt),
            ]),
        )
        .unwrap();
        let rpk = auth.rpk().unwrap();
        let mut cap_token_1 =
            create_unsafe_capability_token(&mut rng, &mut auth, subspace_1.clone()).unwrap();
        let mut cap_token_2 =
            create_unsafe_capability_token(&mut rng, &mut auth, subspace_2.clone()).unwrap();

        let (old_key_1, old_enc_1) = rpk.encapsulate(&mut rng, &subspace_1).unwrap();
        let (old_key_2, old_enc_2) = rpk.encapsulate(&mut rng, &subspace_2).unwrap();

        assert_eq!(
            Some(&old_key_1),
            cap_token_1.decapsulate(&mut rng, &old_enc_1).unwrap().as_ref()
        );
        assert_eq!(None, cap_token_1.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(Some(old_key_2), cap_token_2.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(None, cap_token_2.decapsulate(&mut rng, &old_enc_1).unwrap());

        refresh_capability_authority(&mut rng, &mut auth, universe).unwrap();
        let rpk = auth.rpk().unwrap();

        let (new_key_1, new_enc_1) = rpk.encapsulate(&mut rng, &subspace_1).unwrap();
        let (new_key_2, new_enc_2) = rpk.encapsulate(&mut rng, &subspace_2).unwrap();

        assert_eq!(None, cap_token_1.decapsulate(&mut rng, &new_enc_1).unwrap());
        assert_eq!(None, cap_token_1.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(None, cap_token_2.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(None, cap_token_2.decapsulate(&mut rng, &new_enc_1).unwrap());

        refresh_capability_token(&mut rng, &mut auth, &mut cap_token_1, true).unwrap();
        refresh_capability_token(&mut rng, &mut auth, &mut cap_token_2, false).unwrap();

        assert_eq!(Some(new_key_1), cap_token_1.decapsulate(&mut rng, &new_enc_1).unwrap());
        assert_eq!(None, cap_token_1.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(Some(new_key_2), cap_token_2.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(None, cap_token_2.decapsulate(&mut rng, &new_enc_1).unwrap());

        assert_eq!(Some(old_key_1), cap_token_1.decapsulate(&mut rng, &old_enc_1).unwrap());
        assert_eq!(None, cap_token_1.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(None, cap_token_2.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(None, cap_token_2.decapsulate(&mut rng, &old_enc_1).unwrap());
    }

    #[test]
    fn test_integrity_check() {
        let mut rng = CsRng::from_entropy();
        let coordinate_1 = Right::random(&mut rng);
        let coordinate_2 = Right::random(&mut rng);
        let subspace_1 = HashSet::from_iter([coordinate_1.clone()]);
        let subspace_2 = HashSet::from_iter([coordinate_2.clone()]);

        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from_iter([
                (coordinate_1.clone(), AttributeStatus::EncryptDecrypt),
                (coordinate_2.clone(), AttributeStatus::EncryptDecrypt),
            ]),
        )
        .unwrap();
        let cap_token_1 =
            create_unsafe_capability_token(&mut rng, &mut auth, subspace_1.clone()).unwrap();
        let cap_token_2 =
            create_unsafe_capability_token(&mut rng, &mut auth, subspace_2.clone()).unwrap();

        let mut old_forged_cap_token = cap_token_1.clone();
        for (key, chain) in cap_token_2.sk_access_rights.iter() {
            old_forged_cap_token
                .sk_access_rights
                .insert_new_chain(key.clone(), chain.clone());
        }
        assert_eq!(
            old_forged_cap_token.sk_access_rights.count_elements(),
            cap_token_1.sk_access_rights.count_elements()
                + cap_token_2.sk_access_rights.count_elements()
        );

        let mut new_forged_cap_token = old_forged_cap_token.clone();
        assert!(
            refresh_capability_token(&mut rng, &mut auth, &mut new_forged_cap_token, true).is_err()
        );
        assert_eq!(new_forged_cap_token, old_forged_cap_token);
    }

    #[test]
    fn test_reencrypt_with_auth() {
        let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
        let cc = AccessControl::default();

        let mut rng = CsRng::from_entropy();

        let (mut auth, _) = gen_auth(&cc, false).unwrap();
        let rpk = cc.update_capability_authority(&mut auth).expect("cannot update master keys");
        let mut cap_token =
            cc.grant_unsafe_capability(&mut auth, &ap).expect("cannot generate cap_token");

        let (old_key, old_enc) = cc.encaps(&rpk, &ap).unwrap();
        assert_eq!(Some(&old_key), cap_token.decapsulate(&mut rng, &old_enc).unwrap().as_ref());

        cc.refresh_capability_authority(&mut auth, &ap).unwrap();
        let new_rpk = auth.rpk().unwrap();
        let (new_key, new_enc) = cc.recaps(&auth, &new_rpk, &old_enc).unwrap();
        cc.refresh_capability(&mut auth, &mut cap_token, true).unwrap();
        assert_eq!(Some(new_key), cap_token.decapsulate(&mut rng, &new_enc).unwrap());
        assert_ne!(Some(old_key), cap_token.decapsulate(&mut rng, &new_enc).unwrap());
    }

    #[test]
    fn test_root_kem() {
        let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
        let api = AccessControl::default();
        let (mut auth, _rpk) = gen_auth(&api, false).unwrap();
        let rpk = api.update_capability_authority(&mut auth).expect("cannot update master keys");
        let cap_token =
            api.grant_unsafe_capability(&mut auth, &ap).expect("cannot generate cap_token");
        let (secret, enc) = api.encaps(&rpk, &ap).unwrap();
        let res = api.decaps(&cap_token, &enc).unwrap();
        assert_eq!(secret, res.unwrap());
    }

    #[test]
    fn test_root_pke() {
        let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
        let api = AccessControl::default();
        let (mut auth, rpk) = gen_auth(&api, false).unwrap();

        let ptx = "testing encryption/decryption".as_bytes();
        let aad = "COLOSSUS-ROOT".as_bytes();

        let ctx = PkeAc::<{ XChaCha20Poly1305::KEY_LENGTH }, XChaCha20Poly1305>::encrypt(
            &api, &rpk, &ap, ptx, aad,
        )
        .expect("cannot encrypt!");
        let cap_token =
            api.grant_unsafe_capability(&mut auth, &ap).expect("cannot generate cap_token");
        let ptx1 = PkeAc::<{ XChaCha20Poly1305::KEY_LENGTH }, XChaCha20Poly1305>::decrypt(
            &api, &cap_token, &ctx, aad,
        )
        .expect("cannot decrypt the ciphertext");
        assert_eq!(ptx, &*ptx1.unwrap());
    }
}
