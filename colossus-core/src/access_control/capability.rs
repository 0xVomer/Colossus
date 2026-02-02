mod access_right;
mod attestation;
mod authority;
mod token;
mod tracing;

pub use crate::dac::{Attributes, keypair::CredProof, zkp::Nonce};
pub use access_right::{AccessRightPublicKey, AccessRightSecretKey};
pub use attestation::{
    AuthorityIdentity, CapabilityAttestation, DelegationCertificate, DelegationChain,
    DelegationScope,
};
pub use authority::{
    CapabilityAuthority, CapabilityAuthorityPublicKey, create_blinded_capability_token,
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
    policy::{AttributeStatus, Error, RevisionMap, RevisionVec, Right},
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

/// A blinded access claim for privacy-preserving capability requests.
///
/// Unlike `AccessClaim` which contains plaintext `QualifiedAttribute` values,
/// this claim only contains blinded attribute commitments. The authority
/// cannot see the actual attribute values, only verify that the issuer
/// vouches for them through ownership proofs.
///
/// # Flow
///
/// 1. User obtains a DAC credential from an issuer (with plaintext attributes)
/// 2. User creates blinded commitments for their attributes
/// 3. Issuer signs ownership proofs for the blinded attributes
/// 4. User submits `BlindedCapabilityClaim` to authority
/// 5. Authority grants capability without seeing actual attribute values
pub struct BlindedCapabilityClaim {
    /// Index of the issuer that registered with the authority (1-indexed)
    pub issuer_id: usize,
    /// The blinded attributes being claimed
    pub blinded_attributes: Vec<crate::policy::BlindedAttribute>,
    /// Ownership proofs for each blinded attribute
    pub ownership_proofs: Vec<crate::policy::AttributeOwnershipProof>,
    /// Optional: batch proof for all attributes (more efficient)
    pub batch_proof: Option<crate::policy::BatchOwnershipProof>,
}

impl BlindedCapabilityClaim {
    /// Create a new claim with individual ownership proofs.
    pub fn new(issuer_id: usize) -> Self {
        Self {
            issuer_id,
            blinded_attributes: Vec::new(),
            ownership_proofs: Vec::new(),
            batch_proof: None,
        }
    }

    /// Create from a BlindedAccessClaim.
    pub fn from_blinded_claim(issuer_id: usize, claim: crate::policy::BlindedAccessClaim) -> Self {
        Self {
            issuer_id,
            blinded_attributes: claim.attributes,
            ownership_proofs: claim.proofs,
            batch_proof: None,
        }
    }

    /// Create from a batched claim (more efficient).
    pub fn from_batched_claim(
        issuer_id: usize,
        claim: crate::policy::BlindedAccessClaimBatched,
    ) -> Self {
        Self {
            issuer_id,
            blinded_attributes: claim.batch_proof.attributes.clone(),
            ownership_proofs: Vec::new(), // Not needed when using batch proof
            batch_proof: Some(claim.batch_proof),
        }
    }

    /// Add a blinded attribute with its proof.
    pub fn add_attribute(
        &mut self,
        attribute: crate::policy::BlindedAttribute,
        proof: crate::policy::AttributeOwnershipProof,
    ) {
        self.blinded_attributes.push(attribute);
        self.ownership_proofs.push(proof);
    }

    /// Verify all proofs in this claim.
    pub fn verify(&self, issuer_public_key: &crate::crypto::Falcon512PublicKey) -> bool {
        // If we have a batch proof, verify that
        if let Some(ref batch_proof) = self.batch_proof {
            return batch_proof.verify(issuer_public_key);
        }

        // Otherwise verify individual proofs
        if self.blinded_attributes.len() != self.ownership_proofs.len() {
            return false;
        }

        for (attr, proof) in self.blinded_attributes.iter().zip(self.ownership_proofs.iter()) {
            // Verify the proof is for this attribute
            if proof.attribute.commitment() != attr.commitment() {
                return false;
            }
            // Verify the proof signature
            if !proof.verify(issuer_public_key) {
                return false;
            }
        }

        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use cosmian_crypto_core::{
        CsRng, bytes_ser_de::test_serialization, reexport::rand_core::SeedableRng,
    };
    use std::collections::HashMap;

    #[test]
    fn test_serializations() {
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
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        access_control::cryptography::MIN_TRACING_LEVEL,
        policy::{AttributeStatus, Right},
    };
    use cosmian_crypto_core::{CsRng, reexport::rand_core::SeedableRng};
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
    #[ignore] // Legacy test - requires AccessPolicy-based flow which has been removed
    fn test_reencrypt_with_auth() {
        // This test used the legacy AccessPolicy-based flow with gen_auth
        // and grant_unsafe_capability. The functionality is now blinded-mode only.
    }

    #[test]
    #[ignore] // Legacy test - requires AccessPolicy-based flow which has been removed
    fn test_root_kem() {
        // This test used the legacy AccessPolicy-based KEM flow.
        // Use encapsulate_for_rights and decapsulate methods instead.
    }

    #[test]
    #[ignore] // Legacy test - requires PkeAc trait which has been removed
    fn test_root_pke() {
        // This test used the legacy PkeAc trait.
        // The blinded mode provides privacy-preserving encryption instead.
    }

    // ========================================================================
    // Authority Identity Integration Tests
    // ========================================================================

    #[test]
    fn test_authority_with_identity() {
        use miden_crypto::field::PrimeCharacteristicRing;

        let mut rng = CsRng::from_entropy();

        // Create authority with identity
        let auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap().with_identity();

        // Verify identity is set
        assert!(auth.identity().is_some());

        // Verify identity has valid commitment (not all zeros)
        let identity = auth.identity().unwrap();
        let commitment = identity.commitment();
        let zero_word = miden_crypto::Word::new([miden_crypto::Felt::ZERO; 4]);
        assert_ne!(commitment, zero_word);
    }

    #[test]
    fn test_authority_token_attestation() {
        let mut rng = CsRng::from_entropy();
        let coordinate = Right::random(&mut rng);

        // Create authority with identity
        let mut auth =
            CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap().with_identity();

        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from([(coordinate.clone(), AttributeStatus::EncryptDecrypt)]),
        )
        .unwrap();

        // Create a capability token
        let cap_token =
            create_unsafe_capability_token(&mut rng, &mut auth, HashSet::from([coordinate]))
                .unwrap();

        // Create attestation for the token
        let timestamp = 1234567890u64;
        let attestation = auth.attest_token(&cap_token, timestamp).unwrap();
        assert!(attestation.is_some());

        let attestation = attestation.unwrap();

        // Verify the attestation
        assert!(attestation.verify());
        assert_eq!(attestation.timestamp, timestamp);

        // Verify attestation matches authority's public key
        let identity = auth.identity().unwrap();
        assert_eq!(attestation.authority_pk.commitment(), identity.public_key().commitment());
    }

    #[test]
    fn test_authority_without_identity_no_attestation() {
        let mut rng = CsRng::from_entropy();
        let coordinate = Right::random(&mut rng);

        // Create authority WITHOUT identity
        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();

        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from([(coordinate.clone(), AttributeStatus::EncryptDecrypt)]),
        )
        .unwrap();

        // Create a capability token
        let cap_token =
            create_unsafe_capability_token(&mut rng, &mut auth, HashSet::from([coordinate]))
                .unwrap();

        // Attestation should return None when no identity is set
        let attestation = auth.attest_token(&cap_token, 1234567890).unwrap();
        assert!(attestation.is_none());
    }

    #[test]
    fn test_authority_serialization_with_identity() {
        use cosmian_crypto_core::bytes_ser_de::test_serialization;

        let mut rng = CsRng::from_entropy();

        // Create authority with identity
        let mut auth =
            CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap().with_identity();

        // Create self-attestation
        if let Some(identity) = auth.identity_mut() {
            identity.create_self_attestation(1000);
        }

        // Add some access rights
        let coordinate = Right::random(&mut rng);
        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from([(coordinate, AttributeStatus::EncryptDecrypt)]),
        )
        .unwrap();

        // Serialize and deserialize
        test_serialization(&auth).expect("authority serialization failed");

        // Verify identity survives serialization
        let serialized = auth.serialize().unwrap();
        let restored = CapabilityAuthority::deserialize(&serialized).unwrap();

        assert!(restored.identity().is_some());
        assert_eq!(
            auth.identity().unwrap().commitment(),
            restored.identity().unwrap().commitment()
        );
    }

    #[test]
    fn test_authority_delegation() {
        let mut rng = CsRng::from_entropy();

        // Create two authorities with identities
        let auth1 =
            CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap().with_identity();

        let auth2 =
            CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap().with_identity();

        // Authority 1 delegates to Authority 2
        let cert = auth1
            .delegate_to(
                &auth2.identity().unwrap().public_key(),
                DelegationScope::Full,
                Some(2000000), // Expires at timestamp 2000000
            )
            .expect("delegation should succeed when identity is set");

        // Verify the certificate
        assert!(cert.verify(Some(1000000))); // Current time 1000000 < expiration
        assert!(!cert.verify(Some(3000000))); // Current time 3000000 > expiration

        // Verify delegator matches auth1
        assert_eq!(
            cert.delegator_pk.commitment(),
            auth1.identity().unwrap().public_key().commitment()
        );
    }

    #[test]
    fn test_token_commitment_deterministic() {
        let mut rng = CsRng::from_entropy();
        let coordinate = Right::random(&mut rng);

        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_capability_authority(
            &mut rng,
            &mut auth,
            HashMap::from([(coordinate.clone(), AttributeStatus::EncryptDecrypt)]),
        )
        .unwrap();

        let cap_token =
            create_unsafe_capability_token(&mut rng, &mut auth, HashSet::from([coordinate]))
                .unwrap();

        // Compute commitment twice - should be identical
        let commitment1 = CapabilityAuthority::compute_token_commitment(&cap_token).unwrap();
        let commitment2 = CapabilityAuthority::compute_token_commitment(&cap_token).unwrap();

        assert_eq!(commitment1, commitment2);
    }
}
