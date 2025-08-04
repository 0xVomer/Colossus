pub mod capability;
mod cryptography;
pub mod encrypted_header;
mod test_utils;

use crate::{
    access_control::cryptography::{
        MIN_TRACING_LEVEL, SHARED_SECRET_LENGTH, XEnc,
        traits::{AE, KemAc, PkeAc},
    },
    dac::keypair::IssuerPublic,
    policy::{AccessPolicy, Error},
};
pub use capability::{
    AccessCapabilityId, AccessCapabilityToken, AccessRightPublicKey, AccessRightSecretKey,
    CapabilityAuthority, CapabilityAuthorityPublicKey, TracingPublicKey, create_capability_token,
    prune_capability_authority, refresh_capability_authority, refresh_capability_token,
    update_capability_authority,
};
use cosmian_crypto_core::{CsRng, Secret, SymmetricKey, reexport::rand_core::SeedableRng};
pub use encrypted_header::EncryptedHeader;
use std::sync::{Mutex, MutexGuard};
use zeroize::Zeroizing;

#[derive(Debug)]
pub struct AccessControl {
    rng: Mutex<CsRng>,
}

impl Default for AccessControl {
    fn default() -> Self {
        Self { rng: Mutex::new(CsRng::from_entropy()) }
    }
}

impl AccessControl {
    pub fn rng(&self) -> MutexGuard<CsRng> {
        self.rng.lock().expect("poisoned mutex")
    }

    pub fn setup_capability_authority(
        &self,
    ) -> Result<(CapabilityAuthority, CapabilityAuthorityPublicKey), Error> {
        let mut rng = self.rng.lock().expect("Mutex lock failed!");
        let mut auth = CapabilityAuthority::setup(MIN_TRACING_LEVEL, &mut *rng)?;
        let rights = auth.access_structure.omega()?;
        update_capability_authority(&mut *rng, &mut auth, rights)?;
        let rpk = auth.rpk()?;
        Ok((auth, rpk))
    }

    pub fn update_capability_authority(
        &self,
        auth: &mut CapabilityAuthority,
    ) -> Result<CapabilityAuthorityPublicKey, Error> {
        update_capability_authority(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            auth.access_structure.omega()?,
        )?;
        auth.rpk()
    }
    pub fn refresh_capability_authority(
        &self,
        auth: &mut CapabilityAuthority,
        ap: &AccessPolicy,
    ) -> Result<CapabilityAuthorityPublicKey, Error> {
        refresh_capability_authority(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            auth.access_structure.ap_to_access_rights(ap)?,
        )?;
        auth.rpk()
    }

    pub fn register_issuer(
        &self,
        auth: &mut CapabilityAuthority,
        issuer: &IssuerPublic,
    ) -> Result<(usize, CapabilityAuthorityPublicKey), Error> {
        let id =
            auth.register_issuer(issuer, &mut *self.rng.lock().expect("Mutex lock failed!"))?;
        let rpk = auth.rpk()?;
        Ok((id, rpk))
    }

    pub fn prune_capability_authority(
        &self,
        auth: &mut CapabilityAuthority,
        ap: &AccessPolicy,
    ) -> Result<CapabilityAuthorityPublicKey, Error> {
        prune_capability_authority(auth, &auth.access_structure.ap_to_access_rights(ap)?);
        auth.rpk()
    }

    pub fn grant_capability(
        &self,
        auth: &mut CapabilityAuthority,
        ap: &AccessPolicy,
    ) -> Result<AccessCapabilityToken, Error> {
        create_capability_token(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            auth.access_structure.ap_to_access_rights(ap)?,
        )
    }
    pub fn refresh_capability(
        &self,
        auth: &mut CapabilityAuthority,
        cap_token: &mut AccessCapabilityToken,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        refresh_capability_token(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            cap_token,
            keep_old_secrets,
        )
    }
    pub fn recaps(
        &self,
        auth: &CapabilityAuthority,
        pk: &CapabilityAuthorityPublicKey,
        encapsulation: &XEnc,
    ) -> Result<(Secret<32>, XEnc), Error> {
        let (_ss, rights) = auth.decapsulate(encapsulation)?;
        pk.encapsulate(&mut *self.rng.lock().expect("Mutex lock failed!"), &rights)
    }
}

impl KemAc<SHARED_SECRET_LENGTH> for AccessControl {
    type EncapsulationKey = CapabilityAuthorityPublicKey;
    type DecapsulationKey = AccessCapabilityToken;
    type Encapsulation = XEnc;
    type Error = Error;

    fn encaps(
        &self,
        ek: &Self::EncapsulationKey,
        ap: &AccessPolicy,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, Self::Encapsulation), Self::Error> {
        ek.encapsulate(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            &ek.access_structure.ap_to_enc_rights(ap)?,
        )
    }

    fn decaps(
        &self,
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        dk.decapsulate(&mut *self.rng.lock().expect("Mutex lock failed!"), enc)
    }
}

impl<const KEY_LENGTH: usize, E: AE<KEY_LENGTH, Error = Error>> PkeAc<KEY_LENGTH, E>
    for AccessControl
{
    type EncryptionKey = CapabilityAuthorityPublicKey;
    type DecryptionKey = AccessCapabilityToken;
    type Ciphertext = (XEnc, Vec<u8>);
    type Error = Error;

    fn encrypt(
        &self,
        ek: &Self::EncryptionKey,
        ap: &AccessPolicy,
        ptx: &[u8],
        aad: &[u8],
    ) -> Result<Self::Ciphertext, Self::Error> {
        let (seed, enc) = self.encaps(ek, ap)?;

        let mut rng = self.rng.lock().expect("poisoned lock");
        let key = SymmetricKey::derive(&seed, b"ROOT-AUTHORIZED-KEY")?;
        E::encrypt(&mut *rng, &key, ptx, aad).map(|ctx| (enc, ctx))
    }

    fn decrypt(
        &self,
        usk: &Self::DecryptionKey,
        ctx: &Self::Ciphertext,
        aad: &[u8],
    ) -> Result<Option<Zeroizing<Vec<u8>>>, Self::Error> {
        self.decaps(usk, &ctx.0)?
            .map(|seed| {
                let key = SymmetricKey::derive(&seed, b"ROOT-AUTHORIZED-KEY")?;
                E::decrypt(&key, &ctx.1, aad)
            })
            .transpose()
    }
}
