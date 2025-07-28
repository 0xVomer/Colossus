use crate::{
    access_control::{
        RootAuthority, RootPublicKey, UserSecretKey,
        cryptography::{
            MIN_TRACING_LEVEL, SHARED_SECRET_LENGTH, XEnc,
            traits::{AE, KemAc, PkeAc},
        },
        root_authority::{prune, refresh_usk, rekey, update_root_authority, usk_keygen},
    },
    policy::{AccessPolicy, Error},
};
use cosmian_crypto_core::{CsRng, Secret, SymmetricKey, reexport::rand_core::SeedableRng};
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

    pub fn setup(&self) -> Result<(RootAuthority, RootPublicKey), Error> {
        let mut rng = self.rng.lock().expect("Mutex lock failed!");
        let mut auth = RootAuthority::setup(MIN_TRACING_LEVEL, &mut *rng)?;
        let rights = auth.access_structure.omega()?;
        update_root_authority(&mut *rng, &mut auth, rights)?;
        let rpk = auth.rpk()?;
        Ok((auth, rpk))
    }

    pub fn update_auth(&self, auth: &mut RootAuthority) -> Result<RootPublicKey, Error> {
        update_root_authority(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            auth.access_structure.omega()?,
        )?;
        auth.rpk()
    }
    pub fn rekey(
        &self,
        auth: &mut RootAuthority,
        ap: &AccessPolicy,
    ) -> Result<RootPublicKey, Error> {
        rekey(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            auth.access_structure.ap_to_usk_rights(ap)?,
        )?;
        auth.rpk()
    }

    pub fn prune_master_secret_key(
        &self,
        auth: &mut RootAuthority,
        ap: &AccessPolicy,
    ) -> Result<RootPublicKey, Error> {
        prune(auth, &auth.access_structure.ap_to_usk_rights(ap)?);
        auth.rpk()
    }

    pub fn grant_access_right_keys(
        &self,
        auth: &mut RootAuthority,
        ap: &AccessPolicy,
    ) -> Result<UserSecretKey, Error> {
        usk_keygen(
            &mut *self.rng.lock().expect("Mutex lock failed!"),
            auth,
            auth.access_structure.ap_to_usk_rights(ap)?,
        )
    }
    pub fn refresh_usk(
        &self,
        auth: &mut RootAuthority,
        usk: &mut UserSecretKey,
        keep_old_secrets: bool,
    ) -> Result<(), Error> {
        refresh_usk(&mut *self.rng.lock().expect("Mutex lock failed!"), auth, usk, keep_old_secrets)
    }
    pub fn recaps(
        &self,
        auth: &RootAuthority,
        pk: &RootPublicKey,
        encapsulation: &XEnc,
    ) -> Result<(Secret<32>, XEnc), Error> {
        let (_ss, rights) = auth.decapsulate(encapsulation)?;
        pk.encapsulate(&mut *self.rng.lock().expect("Mutex lock failed!"), &rights)
    }
}

impl KemAc<SHARED_SECRET_LENGTH> for AccessControl {
    type EncapsulationKey = RootPublicKey;
    type DecapsulationKey = UserSecretKey;
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
    type EncryptionKey = RootPublicKey;
    type DecryptionKey = UserSecretKey;
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
