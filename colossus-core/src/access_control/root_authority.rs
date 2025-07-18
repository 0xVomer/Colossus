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
use std::{
    collections::{HashMap, HashSet, LinkedList},
    mem::take,
};
use tiny_keccak::{Hasher, Kmac, Sha3};
use zeroize::Zeroize;

#[derive(Clone, Debug, PartialEq, Eq, Hash, Default)]
pub struct UserId(pub LinkedList<<ElGamal as Nike>::SecretKey>);

impl Serializable for UserId {
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

#[derive(Clone, Debug, PartialEq)]
pub struct AccessRightPublicKey {
    pub h: <ElGamal as Nike>::PublicKey,
    pub ek: <MlKem as Kem>::EncapsulationKey,
}

impl Serializable for AccessRightPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.h.length() + self.ek.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.h)?;
        n += ser.write(&self.ek)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let h = de.read()?;
        let ek = de.read()?;
        Ok(Self { h, ek })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct AccessRightSecretKey {
    sk: <ElGamal as Nike>::SecretKey,
    dk: <MlKem as Kem>::DecapsulationKey,
}

impl Serializable for AccessRightSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.sk.length() + self.dk.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.sk)?;
        n += ser.write(&self.dk)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let sk = de.read()?;
        let dk = de.read()?;
        Ok(Self { sk, dk })
    }
}

impl AccessRightSecretKey {
    pub(super) fn random(rng: &mut impl CryptoRngCore) -> Result<Self, Error> {
        let sk = <ElGamal as Nike>::SecretKey::random(rng);
        let (dk, _) = MlKem::keygen(rng)?;
        Ok(Self { sk, dk })
    }

    #[must_use]
    pub(super) fn cpk(&self, h: &<ElGamal as Nike>::PublicKey) -> AccessRightPublicKey {
        AccessRightPublicKey { h: h * &self.sk, ek: self.dk.ek() }
    }
}

#[derive(Debug, PartialEq, Eq, Default)]
pub struct TracingPublicKey(pub LinkedList<<ElGamal as Nike>::PublicKey>);

impl TracingPublicKey {
    pub(super) fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }
}

impl Serializable for TracingPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len()) + self.0.iter().map(Serializable::length).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for pk in self.0.iter() {
            n += pk.write(ser)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let n_pk = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_pk {
            let tracer = de.read()?;
            tracers.push_back(tracer);
        }
        Ok(Self(tracers))
    }
}

#[derive(Debug, PartialEq)]
pub struct RootAuthority {
    pub access_structure: AccessStructure,
    users: HashSet<UserId>,

    sk: <ElGamal as Nike>::SecretKey,
    signing_key: Option<SymmetricKey<SIGNING_KEY_LENGTH>>,
    tracers: LinkedList<(<ElGamal as Nike>::SecretKey, <ElGamal as Nike>::PublicKey)>,
    sk_access_rights: RevisionMap<Right, (bool, AccessRightSecretKey)>,
}

impl RootAuthority {
    pub fn setup(
        tracing_level: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<RootAuthority, Error> {
        if tracing_level < MIN_TRACING_LEVEL {
            return Err(Error::OperationNotPermitted(format!(
                "tracing level cannot be lower than {MIN_TRACING_LEVEL}"
            )));
        }

        Ok(RootAuthority {
            access_structure: AccessStructure::default(),
            users: HashSet::new(),
            sk: <ElGamal as Nike>::SecretKey::random(rng),
            sk_access_rights: RevisionMap::new(),
            signing_key: Some(SymmetricKey::<SIGNING_KEY_LENGTH>::new(rng)),
            tracers: (0..=tracing_level).map(|_| ElGamal::keygen(rng)).collect::<Result<_, _>>()?,
        })
    }

    pub fn count(&self) -> usize {
        self.sk_access_rights.len()
    }

    fn get_latest_access_right_sk<'a>(
        &'a self,
        rs: impl Iterator<Item = Right> + 'a,
    ) -> impl Iterator<Item = Result<(Right, AccessRightSecretKey), Error>> + 'a {
        rs.map(|r| {
            self.sk_access_rights
                .get_latest(&r)
                .ok_or(Error::KeyError(format!("MSK has no key for right {r:?}")))
                .cloned()
                .map(|(_, key)| (r, key))
        })
    }
    pub fn rpk(&self) -> Result<RootPublicKey, Error> {
        let h = self.binding_point();
        Ok(RootPublicKey {
            tpk: self.tpk(),
            pk_access_rights: self
                .sk_access_rights
                .iter()
                .filter_map(|(r, secrets)| {
                    secrets.front().and_then(|(is_activated, csk)| {
                        if *is_activated {
                            Some((r.clone(), csk.cpk(&h)))
                        } else {
                            None
                        }
                    })
                })
                .collect(),
            access_structure: self.access_structure.clone(),
        })
    }
    pub fn sign_access_rights(
        &self,
        user_id: &UserId,
        access_rights: &RevisionVec<Right, AccessRightSecretKey>,
    ) -> Result<Option<KmacSignature>, Error> {
        if let Some(kmac_key) = &self.signing_key {
            let mut kmac = Kmac::v256(&**kmac_key, b"USK signature");
            for marker in user_id.iter() {
                kmac.update(&marker.serialize()?)
            }
            for (access_right, sk_access_right) in access_rights.iter() {
                kmac.update(access_right);
                for subkey in sk_access_right.iter() {
                    kmac.update(&subkey.sk.serialize()?);
                    kmac.update(&subkey.dk.serialize()?);
                }
            }
            let mut res = [0; SIGNATURE_LENGTH];
            kmac.finalize(&mut res);
            Ok(Some(res))
        } else {
            Ok(None)
        }
    }

    pub fn verify_usk(&self, usk: &UserSecretKey) -> Result<(), Error> {
        let fresh_signature = self.sign_access_rights(&usk.id, &usk.sk_access_rights)?;
        if fresh_signature != usk.signature {
            Err(Error::KeyError("USK failed the integrity check".to_string()))
        } else {
            Ok(())
        }
    }

    pub fn decapsulate(
        &self,
        cap: &XEnc,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, HashSet<Right>), Error> {
        let A = {
            let c_0 = cap
                .c
                .first()
                .ok_or_else(|| Error::Kem("invalid encapsulation: C is empty".to_string()))?;
            let t_0 = self
                .tracers
                .front()
                .map(|(si, _)| si)
                .ok_or_else(|| Error::KeyError("root-auth has no tracer".to_string()))?;

            c_0 * &(&self.sk / t_0)?
        };

        let T = {
            let mut hasher = Sha3::v256();
            let mut secret = Secret::<SHARED_SECRET_LENGTH>::new();
            cap.c.iter().try_for_each(|ck| {
                hasher.update(&ck.serialize()?);
                Ok::<_, Error>(())
            })?;

            cap.encapsulations.0.iter().try_for_each(|(e, _)| {
                hasher.update(&e.serialize()?);
                Ok::<_, Error>(())
            })?;
            hasher.finalize(&mut *secret);
            secret
        };

        let U = {
            let mut secret = Secret::<SHARED_SECRET_LENGTH>::new();
            let mut hasher = Sha3::v256();
            hasher.update(&*T);
            cap.encapsulations.0.iter().for_each(|(_, F)| hasher.update(F));
            hasher.finalize(&mut *secret);
            secret
        };

        let mut enc_ss = None;
        let mut rights = HashSet::with_capacity(cap.count());
        let mut try_decaps = |right: &Right,
                              K1: &mut <ElGamal as Nike>::PublicKey,
                              K2: Option<Secret<SHARED_SECRET_LENGTH>>,
                              F| {
            let S_ij = xor_in_place(H_hash(K1, K2.as_ref(), &T)?, F);
            let (tag_ij, ss) = J_hash(&S_ij, &U);
            if cap.tag == tag_ij {
                // Fujisaki-Okamoto
                let r = G_hash(&S_ij)?;
                let c_ij = self.set_traps(&r);
                if cap.c == c_ij {
                    K1.zeroize();
                    enc_ss = Some(ss);
                    rights.insert(right.clone());
                }
            }
            Ok::<_, Error>(())
        };

        for (E, F) in cap.encapsulations.0.iter() {
            for (right, secret_set) in self.sk_access_rights.iter() {
                for (is_activated, secret) in secret_set {
                    if *is_activated {
                        let mut K1 = ElGamal::session_key(&secret.sk, &A)?;
                        let K2 = MlKem::dec(&secret.dk, &E)?;
                        try_decaps(right, &mut K1, Some(K2), &F)?;
                    }
                }
            }
        }

        enc_ss
            .map(|ss| (ss, rights))
            .ok_or_else(|| Error::Kem("could not open the encapsulation".to_string()))
    }
}

impl RootAuthority {
    pub(super) fn tracing_level(&self) -> usize {
        self.tracers.len() - 1
    }

    fn set_traps(&self, r: &<ElGamal as Nike>::SecretKey) -> Vec<<ElGamal as Nike>::PublicKey> {
        self.tracers.iter().map(|(_, Pi)| Pi * r).collect()
    }

    fn _increase_tracing(&mut self, rng: &mut impl CryptoRngCore) -> Result<(), Error> {
        self.tracers.push_back(ElGamal::keygen(rng)?);
        Ok(())
    }

    fn _decrease_tracing(
        &mut self,
    ) -> Result<(<ElGamal as Nike>::SecretKey, <ElGamal as Nike>::PublicKey), Error> {
        if self.tracing_level() == MIN_TRACING_LEVEL {
            Err(Error::OperationNotPermitted(format!(
                "tracing level cannot be lower than {MIN_TRACING_LEVEL}"
            )))
        } else {
            Ok(self
                .tracers
                .pop_front()
                .expect("previous check ensures the queue is never empty"))
        }
    }

    pub fn _set_tracing_level(
        &mut self,
        rng: &mut impl CryptoRngCore,
        target_level: usize,
    ) -> Result<(), Error> {
        if target_level < self.tracing_level() {
            for _ in target_level..self.tracing_level() {
                self._decrease_tracing()?;
            }
        } else {
            for _ in self.tracing_level()..target_level {
                self._increase_tracing(rng)?;
            }
        }
        Ok(())
    }

    fn is_known(&self, id: &UserId) -> bool {
        self.users.contains(id)
    }

    fn add_user(&mut self, id: UserId) {
        self.users.insert(id);
    }

    fn del_user(&mut self, id: &UserId) -> bool {
        self.users.remove(id)
    }

    #[must_use]
    pub(super) fn tpk(&self) -> TracingPublicKey {
        TracingPublicKey(self.tracers.iter().map(|(_, Pi)| Pi).cloned().collect())
    }

    pub(super) fn binding_point(&self) -> <ElGamal as Nike>::PublicKey {
        (&self.sk).into()
    }

    fn generate_user_id(&mut self, rng: &mut impl CryptoRngCore) -> Result<UserId, Error> {
        if let Some((last_tracer, _)) = self.tracers.back() {
            // Generate all but the last marker at random.
            let mut markers = self
                .tracers
                .iter()
                .take(self.tracers.len() - 1)
                .map(|_| <ElGamal as Nike>::SecretKey::random(rng))
                .collect::<LinkedList<_>>();

            let last_marker = ((&self.sk
                - &self
                    .tracers
                    .iter()
                    .zip(markers.iter())
                    .map(|((sk_i, _), a_i)| sk_i * a_i)
                    .fold(<ElGamal as Nike>::SecretKey::zero(), |acc, x_i| acc + x_i))
                / last_tracer)?;

            markers.push_back(last_marker);
            let id = UserId(markers);
            self.add_user(id.clone());
            Ok(id)
        } else {
            Err(Error::KeyError("MSK has no tracer".to_string()))
        }
    }

    fn _validate_user_id(&self, id: &UserId) -> bool {
        self.sk
            == id
                .iter()
                .zip(self.tracers.iter())
                .map(|(identifier, (tracer, _))| identifier * tracer)
                .sum()
    }

    fn refresh_id(&mut self, rng: &mut impl CryptoRngCore, id: UserId) -> Result<UserId, Error> {
        if !self.is_known(&id) {
            Err(Error::Tracing("unknown user".to_string()))
        } else if id.tracing_level() != self.tracing_level() {
            let new_id = self.generate_user_id(rng)?;
            self.add_user(new_id.clone());
            self.del_user(&id);
            Ok(new_id)
        } else {
            Ok(id)
        }
    }
}

impl Serializable for RootAuthority {
    type Error = Error;

    fn length(&self) -> usize {
        self.sk.length()
            + to_leb128_len(self.users.len())
            + self.users.iter().map(Serializable::length).sum::<usize>()
            + to_leb128_len(self.tracers.len())
            + self.tracers.iter().map(|(sk, pk)| sk.length() + pk.length()).sum::<usize>()
            + to_leb128_len(self.sk_access_rights.len())
            + self
                .sk_access_rights
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(|(_, k)| 1 + k.length()).sum::<usize>()
                })
                .sum::<usize>()
            + self.signing_key.as_ref().map_or_else(|| 0, |key| key.len())
            + self.access_structure.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = self.sk.write(ser)?;

        n += ser.write_leb128_u64(self.tracers.len() as u64)?;
        for (sk, pk) in &self.tracers {
            n += ser.write(sk)?;
            n += ser.write(pk)?;
        }

        n = ser.write_leb128_u64(self.users.len() as u64)?;
        for id in &self.users {
            n += ser.write(id)?;
        }

        n += ser.write_leb128_u64(self.sk_access_rights.len() as u64)?;
        for (coordinate, chain) in &self.sk_access_rights.map {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(chain.len() as u64)?;
            for (is_activated, sk) in chain {
                n += ser.write_leb128_u64((*is_activated).into())?;
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac_key) = &self.signing_key {
            n += ser.write_array(&**kmac_key)?;
        }
        n += ser.write(&self.access_structure)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let sk = de.read()?;

        let n_tracers = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut tracers = LinkedList::new();
        for _ in 0..n_tracers {
            let sk = de.read()?;
            let pk = de.read()?;
            tracers.push_back((sk, pk));
        }

        let n_users = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut users = HashSet::with_capacity(n_users);
        for _ in 0..n_users {
            let id = de.read()?;
            users.insert(id);
        }

        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut coordinate_keypairs = RevisionMap::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let chain = (0..n_keys)
                .map(|_| -> Result<_, Error> {
                    let is_activated = de.read_leb128_u64()? == 1;
                    let sk = de.read::<AccessRightSecretKey>()?;
                    Ok((is_activated, sk))
                })
                .collect::<Result<LinkedList<_>, _>>()?;
            coordinate_keypairs.map.insert(coordinate, chain);
        }

        let signing_key = if de.value().len() < SIGNING_KEY_LENGTH {
            None
        } else {
            Some(SymmetricKey::try_from_bytes(de.read_array::<SIGNING_KEY_LENGTH>()?)?)
        };

        let access_structure = de.read()?;

        Ok(Self {
            sk,
            users,
            tracers,
            sk_access_rights: coordinate_keypairs,
            signing_key,
            access_structure,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct RootPublicKey {
    pub tpk: TracingPublicKey,
    pub pk_access_rights: HashMap<Right, AccessRightPublicKey>,
    pub access_structure: AccessStructure,
}

impl RootPublicKey {
    #[inline(always)]
    pub fn tracing_level(&self) -> usize {
        self.tpk.tracing_level()
    }

    pub fn count(&self) -> usize {
        self.pk_access_rights.len()
    }

    pub(crate) fn set_traps(
        &self,
        r: &<ElGamal as Nike>::SecretKey,
    ) -> Vec<<ElGamal as Nike>::PublicKey> {
        self.tpk.0.iter().map(|Pi| Pi * r).collect()
    }

    pub fn select_access_right_keys(
        &self,
        targets: &HashSet<Right>,
    ) -> Result<Vec<&AccessRightPublicKey>, Error> {
        let subkeys = targets
            .iter()
            .map(|r| {
                let subkey = self
                    .pk_access_rights
                    .get(r)
                    .ok_or_else(|| Error::KeyError(format!("no public key for right '{r:#?}'")))?;
                Ok(subkey)
            })
            .collect::<Result<_, Error>>()?;

        Ok(subkeys)
    }

    pub fn encapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
        encryption_set: &HashSet<Right>,
    ) -> Result<(Secret<SHARED_SECRET_LENGTH>, XEnc), Error> {
        let mut access_rights = self.select_access_right_keys(encryption_set)?;

        shuffle(&mut access_rights, rng);

        let rng_secret = Secret::random(rng);
        let r = G_hash(&rng_secret)?;
        let c = self.set_traps(&r);

        let rights = access_rights
            .iter()
            .map(|subkey| {
                let K1 = ElGamal::session_key(&r, &subkey.h)?;
                let (K2, E) = MlKem::enc(&subkey.ek, rng)?;
                Ok((K1, K2, E))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let T = {
            let mut hasher = Sha3::v256();
            let mut secret = Secret::new();
            c.iter().try_for_each(|ck| {
                hasher.update(&ck.serialize()?);
                Ok::<_, Error>(())
            })?;
            rights.iter().try_for_each(|(_, _, E)| {
                hasher.update(&E.serialize()?);
                Ok::<_, Error>(())
            })?;
            hasher.finalize(&mut *secret);
            secret
        };

        let encs = rights
            .into_iter()
            .map(|(mut K1, K2, E)| -> Result<_, _> {
                let F = xor_2(&rng_secret, &*H_hash(&K1, Some(&K2), &T)?);
                K1.zeroize();
                Ok((E, F))
            })
            .collect::<Result<Vec<_>, Error>>()?;

        let U = {
            let mut U = Secret::new();
            let mut hasher = Sha3::v256();
            hasher.update(&*T);
            encs.iter().for_each(|(_, F)| hasher.update(F));
            hasher.finalize(&mut *U);
            U
        };

        let (tag, ss) = J_hash(&rng_secret, &U);

        Ok((
            ss,
            XEnc {
                tag,
                c,
                encapsulations: Encapsulations(encs),
            },
        ))
    }
}

impl Serializable for RootPublicKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.tpk.length()
            + to_leb128_len(self.pk_access_rights.len())
            + self
                .pk_access_rights
                .iter()
                .map(|(access_right, pk)| access_right.length() + pk.length())
                .sum::<usize>()
            + self.access_structure.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.tpk)?;
        n += ser.write_leb128_u64(self.pk_access_rights.len() as u64)?;
        for (access_right, pk) in &self.pk_access_rights {
            n += ser.write(access_right)?;
            n += ser.write(pk)?;
        }
        n += ser.write(&self.access_structure)?;

        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tpk = de.read::<TracingPublicKey>()?;
        let n_rights = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut access_rights = HashMap::with_capacity(n_rights);
        for _ in 0..n_rights {
            let acess_right = de.read::<Right>()?;
            let pk = de.read::<AccessRightPublicKey>()?;
            access_rights.insert(acess_right, pk);
        }
        let access_structure = de.read::<AccessStructure>()?;
        Ok(Self {
            tpk,
            pk_access_rights: access_rights,
            access_structure,
        })
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct UserSecretKey {
    id: UserId,
    ps: Vec<<ElGamal as Nike>::PublicKey>,
    sk_access_rights: RevisionVec<Right, AccessRightSecretKey>,
    signature: Option<KmacSignature>,
}

impl UserSecretKey {
    pub(crate) fn tracing_level(&self) -> usize {
        self.id.tracing_level()
    }

    pub(crate) fn count(&self) -> usize {
        self.sk_access_rights.len()
    }

    pub(crate) fn set_traps(
        &self,
        r: &<ElGamal as Nike>::SecretKey,
    ) -> Vec<<ElGamal as Nike>::PublicKey> {
        self.ps.iter().map(|Pi| Pi * r).collect()
    }

    fn public_key(
        &self,
        traps: &Vec<<ElGamal as Nike>::PublicKey>,
    ) -> <ElGamal as Nike>::PublicKey {
        self.id.iter().zip(traps.iter()).map(|(marker, trap)| trap * marker).sum()
    }

    pub(crate) fn decapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
        cap: &XEnc,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        let pk = self.public_key(&cap.c);

        let T = {
            let mut hasher = Sha3::v256();
            let mut secret = Secret::<SHARED_SECRET_LENGTH>::new();
            cap.c.iter().try_for_each(|ck| {
                hasher.update(&ck.serialize()?);
                Ok::<_, Error>(())
            })?;
            cap.encapsulations.0.iter().try_for_each(|(E, _)| {
                hasher.update(&E.serialize()?);
                Ok::<_, Error>(())
            })?;
            hasher.finalize(&mut *secret);
            secret
        };

        let U = {
            let mut secret = Secret::<SHARED_SECRET_LENGTH>::new();
            let mut hasher = Sha3::v256();
            hasher.update(&*T);
            cap.encapsulations.0.iter().for_each(|(_, F)| hasher.update(F));
            hasher.finalize(&mut *secret);
            secret
        };

        let mut encs = cap.encapsulations.0.iter().collect::<Vec<_>>();
        shuffle(&mut encs, rng);

        for mut revision in self.sk_access_rights.revisions() {
            shuffle(&mut revision, rng);
            for (E, F) in &encs {
                for (_, secret) in &revision {
                    let mut K1 = ElGamal::session_key(&secret.sk, &pk)?;
                    let K2 = MlKem::dec(&secret.dk, E)?;
                    let S_ij = xor_in_place(H_hash(&K1, Some(&K2), &T)?, F);
                    let (tag_ij, ss) = J_hash(&S_ij, &U);
                    if &cap.tag == &tag_ij {
                        // Fujisaki-Okamoto
                        let r = G_hash(&S_ij)?;
                        let c_ij = self.set_traps(&r);
                        if cap.c == c_ij {
                            K1.zeroize();
                            return Ok(Some(ss));
                        }
                    }
                }
            }
        }
        Ok(None)
    }
}

impl Serializable for UserSecretKey {
    type Error = Error;

    fn length(&self) -> usize {
        self.id.length()
            + to_leb128_len(self.ps.len())
            + self.ps.iter().map(|p| p.length()).sum::<usize>()
            + to_leb128_len(self.sk_access_rights.len())
            + self
                .sk_access_rights
                .iter()
                .map(|(coordinate, chain)| {
                    coordinate.length()
                        + to_leb128_len(chain.len())
                        + chain.iter().map(|sk| sk.length()).sum::<usize>()
                })
                .sum::<usize>()
            + self.signature.as_ref().map_or_else(|| 0, |kmac| kmac.len())
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write(&self.id)?;

        n += ser.write_leb128_u64(self.ps.len() as u64)?;
        for p in &self.ps {
            n += ser.write(p)?;
        }

        n += ser.write_leb128_u64(self.sk_access_rights.len() as u64)?;
        for (coordinate, chain) in self.sk_access_rights.iter() {
            n += ser.write(coordinate)?;
            n += ser.write_leb128_u64(chain.len() as u64)?;
            for sk in chain {
                n += ser.write(sk)?;
            }
        }
        if let Some(kmac) = &self.signature {
            n += ser.write_array(kmac)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let id = de.read::<UserId>()?;

        let n_ps = usize::try_from(de.read_leb128_u64()?)?;

        let mut ps = Vec::with_capacity(n_ps);
        for _ in 0..n_ps {
            let p = de.read()?;
            ps.push(p);
        }

        let n_coordinates = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut access_right_keys = RevisionVec::with_capacity(n_coordinates);
        for _ in 0..n_coordinates {
            let coordinate = de.read()?;
            let n_keys = <usize>::try_from(de.read_leb128_u64()?)?;
            let new_chain = (0..n_keys)
                .map(|_| de.read::<AccessRightSecretKey>())
                .collect::<Result<_, _>>()?;
            access_right_keys.insert_new_chain(coordinate, new_chain);
        }

        let msk_signature = if de.value().len() < SIGNATURE_LENGTH {
            None
        } else {
            Some(de.read_array::<SIGNATURE_LENGTH>()?)
        };

        Ok(Self {
            id,
            ps,
            sk_access_rights: access_right_keys,
            signature: msk_signature,
        })
    }
}

pub fn usk_keygen(
    rng: &mut impl CryptoRngCore,
    auth: &mut RootAuthority,
    coordinates: HashSet<Right>,
) -> Result<UserSecretKey, Error> {
    // Extract keys first to avoid unnecessary computation in case those cannot be found.
    let coordinate_keys = auth
        .get_latest_access_right_sk(coordinates.into_iter())
        .collect::<Result<RevisionVec<_, _>, Error>>()?;
    let id = auth.generate_user_id(rng)?;
    let signature = auth.sign_access_rights(&id, &coordinate_keys)?;

    Ok(UserSecretKey {
        id,
        ps: auth.tracers.iter().map(|(_, Pi)| Pi).cloned().collect(),
        sk_access_rights: coordinate_keys,
        signature,
    })
}

pub fn update_root_authority(
    rng: &mut impl CryptoRngCore,
    root: &mut RootAuthority,
    rights: HashMap<Right, AttributeStatus>,
) -> Result<(), Error> {
    let mut secrets = take(&mut root.sk_access_rights);
    secrets.retain(|r| rights.contains_key(r));

    for (r, status) in rights {
        if let Some((is_activated, _)) = secrets.get_latest_mut(&r) {
            *is_activated = AttributeStatus::EncryptDecrypt == status;
        } else {
            if AttributeStatus::DecryptOnly == status {
                return Err(Error::OperationNotPermitted(
                    "cannot add decrypt only secret".to_string(),
                ));
            }
            let secret = AccessRightSecretKey::random(rng)?;
            secrets.insert(r, (true, secret));
        }
    }
    root.sk_access_rights = secrets;
    Ok(())
}

pub fn prune(root: &mut RootAuthority, coordinates: &HashSet<Right>) {
    for coordinate in coordinates {
        root.sk_access_rights.keep(coordinate, 1);
    }
}

pub fn rekey(
    rng: &mut impl CryptoRngCore,
    root: &mut RootAuthority,
    rights: HashSet<Right>,
) -> Result<(), Error> {
    for r in rights {
        if root.sk_access_rights.contains_key(&r) {
            root.sk_access_rights.get_latest(&r).ok_or_else(|| {
                Error::OperationNotPermitted(format!("no current access right known for {r:#?}"))
            })?;
            root.sk_access_rights.insert(r, (true, AccessRightSecretKey::random(rng)?));
        } else {
            return Err(Error::OperationNotPermitted("unkown access right".to_string()));
        }
    }
    Ok(())
}

fn refresh_access_rights(
    root: &RootAuthority,
    access_rights: RevisionVec<Right, AccessRightSecretKey>,
) -> RevisionVec<Right, AccessRightSecretKey> {
    access_rights
        .into_iter()
        .filter_map(|(access_right, sk_access_right)| {
            root.sk_access_rights.get(&access_right).and_then(|root_access_rights| {
                let mut updated_chain = LinkedList::new();
                let mut sk_root = root_access_rights.iter();
                let mut sk_usk = sk_access_right.into_iter();
                let first_secret = sk_usk.next()?;

                for (_, root_secret) in sk_root.by_ref() {
                    if root_secret == &first_secret {
                        break;
                    }
                    updated_chain.push_back(root_secret.clone());
                }
                updated_chain.push_back(first_secret);
                for usk_access_right in sk_usk {
                    if let Some((_, root_secret)) = sk_root.next() {
                        if root_secret == &usk_access_right {
                            updated_chain.push_back(root_secret.clone());
                            continue;
                        }
                    }
                    break;
                }
                Some((access_right, updated_chain))
            })
        })
        .collect::<RevisionVec<_, _>>()
}

pub fn refresh_usk(
    rng: &mut impl CryptoRngCore,
    root: &mut RootAuthority,
    usk: &mut UserSecretKey,
    keep_old_rights: bool,
) -> Result<(), Error> {
    root.verify_usk(usk)?;

    let usk_id = take(&mut usk.id);
    let new_id = root.refresh_id(rng, usk_id)?;

    let usk_rights = take(&mut usk.sk_access_rights);
    let new_rights = if keep_old_rights {
        refresh_access_rights(root, usk_rights)
    } else {
        root.get_latest_access_right_sk(usk_rights.into_keys())
            .collect::<Result<RevisionVec<Right, AccessRightSecretKey>, Error>>()?
    };

    let signature = root.sign_access_rights(&new_id, &new_rights)?;

    usk.id = new_id;
    usk.sk_access_rights = new_rights;
    usk.signature = signature;

    Ok(())
}

impl UserId {
    /// Returns the tracing level of the USK.
    pub(crate) fn tracing_level(&self) -> usize {
        self.0.len() - 1
    }

    pub(crate) fn iter(&self) -> impl Iterator<Item = &<ElGamal as Nike>::SecretKey> {
        self.0.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        access_control::{Root, cryptography::traits::KemAc, test_utils::gen_auth},
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

            let mut auth = RootAuthority::setup(MIN_TRACING_LEVEL + 2, &mut rng).unwrap();
            update_root_authority(&mut rng, &mut auth, universe.clone()).unwrap();
            let rpk = auth.rpk().unwrap();
            let usk = usk_keygen(&mut rng, &mut auth, user_set).unwrap();
            let (_, enc) = rpk.encapsulate(&mut rng, &target_set).unwrap();

            test_serialization(&auth).unwrap();
            test_serialization(&rpk).unwrap();
            test_serialization(&usk).unwrap();
            test_serialization(&enc).unwrap();

            rekey(&mut rng, &mut auth, universe.keys().cloned().collect()).unwrap();
            test_serialization(&auth).unwrap();
        }

        {
            let api = Root::default();
            let (mut msk, mpk) = gen_auth(&api, false).unwrap();
            let usk = api
                .generate_user_secret_key(&mut msk, &AccessPolicy::parse("SEC::TOP").unwrap())
                .unwrap();
            let (_, enc) = api.encaps(&mpk, &AccessPolicy::parse("DPT::MKG").unwrap()).unwrap();

            test_serialization(&msk).unwrap();
            test_serialization(&mpk).unwrap();
            test_serialization(&usk).unwrap();
            test_serialization(&enc).unwrap();
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{
        access_control::{
            Root,
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

        let mut auth = RootAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_root_authority(
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
            let usk =
                usk_keygen(&mut rng, &mut auth, HashSet::from_iter([target_coordinate.clone()]))
                    .unwrap();
            assert_eq!(usk.count(), 1);
            assert_eq!(Some(&key), usk.decapsulate(&mut rng, &enc).unwrap().as_ref());
        }

        let usk = usk_keygen(&mut rng, &mut auth, HashSet::from_iter([other_coordinate.clone()]))
            .unwrap();
        assert_eq!(usk.count(), 1);
        assert_eq!(None, usk.decapsulate(&mut rng, &enc).unwrap().as_ref());
    }

    #[test]
    fn test_update() {
        let mut rng = CsRng::from_entropy();

        let mut auth = RootAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        assert_eq!(auth.tracing_level(), MIN_TRACING_LEVEL);
        assert_eq!(auth.count(), 0);

        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.tpk.tracing_level(), MIN_TRACING_LEVEL);
        assert_eq!(rpk.count(), 0);

        let mut coordinates = (0..30)
            .map(|_| (Right::random(&mut rng), AttributeStatus::EncryptDecrypt))
            .collect::<HashMap<_, _>>();
        update_root_authority(&mut rng, &mut auth, coordinates.clone()).unwrap();
        assert_eq!(auth.count(), 30);

        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.count(), 30);

        coordinates.iter_mut().enumerate().for_each(|(i, (_, status))| {
            if i % 2 == 0 {
                *status = AttributeStatus::DecryptOnly;
            }
        });
        update_root_authority(&mut rng, &mut auth, coordinates.clone()).unwrap();
        assert_eq!(auth.count(), 30);
        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.count(), 15);

        let coordinates = coordinates.into_iter().take(10).collect::<HashMap<_, _>>();
        update_root_authority(&mut rng, &mut auth, coordinates).unwrap();
        assert_eq!(auth.count(), 10);
        let rpk = auth.rpk().unwrap();
        assert_eq!(rpk.count(), 5);
    }

    #[test]
    fn test_rekey() {
        let mut rng = CsRng::from_entropy();
        let coordinate_1 = Right::random(&mut rng);
        let coordinate_2 = Right::random(&mut rng);
        let subspace_1 = HashSet::from_iter([coordinate_1.clone()]);
        let subspace_2 = HashSet::from_iter([coordinate_2.clone()]);
        let universe = HashSet::from_iter([coordinate_1.clone(), coordinate_2.clone()]);

        let mut auth = RootAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_root_authority(
            &mut rng,
            &mut auth,
            HashMap::from_iter([
                (coordinate_1.clone(), AttributeStatus::EncryptDecrypt),
                (coordinate_2.clone(), AttributeStatus::EncryptDecrypt),
            ]),
        )
        .unwrap();
        let rpk = auth.rpk().unwrap();
        let mut usk_1 = usk_keygen(&mut rng, &mut auth, subspace_1.clone()).unwrap();
        let mut usk_2 = usk_keygen(&mut rng, &mut auth, subspace_2.clone()).unwrap();

        let (old_key_1, old_enc_1) = rpk.encapsulate(&mut rng, &subspace_1).unwrap();
        let (old_key_2, old_enc_2) = rpk.encapsulate(&mut rng, &subspace_2).unwrap();

        // Old USK can open encapsulations associated with their coordinate.
        assert_eq!(Some(&old_key_1), usk_1.decapsulate(&mut rng, &old_enc_1).unwrap().as_ref());
        assert_eq!(None, usk_1.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(Some(old_key_2), usk_2.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(None, usk_2.decapsulate(&mut rng, &old_enc_1).unwrap());

        rekey(&mut rng, &mut auth, universe).unwrap();
        let rpk = auth.rpk().unwrap();

        let (new_key_1, new_enc_1) = rpk.encapsulate(&mut rng, &subspace_1).unwrap();
        let (new_key_2, new_enc_2) = rpk.encapsulate(&mut rng, &subspace_2).unwrap();

        assert_eq!(None, usk_1.decapsulate(&mut rng, &new_enc_1).unwrap());
        assert_eq!(None, usk_1.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(None, usk_2.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(None, usk_2.decapsulate(&mut rng, &new_enc_1).unwrap());

        refresh_usk(&mut rng, &mut auth, &mut usk_1, true).unwrap();
        refresh_usk(&mut rng, &mut auth, &mut usk_2, false).unwrap();

        assert_eq!(Some(new_key_1), usk_1.decapsulate(&mut rng, &new_enc_1).unwrap());
        assert_eq!(None, usk_1.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(Some(new_key_2), usk_2.decapsulate(&mut rng, &new_enc_2).unwrap());
        assert_eq!(None, usk_2.decapsulate(&mut rng, &new_enc_1).unwrap());

        assert_eq!(Some(old_key_1), usk_1.decapsulate(&mut rng, &old_enc_1).unwrap());
        assert_eq!(None, usk_1.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(None, usk_2.decapsulate(&mut rng, &old_enc_2).unwrap());
        assert_eq!(None, usk_2.decapsulate(&mut rng, &old_enc_1).unwrap());
    }

    #[test]
    fn test_integrity_check() {
        let mut rng = CsRng::from_entropy();
        let coordinate_1 = Right::random(&mut rng);
        let coordinate_2 = Right::random(&mut rng);
        let subspace_1 = HashSet::from_iter([coordinate_1.clone()]);
        let subspace_2 = HashSet::from_iter([coordinate_2.clone()]);

        let mut auth = RootAuthority::setup(MIN_TRACING_LEVEL, &mut rng).unwrap();
        update_root_authority(
            &mut rng,
            &mut auth,
            HashMap::from_iter([
                (coordinate_1.clone(), AttributeStatus::EncryptDecrypt),
                (coordinate_2.clone(), AttributeStatus::EncryptDecrypt),
            ]),
        )
        .unwrap();
        let usk_1 = usk_keygen(&mut rng, &mut auth, subspace_1.clone()).unwrap();
        let usk_2 = usk_keygen(&mut rng, &mut auth, subspace_2.clone()).unwrap();

        let mut old_forged_usk = usk_1.clone();
        for (key, chain) in usk_2.sk_access_rights.iter() {
            old_forged_usk.sk_access_rights.insert_new_chain(key.clone(), chain.clone());
        }
        assert_eq!(
            old_forged_usk.sk_access_rights.count_elements(),
            usk_1.sk_access_rights.count_elements() + usk_2.sk_access_rights.count_elements()
        );

        let mut new_forged_usk = old_forged_usk.clone();
        assert!(refresh_usk(&mut rng, &mut auth, &mut new_forged_usk, true).is_err());
        assert_eq!(new_forged_usk, old_forged_usk);
    }

    #[test]
    fn test_reencrypt_with_auth() {
        let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
        let cc = Root::default();

        let mut rng = CsRng::from_entropy();

        let (mut auth, _) = gen_auth(&cc, false).unwrap();
        let rpk = cc.update_auth(&mut auth).expect("cannot update master keys");
        let mut usk = cc.generate_user_secret_key(&mut auth, &ap).expect("cannot generate usk");

        let (old_key, old_enc) = cc.encaps(&rpk, &ap).unwrap();
        assert_eq!(Some(&old_key), usk.decapsulate(&mut rng, &old_enc).unwrap().as_ref());

        cc.rekey(&mut auth, &ap).unwrap();
        let new_rpk = auth.rpk().unwrap();
        let (new_key, new_enc) = cc.recaps(&auth, &new_rpk, &old_enc).unwrap();
        cc.refresh_usk(&mut auth, &mut usk, true).unwrap();
        assert_eq!(Some(new_key), usk.decapsulate(&mut rng, &new_enc).unwrap());
        assert_ne!(Some(old_key), usk.decapsulate(&mut rng, &new_enc).unwrap());
    }

    #[test]
    fn test_root_kem() {
        let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
        let api = Root::default();
        let (mut auth, _rpk) = gen_auth(&api, false).unwrap();
        let rpk = api.update_auth(&mut auth).expect("cannot update master keys");
        let usk = api.generate_user_secret_key(&mut auth, &ap).expect("cannot generate usk");
        let (secret, enc) = api.encaps(&rpk, &ap).unwrap();
        let res = api.decaps(&usk, &enc).unwrap();
        assert_eq!(secret, res.unwrap());
    }

    #[test]
    fn test_root_pke() {
        let ap = AccessPolicy::parse("DPT::FIN && SEC::TOP").unwrap();
        let api = Root::default();
        let (mut auth, rpk) = gen_auth(&api, false).unwrap();

        let ptx = "testing encryption/decryption".as_bytes();
        let aad = "COLOSSUS-ROOT".as_bytes();

        let ctx = PkeAc::<{ XChaCha20Poly1305::KEY_LENGTH }, XChaCha20Poly1305>::encrypt(
            &api, &rpk, &ap, ptx, aad,
        )
        .expect("cannot encrypt!");
        let usk = api.generate_user_secret_key(&mut auth, &ap).expect("cannot generate usk");
        let ptx1 = PkeAc::<{ XChaCha20Poly1305::KEY_LENGTH }, XChaCha20Poly1305>::decrypt(
            &api, &usk, &ctx, aad,
        )
        .expect("cannot decrypt the ciphertext");
        assert_eq!(ptx, &*ptx1.unwrap());
    }
}
