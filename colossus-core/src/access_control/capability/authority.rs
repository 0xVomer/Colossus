use super::*;

#[derive(Debug, PartialEq)]
pub struct CapabilityAuthority {
    pub access_structure: AccessStructure,

    signing_key: Option<SymmetricKey<SIGNING_KEY_LENGTH>>,

    sk_access_rights: RevisionMap<Right, (bool, AccessRightSecretKey)>,
    capabilities: HashSet<AccessCapabilityId>,

    sk_trace: <ElGamal as Nike>::SecretKey,
    tracers: LinkedList<(<ElGamal as Nike>::SecretKey, <ElGamal as Nike>::PublicKey)>,
}

impl CapabilityAuthority {
    pub fn setup(
        tracing_level: usize,
        rng: &mut impl CryptoRngCore,
    ) -> Result<CapabilityAuthority, Error> {
        if tracing_level < MIN_TRACING_LEVEL {
            return Err(Error::OperationNotPermitted(format!(
                "tracing level cannot be lower than {MIN_TRACING_LEVEL}"
            )));
        }

        Ok(CapabilityAuthority {
            access_structure: AccessStructure::default(),
            capabilities: HashSet::new(),
            sk_trace: <ElGamal as Nike>::SecretKey::random(rng),
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
    pub fn rpk(&self) -> Result<CapabilityAuthorityPublicKey, Error> {
        let h = self.binding_point();
        Ok(CapabilityAuthorityPublicKey {
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
        cap_id: &AccessCapabilityId,
        access_rights: &RevisionVec<Right, AccessRightSecretKey>,
    ) -> Result<Option<KmacSignature>, Error> {
        if let Some(kmac_key) = &self.signing_key {
            let mut kmac = Kmac::v256(&**kmac_key, b"USK signature");
            for marker in cap_id.iter() {
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

    pub fn verify_capability(&self, cap_token: &AccessCapabilityToken) -> Result<(), Error> {
        let fresh_signature =
            self.sign_access_rights(&cap_token.id, &cap_token.sk_access_rights)?;
        if fresh_signature != cap_token.signature {
            Err(Error::KeyError("USK failed the integrity check".to_string()))
        } else {
            Ok(())
        }
    }

    pub(super) fn refresh_access_rights(
        auth: &CapabilityAuthority,
        access_rights: RevisionVec<Right, AccessRightSecretKey>,
    ) -> RevisionVec<Right, AccessRightSecretKey> {
        access_rights
            .into_iter()
            .filter_map(|(access_right, sk_access_right)| {
                auth.sk_access_rights.get(&access_right).and_then(|root_access_rights| {
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

            c_0 * &(&self.sk_trace / t_0)?
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

impl CapabilityAuthority {
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

    fn is_known(&self, cap_id: &AccessCapabilityId) -> bool {
        self.capabilities.contains(cap_id)
    }

    fn add_capability(&mut self, cap_id: AccessCapabilityId) {
        self.capabilities.insert(cap_id);
    }

    fn del_capability(&mut self, cap_id: &AccessCapabilityId) -> bool {
        self.capabilities.remove(cap_id)
    }

    #[must_use]
    pub(super) fn tpk(&self) -> TracingPublicKey {
        TracingPublicKey(self.tracers.iter().map(|(_, pi)| pi).cloned().collect())
    }

    pub(super) fn binding_point(&self) -> <ElGamal as Nike>::PublicKey {
        (&self.sk_trace).into()
    }

    fn generate_cap_id(
        &mut self,
        rng: &mut impl CryptoRngCore,
    ) -> Result<AccessCapabilityId, Error> {
        if let Some((last_tracer, _)) = self.tracers.back() {
            let mut markers = self
                .tracers
                .iter()
                .take(self.tracers.len() - 1)
                .map(|_| <ElGamal as Nike>::SecretKey::random(rng))
                .collect::<LinkedList<_>>();

            let last_marker = ((&self.sk_trace
                - &self
                    .tracers
                    .iter()
                    .zip(markers.iter())
                    .map(|((sk_i, _), a_i)| sk_i * a_i)
                    .fold(<ElGamal as Nike>::SecretKey::zero(), |acc, x_i| acc + x_i))
                / last_tracer)?;

            markers.push_back(last_marker);
            let id = AccessCapabilityId(markers);
            self.add_capability(id.clone());
            Ok(id)
        } else {
            Err(Error::KeyError("MSK has no tracer".to_string()))
        }
    }

    fn _validate_cap_id(&self, cap_id: &AccessCapabilityId) -> bool {
        self.sk_trace
            == cap_id
                .iter()
                .zip(self.tracers.iter())
                .map(|(identifier, (tracer, _))| identifier * tracer)
                .sum()
    }

    fn refresh_id(
        &mut self,
        rng: &mut impl CryptoRngCore,
        id: AccessCapabilityId,
    ) -> Result<AccessCapabilityId, Error> {
        if !self.is_known(&id) {
            Err(Error::Tracing("unknown user".to_string()))
        } else if id.tracing_level() != self.tracing_level() {
            let new_id = self.generate_cap_id(rng)?;
            self.add_capability(new_id.clone());
            self.del_capability(&id);
            Ok(new_id)
        } else {
            Ok(id)
        }
    }
}

impl Serializable for CapabilityAuthority {
    type Error = Error;

    fn length(&self) -> usize {
        self.sk_trace.length()
            + to_leb128_len(self.capabilities.len())
            + self.capabilities.iter().map(Serializable::length).sum::<usize>()
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
        let mut n = self.sk_trace.write(ser)?;

        n += ser.write_leb128_u64(self.tracers.len() as u64)?;
        for (sk, pk) in &self.tracers {
            n += ser.write(sk)?;
            n += ser.write(pk)?;
        }

        n = ser.write_leb128_u64(self.capabilities.len() as u64)?;
        for id in &self.capabilities {
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

        let n_capabilities = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut capabilities = HashSet::with_capacity(n_capabilities);
        for _ in 0..n_capabilities {
            let id = de.read()?;
            capabilities.insert(id);
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
            sk_trace: sk,
            capabilities,
            tracers,
            sk_access_rights: coordinate_keypairs,
            signing_key,
            access_structure,
        })
    }
}

#[derive(Debug, PartialEq)]
pub struct CapabilityAuthorityPublicKey {
    pub tpk: TracingPublicKey,
    pub pk_access_rights: HashMap<Right, AccessRightPublicKey>,
    pub access_structure: AccessStructure,
}

impl CapabilityAuthorityPublicKey {
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
        self.tpk.0.iter().map(|pi| pi * r).collect()
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

impl Serializable for CapabilityAuthorityPublicKey {
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

pub fn update_capability_authority(
    rng: &mut impl CryptoRngCore,
    auth: &mut CapabilityAuthority,
    rights: HashMap<Right, AttributeStatus>,
) -> Result<(), Error> {
    let mut secrets = take(&mut auth.sk_access_rights);
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
    auth.sk_access_rights = secrets;
    Ok(())
}

pub fn prune_capability_authority(auth: &mut CapabilityAuthority, coordinates: &HashSet<Right>) {
    for coordinate in coordinates {
        auth.sk_access_rights.keep(coordinate, 1);
    }
}

pub fn refresh_capability_authority(
    rng: &mut impl CryptoRngCore,
    auth: &mut CapabilityAuthority,
    rights: HashSet<Right>,
) -> Result<(), Error> {
    for r in rights {
        if auth.sk_access_rights.contains_key(&r) {
            auth.sk_access_rights.get_latest(&r).ok_or_else(|| {
                Error::OperationNotPermitted(format!("no current access right known for {r:#?}"))
            })?;
            auth.sk_access_rights.insert(r, (true, AccessRightSecretKey::random(rng)?));
        } else {
            return Err(Error::OperationNotPermitted("unkown access right".to_string()));
        }
    }
    Ok(())
}

pub fn refresh_capability_token(
    rng: &mut impl CryptoRngCore,
    auth: &mut CapabilityAuthority,
    cap_token: &mut AccessCapabilityToken,
    keep_old_rights: bool,
) -> Result<(), Error> {
    auth.verify_capability(cap_token)?;

    let cap_id = take(&mut cap_token.id);
    let new_id = auth.refresh_id(rng, cap_id)?;

    let cap_rights = take(&mut cap_token.sk_access_rights);

    let new_rights = if keep_old_rights {
        refresh_access_rights(auth, cap_rights)
    } else {
        auth.get_latest_access_right_sk(cap_rights.into_keys())
            .collect::<Result<RevisionVec<Right, AccessRightSecretKey>, Error>>()?
    };

    let signature = auth.sign_access_rights(&new_id, &new_rights)?;

    cap_token.id = new_id;
    cap_token.sk_access_rights = new_rights;
    cap_token.signature = signature;

    Ok(())
}

pub fn refresh_access_rights(
    auth: &CapabilityAuthority,
    access_rights: RevisionVec<Right, AccessRightSecretKey>,
) -> RevisionVec<Right, AccessRightSecretKey> {
    access_rights
        .into_iter()
        .filter_map(|(access_right, sk_access_right)| {
            auth.sk_access_rights.get(&access_right).and_then(|root_access_rights| {
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

pub fn create_capability_token(
    rng: &mut impl CryptoRngCore,
    auth: &mut CapabilityAuthority,
    coordinates: HashSet<Right>,
) -> Result<AccessCapabilityToken, Error> {
    let coordinate_keys = auth
        .get_latest_access_right_sk(coordinates.into_iter())
        .collect::<Result<RevisionVec<_, _>, Error>>()?;
    let id = auth.generate_cap_id(rng)?;
    let signature = auth.sign_access_rights(&id, &coordinate_keys)?;

    Ok(AccessCapabilityToken {
        id,
        ps: auth.tracers.iter().map(|(_, pi)| pi).cloned().collect(),
        sk_access_rights: coordinate_keys,
        signature,
    })
}
