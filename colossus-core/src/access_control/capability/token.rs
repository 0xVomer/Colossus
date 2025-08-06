use super::*;

#[derive(Clone, Debug, PartialEq)]
pub struct AccessCapabilityToken {
    pub id: AccessCapabilityId,
    pub ps: Vec<<ElGamal as Nike>::PublicKey>,
    pub(super) sk_access_rights: RevisionVec<Right, AccessRightSecretKey>,
    pub signature: Option<KmacSignature>,
}

impl AccessCapabilityToken {
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

    fn tk(&self, traps: &Vec<<ElGamal as Nike>::PublicKey>) -> <ElGamal as Nike>::PublicKey {
        self.id.iter().zip(traps.iter()).map(|(marker, trap)| trap * marker).sum()
    }

    pub(crate) fn decapsulate(
        &self,
        rng: &mut impl CryptoRngCore,
        cap: &XEnc,
    ) -> Result<Option<Secret<SHARED_SECRET_LENGTH>>, Error> {
        let tk = self.tk(&cap.c);

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
                    let (mut K1, K2) = secret.session_keys(&tk, E)?;
                    let S_ij = xor_in_place(H_hash(&K1, Some(&K2), &T)?, F);
                    let (tag_ij, ss) = J_hash(&S_ij, &U);
                    if &cap.tag == &tag_ij {
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

impl Serializable for AccessCapabilityToken {
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
        let id = de.read::<AccessCapabilityId>()?;

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
