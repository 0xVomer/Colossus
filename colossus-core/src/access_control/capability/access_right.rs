use super::*;

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
    pub(super) sk: <ElGamal as Nike>::SecretKey,
    pub(super) dk: <MlKem as Kem>::DecapsulationKey,
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

    pub fn session_keys(
        &self,
        pk: &<ElGamal as Nike>::PublicKey,
        enc: &<MlKem as Kem>::Encapsulation,
    ) -> Result<(<ElGamal as Nike>::SessionKey, <MlKem as Kem>::SessionKey), Error> {
        let k1 = ElGamal::session_key(&self.sk, pk)?;
        let k2 = MlKem::dec(&self.dk, enc)?;
        Ok((k1, k2))
    }
}
