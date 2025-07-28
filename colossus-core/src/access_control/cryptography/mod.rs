pub mod ae;
mod mlkem;
mod nike;
pub mod traits;

use crate::policy::Error;
use cosmian_crypto_core::{
    Secret,
    bytes_ser_de::{Deserializer, Serializable, Serializer, to_leb128_len},
    reexport::rand_core::RngCore,
};
pub use mlkem::MlKem512 as MlKem;
pub use nike::R25519 as ElGamal;
use tiny_keccak::{Hasher, Sha3};

pub const SHARED_SECRET_LENGTH: usize = 32;

pub const SIGNING_KEY_LENGTH: usize = 16;

pub const SIGNATURE_LENGTH: usize = 32;

pub type KmacSignature = [u8; SIGNATURE_LENGTH];

pub const TAG_LENGTH: usize = 16;

pub type Tag = [u8; TAG_LENGTH];

pub const MIN_TRACING_LEVEL: usize = 1;

pub fn xor_2<const LENGTH: usize>(lhs: &[u8; LENGTH], rhs: &[u8; LENGTH]) -> [u8; LENGTH] {
    let mut out = [0; LENGTH];
    for pos in 0..LENGTH {
        out[pos] = lhs[pos] ^ rhs[pos];
    }
    out
}

pub fn xor_in_place<const LENGTH: usize>(
    mut lhs: Secret<LENGTH>,
    rhs: &[u8; LENGTH],
) -> Secret<LENGTH> {
    for pos in 0..LENGTH {
        lhs[pos] ^= rhs[pos];
    }
    lhs
}

pub fn shuffle<T>(xs: &mut [T], rng: &mut impl RngCore) {
    for i in 0..xs.len() {
        let j = rng.next_u32() as usize % xs.len();
        xs.swap(i, j);
    }
}

pub fn H_hash(
    K1: &<ElGamal as traits::Nike>::PublicKey,
    K2: Option<&Secret<SHARED_SECRET_LENGTH>>,
    T: &Secret<SHARED_SECRET_LENGTH>,
) -> Result<Secret<SHARED_SECRET_LENGTH>, Error> {
    let mut hasher = Sha3::v256();
    let mut H = Secret::<SHARED_SECRET_LENGTH>::new();
    hasher.update(&K1.serialize()?);
    if let Some(K2) = K2 {
        hasher.update(&**K2);
    }
    hasher.update(&**T);
    hasher.finalize(&mut *H);
    Ok(H)
}

pub fn J_hash(
    S: &Secret<SHARED_SECRET_LENGTH>,
    U: &Secret<SHARED_SECRET_LENGTH>,
) -> ([u8; TAG_LENGTH], Secret<SHARED_SECRET_LENGTH>) {
    let mut hasher = Sha3::v384();
    let mut bytes = [0; 384 / 8];
    hasher.update(&**S);
    hasher.update(&**U);
    hasher.finalize(&mut bytes);

    let mut tag = [0; TAG_LENGTH];
    let mut seed = Secret::<SHARED_SECRET_LENGTH>::default();
    tag.copy_from_slice(&bytes[..TAG_LENGTH]);
    seed.copy_from_slice(&bytes[TAG_LENGTH..]);
    (tag, seed)
}

pub fn G_hash(
    seed: &Secret<SHARED_SECRET_LENGTH>,
) -> Result<<ElGamal as traits::Nike>::SecretKey, Error> {
    Ok(<<ElGamal as traits::Nike>::SecretKey as traits::Sampling>::hash(&**seed))
}

#[derive(Debug, Clone, PartialEq)]
pub struct Encapsulations(
    pub Vec<(<MlKem as traits::Kem>::Encapsulation, [u8; SHARED_SECRET_LENGTH])>,
);

#[derive(Debug, Clone, PartialEq)]
pub struct XEnc {
    pub tag: Tag,
    pub c: Vec<<ElGamal as traits::Nike>::PublicKey>,
    pub encapsulations: Encapsulations,
}

impl XEnc {
    pub fn tracing_level(&self) -> usize {
        self.c.len() - 1
    }

    pub fn count(&self) -> usize {
        self.encapsulations.0.len()
    }
}

impl Serializable for Encapsulations {
    type Error = Error;

    fn length(&self) -> usize {
        to_leb128_len(self.0.len())
            + self.0.iter().map(|(E, F)| E.length() + F.len()).sum::<usize>()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_leb128_u64(self.0.len() as u64)?;
        for (E, F) in self.0.iter() {
            n += ser.write(E)?;
            n += ser.write_array(F)?;
        }
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let len = usize::try_from(de.read_leb128_u64()?)?;
        let vec = (0..len)
            .map(|_| {
                let E = de.read()?;
                let F = de.read_array::<SHARED_SECRET_LENGTH>()?;
                Ok::<_, Error>((E, F))
            })
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self(vec))
    }
}

impl Serializable for XEnc {
    type Error = Error;

    fn length(&self) -> usize {
        TAG_LENGTH
            + to_leb128_len(self.c.len())
            + self.c.iter().map(Serializable::length).sum::<usize>()
            + self.encapsulations.length()
    }

    fn write(&self, ser: &mut Serializer) -> Result<usize, Self::Error> {
        let mut n = ser.write_array(&self.tag)?;
        n += ser.write_leb128_u64(self.c.len() as u64)?;
        for trap in &self.c {
            n += ser.write(trap)?;
        }
        n += ser.write(&self.encapsulations)?;
        Ok(n)
    }

    fn read(de: &mut Deserializer) -> Result<Self, Self::Error> {
        let tag = de.read_array::<TAG_LENGTH>()?;
        let n_traps = <usize>::try_from(de.read_leb128_u64()?)?;
        let mut traps = Vec::with_capacity(n_traps);
        for _ in 0..n_traps {
            let trap = de.read()?;
            traps.push(trap);
        }
        let encapsulations = Encapsulations::read(de)?;
        Ok(Self { tag, c: traps, encapsulations })
    }
}
