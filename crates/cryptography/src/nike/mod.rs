pub mod r25519;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;
use std::ops::Add;
use std::ops::AddAssign;
use std::ops::Div;
use std::ops::Mul;
use std::ops::MulAssign;
use std::ops::Sub;
use std::ops::SubAssign;

pub trait Nike {
    type SecretKey: Sampling;
    type PublicKey: for<'a> From<&'a Self::SecretKey>;
    type SessionKey;
    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SecretKey, Self::PublicKey), Self::Error>;

    /// Generates the session key associated to the given keypair.
    fn session_key(
        sk: &Self::SecretKey,
        pk: &Self::PublicKey,
    ) -> Result<Self::SessionKey, Self::Error>;
}

pub trait Sampling {
    fn random(rng: &mut impl CryptoRngCore) -> Self;
    fn hash(seed: &[u8]) -> Self;
}

pub trait Zero {
    fn zero() -> Self;
    fn is_zero(&self) -> bool;
}

pub trait One {
    fn one() -> Self;
    fn is_one(&self) -> bool;
}

pub trait Group:
    Sized
    + Zero
    + Add<Output = Self>
    + AddAssign
    + Sub<Output = Self>
    + SubAssign
    + for<'a> Add<&'a Self, Output = Self>
    + for<'a> Sub<&'a Self, Output = Self>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
{
}

pub trait Ring:
    Group
    + Zero
    + Mul<Output = Self>
    + MulAssign
    + Div<Output = Result<Self, Self::DivError>>
    + for<'a> Mul<&'a Self, Output = Self>
    + for<'a> Div<&'a Self, Output = Result<Self, Self::DivError>>
where
    for<'a, 'b> &'a Self: Add<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Sub<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Mul<&'b Self, Output = Self>,
    for<'a, 'b> &'a Self: Div<&'b Self, Output = Result<Self, Self::DivError>>,
{
    type DivError;
}

pub trait KeyHomomorphicNike: Nike
where
    Self::PublicKey: Group,
    Self::SecretKey: Ring,
    Self::PublicKey: Mul<Self::SecretKey, Output = Self::PublicKey>,
    for<'a> Self::PublicKey: Mul<&'a Self::SecretKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Add<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::PublicKey: Sub<&'b Self::PublicKey, Output = Self::PublicKey>,
    for<'a, 'b> &'a Self::SecretKey: Add<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Sub<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Mul<&'b Self::SecretKey, Output = Self::SecretKey>,
    for<'a, 'b> &'a Self::SecretKey: Div<
            &'b Self::SecretKey,
            Output = Result<Self::SecretKey, <Self::SecretKey as Ring>::DivError>,
        >,
{
}
