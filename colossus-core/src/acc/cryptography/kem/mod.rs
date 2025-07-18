pub mod mlkem;
use cosmian_crypto_core::reexport::rand_core::CryptoRngCore;

pub trait Kem {
    type EncapsulationKey;
    type DecapsulationKey;
    type SessionKey;
    type Encapsulation;
    type Error: std::error::Error;

    /// Generates a new random keypair.
    fn keygen(
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::DecapsulationKey, Self::EncapsulationKey), Self::Error>;

    /// Generates an encapsulation of a random session key, and returns both the
    /// key and its encapsulation.
    fn enc(
        ek: &Self::EncapsulationKey,
        rng: &mut impl CryptoRngCore,
    ) -> Result<(Self::SessionKey, Self::Encapsulation), Self::Error>;

    /// Attempts opening the given encapsulation. Upon failure to decapsulate,
    /// returns a random session key.
    fn dec(
        dk: &Self::DecapsulationKey,
        enc: &Self::Encapsulation,
    ) -> Result<Self::SessionKey, Self::Error>;
}
