use crate::{access_control::cryptography::traits::AE, policy::Error};
use cosmian_crypto_core::{
    Dem, FixedSizeCBytes, Instantiable, Nonce, RandomFixedSizeCBytes, SymmetricKey,
    XChaCha20Poly1305, reexport::rand_core::CryptoRngCore,
};
use zeroize::Zeroizing;

impl AE<{ Self::KEY_LENGTH }> for XChaCha20Poly1305 {
    type Error = Error;

    fn encrypt(
        rng: &mut impl CryptoRngCore,
        key: &SymmetricKey<{ Self::KEY_LENGTH }>,
        ptx: &[u8],
        aad: &[u8],
    ) -> Result<Vec<u8>, Error> {
        let nonce = Nonce::<{ Self::NONCE_LENGTH }>::new(&mut *rng);
        let ciphertext = Self::new(key).encrypt(&nonce, ptx, Some(aad))?;
        Ok([nonce.as_bytes(), &ciphertext].concat())
    }

    fn decrypt(
        key: &SymmetricKey<{ Self::KEY_LENGTH }>,
        ctx: &[u8],
        aad: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        if ctx.len() < Self::NONCE_LENGTH {
            return Err(Error::CryptoCoreError(
                cosmian_crypto_core::CryptoCoreError::DecryptionError,
            ));
        }
        let nonce = Nonce::try_from_slice(&ctx[..Self::NONCE_LENGTH])?;
        Self::new(key)
            .decrypt(&nonce, &ctx[Self::NONCE_LENGTH..], Some(aad))
            .map_err(Error::CryptoCoreError)
            .map(Zeroizing::new)
    }
}
