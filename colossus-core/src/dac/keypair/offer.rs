use super::{AccessCredential, CBORCodec, spseq_uc::AccessCredentialCompressed};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq)]
pub struct Offer(pub(crate) AccessCredential);

impl AsRef<AccessCredential> for Offer {
    fn as_ref(&self) -> &AccessCredential {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OfferCompressed(AccessCredentialCompressed);

impl CBORCodec for OfferCompressed {}

impl Deref for Offer {
    type Target = AccessCredential;

    fn deref(&self) -> &Self::Target {
        &self.0
    }
}

impl From<Offer> for OfferCompressed {
    fn from(offer: Offer) -> Self {
        OfferCompressed(offer.0.into())
    }
}

impl TryFrom<OfferCompressed> for Offer {
    type Error = crate::dac::error::Error;

    fn try_from(offer: OfferCompressed) -> Result<Self, Self::Error> {
        Ok(Offer(offer.0.try_into()?))
    }
}

impl TryFrom<AccessCredentialCompressed> for Offer {
    type Error = crate::dac::error::Error;

    fn try_from(cred: AccessCredentialCompressed) -> Result<Self, Self::Error> {
        Ok(Offer(cred.try_into()?))
    }
}

impl From<AccessCredentialCompressed> for OfferCompressed {
    fn from(cred: AccessCredentialCompressed) -> Self {
        OfferCompressed(cred)
    }
}

impl From<Offer> for AccessCredential {
    fn from(offer: Offer) -> Self {
        offer.0
    }
}

impl From<AccessCredential> for Offer {
    fn from(cred: AccessCredential) -> Self {
        Offer(cred)
    }
}

impl From<OfferCompressed> for AccessCredentialCompressed {
    fn from(offer: OfferCompressed) -> Self {
        offer.0
    }
}

impl TryFrom<OfferCompressed> for Vec<u8> {
    type Error = crate::dac::error::Error;

    fn try_from(value: OfferCompressed) -> Result<Self, Self::Error> {
        let cred: AccessCredentialCompressed = value.into();
        Ok(cred.to_cbor()?)
    }
}

impl TryFrom<Vec<u8>> for OfferCompressed {
    type Error = crate::dac::error::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let cred = AccessCredentialCompressed::from_cbor(&value)?;
        Ok(cred.into())
    }
}
