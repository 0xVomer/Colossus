use super::{CBORCodec, Credential, spseq_uc::CredentialCompressed};
use serde::{Deserialize, Serialize};
use std::ops::Deref;

#[derive(Clone, Debug, PartialEq)]
pub struct Offer(pub(crate) Credential);

impl AsRef<Credential> for Offer {
    fn as_ref(&self) -> &Credential {
        &self.0
    }
}

#[derive(Clone, Serialize, Deserialize)]
pub struct OfferCompressed(CredentialCompressed);

impl CBORCodec for OfferCompressed {}

impl Deref for Offer {
    type Target = Credential;

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

impl TryFrom<CredentialCompressed> for Offer {
    type Error = crate::dac::error::Error;

    fn try_from(cred: CredentialCompressed) -> Result<Self, Self::Error> {
        Ok(Offer(cred.try_into()?))
    }
}

impl From<CredentialCompressed> for OfferCompressed {
    fn from(cred: CredentialCompressed) -> Self {
        OfferCompressed(cred)
    }
}

impl From<Offer> for Credential {
    fn from(offer: Offer) -> Self {
        offer.0
    }
}

impl From<Credential> for Offer {
    fn from(cred: Credential) -> Self {
        Offer(cred)
    }
}

impl From<OfferCompressed> for CredentialCompressed {
    fn from(offer: OfferCompressed) -> Self {
        offer.0
    }
}

impl TryFrom<OfferCompressed> for Vec<u8> {
    type Error = crate::dac::error::Error;

    fn try_from(value: OfferCompressed) -> Result<Self, Self::Error> {
        let cred: CredentialCompressed = value.into();
        Ok(cred.to_cbor()?)
    }
}

impl TryFrom<Vec<u8>> for OfferCompressed {
    type Error = crate::dac::error::Error;

    fn try_from(value: Vec<u8>) -> Result<Self, Self::Error> {
        let cred = CredentialCompressed::from_cbor(&value)?;
        Ok(cred.into())
    }
}
