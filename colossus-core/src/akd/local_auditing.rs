use super::{
    Digest,
    proofs::{AppendOnlyProof, SingleAppendOnlyProof},
};
use crate::proto::ConversionError;
use protobuf::Message;
use std::convert::{TryFrom, TryInto};

#[derive(Debug)]
pub enum LocalAuditorError {
    NameParseError(String),

    MisMatchedLengths(String),

    ConversionError(ConversionError),
}

impl From<ConversionError> for LocalAuditorError {
    fn from(err: ConversionError) -> Self {
        Self::ConversionError(err)
    }
}

impl From<protobuf::Error> for LocalAuditorError {
    fn from(err: protobuf::Error) -> Self {
        Self::ConversionError(err.into())
    }
}

macro_rules! hash_from_ref {
    ($obj:expr) => {
        crate::akd::try_parse_digest($obj).map_err(ConversionError::Deserialization)
    };
}

const NAME_SEPARATOR: char = '/';

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd, Hash, Default, Copy)]
pub struct AuditBlobName {
    pub epoch: u64,

    pub previous_hash: Digest,

    pub current_hash: Digest,
}

impl std::fmt::Display for AuditBlobName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let previous_hash = hex::encode(self.previous_hash);
        let current_hash = hex::encode(self.current_hash);
        write!(
            f,
            "{}{}{}{}{}",
            self.epoch, NAME_SEPARATOR, previous_hash, NAME_SEPARATOR, current_hash
        )
    }
}

impl TryFrom<&str> for AuditBlobName {
    type Error = LocalAuditorError;

    fn try_from(name: &str) -> Result<Self, Self::Error> {
        let parts = name.split(NAME_SEPARATOR).collect::<Vec<_>>();
        if parts.len() < 3 {
            return Err(LocalAuditorError::NameParseError(
                "Name is malformed, there are not enough components to reconstruct!".to_string(),
            ));
        }

        let epoch: u64 = parts[0].parse().map_err(|_| {
            LocalAuditorError::NameParseError(format!("Failed to parse '{}' into an u64", parts[0]))
        })?;

        let previous_hash_bytes = hex::decode(parts[1]).map_err(|hex_err| {
            LocalAuditorError::NameParseError(format!(
                "Failed to decode previous hash from hex string: {hex_err}"
            ))
        })?;
        let previous_hash = hash_from_ref!(&previous_hash_bytes)?;

        let current_hash_bytes = hex::decode(parts[2]).map_err(|hex_err| {
            LocalAuditorError::NameParseError(format!(
                "Failed to decode current hash from hex string: {hex_err}"
            ))
        })?;
        let current_hash = hash_from_ref!(&current_hash_bytes)?;

        Ok(AuditBlobName { epoch, current_hash, previous_hash })
    }
}

#[derive(Clone)]
pub struct AuditBlob {
    pub name: AuditBlobName,

    pub data: Vec<u8>,
}

impl AuditBlob {
    pub fn new(
        previous_hash: Digest,
        current_hash: Digest,
        epoch: u64,
        proof: &SingleAppendOnlyProof,
    ) -> Result<AuditBlob, LocalAuditorError> {
        let name = AuditBlobName { epoch, previous_hash, current_hash };
        let proto: crate::proto::specs::types::SingleAppendOnlyProof = proof.into();

        Ok(AuditBlob { name, data: proto.write_to_bytes()? })
    }

    pub fn decode(
        &self,
    ) -> Result<(u64, Digest, Digest, SingleAppendOnlyProof), LocalAuditorError> {
        let proof =
            crate::proto::specs::types::SingleAppendOnlyProof::parse_from_bytes(&self.data)?;
        let local_proof: SingleAppendOnlyProof = (&proof).try_into()?;

        Ok((
            self.name.epoch,
            hash_from_ref!(&self.name.previous_hash)?,
            hash_from_ref!(&self.name.current_hash)?,
            local_proof,
        ))
    }
}

pub fn generate_audit_blobs(
    hashes: Vec<Digest>,
    proof: AppendOnlyProof,
) -> Result<Vec<AuditBlob>, LocalAuditorError> {
    if proof.epochs.len() + 1 != hashes.len() {
        return Err(LocalAuditorError::MisMatchedLengths(format!(
            "The proof has a different number of epochs than needed for hashes.
            The number of hashes you provide should be one more than the number of epochs!
            Number of epochs = {}, number of hashes = {}",
            proof.epochs.len(),
            hashes.len()
        )));
    }

    if proof.epochs.len() != proof.proofs.len() {
        return Err(LocalAuditorError::MisMatchedLengths(format!(
            "The proof has {} epochs and {} proofs. These should be equal!",
            proof.epochs.len(),
            proof.proofs.len()
        )));
    }

    let mut results = Vec::with_capacity(proof.proofs.len());

    for i in 0..hashes.len() - 1 {
        let previous_hash = hashes[i];
        let current_hash = hashes[i + 1];

        let epoch = proof.epochs[i];

        let blob = AuditBlob::new(previous_hash, current_hash, epoch, &proof.proofs[i])?;
        results.push(blob);
    }

    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::{AuditBlobName, LocalAuditorError};
    use std::convert::TryInto;

    #[test]
    fn test_audit_proof_naming_conventions() -> Result<(), LocalAuditorError> {
        let expected_name = "54/0101010101010101010101010101010101010101010101010101010101010101/0000000000000000000000000000000000000000000000000000000000000000";

        let blob_name = AuditBlobName {
            current_hash: crate::akd::EMPTY_DIGEST,
            previous_hash: [1u8; crate::akd::DIGEST_BYTES],
            epoch: 54,
        };

        let name = blob_name.to_string();
        assert_ne!(String::new(), name);

        assert_eq!(expected_name.to_string(), blob_name.to_string());

        let blob_name_ref: &str = name.as_ref();
        let decomposed: AuditBlobName = blob_name_ref.try_into()?;
        assert_eq!(blob_name, decomposed);
        Ok(())
    }
}
