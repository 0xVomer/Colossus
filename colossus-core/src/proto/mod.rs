//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! This module contains all the protobuf types for type conversion between internal and external
//! types. NOTE: Protobuf encoding is NOT supported in nostd environments. The generated code is using vector
//! too heavily to be nostd compliant

// Setup the protobuf specs
pub mod specs;

#[cfg(test)]
mod tests;

use crate::akd::{AzksValue, Bit, Digest};
use core::convert::{TryFrom, TryInto};
use protobuf::MessageField;

const DIRECTION_BLINDING_FACTOR: u32 = 0x000Fu32;

/// An error converting a protobuf proof
#[derive(Debug, Eq, PartialEq)]
pub enum ConversionError {
    /// Error deserializing from a protobuf structure/proof
    Deserialization(String),
    /// A core protobuf error occurred
    Protobuf(String),
}

impl From<protobuf::Error> for ConversionError {
    fn from(err: protobuf::Error) -> Self {
        Self::Protobuf(format!("An error occurred in protobuf serialization/deserialization {err}"))
    }
}

impl core::fmt::Display for ConversionError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> core::fmt::Result {
        let code = match &self {
            ConversionError::Deserialization(msg) => format!("(Deserialization) - {msg}"),
            ConversionError::Protobuf(msg) => format!("(Protobuf) - {msg}"),
        };
        write!(f, "Type conversion error {code}")
    }
}

// ************************ Converter macros ************************ //

// Protobuf best practice says everything should be `optional` to ensure
// maximum backwards compatibility. This helper function ensures an optional
// field is present in a particular interface version.
macro_rules! require {
    ($obj:ident, $has_field:ident) => {
        if !$obj.$has_field() {
            return Err(ConversionError::Deserialization(format!(
                "Required field {} missing. '{}'",
                stringify!($obj).to_string(),
                stringify!($has_field).to_string(),
            )));
        }
    };
}

macro_rules! require_messagefield {
    ($obj:ident, $field:ident) => {
        if $obj.$field.is_none() {
            return Err(ConversionError::Deserialization(format!(
                "Required field {} missing. '{}'",
                stringify!($obj).to_string(),
                stringify!($field).to_string(),
            )));
        }
    };
}

macro_rules! hash_from_bytes {
    ($obj:expr) => {{ crate::akd::try_parse_digest($obj).map_err(Self::Error::Deserialization)? }};
}

macro_rules! convert_from_vector {
    ($obj:expr, $expected_type:ty) => {{
        let mut data: Vec<$expected_type> = vec![];
        for item in $obj.iter() {
            data.push(item.try_into()?);
        }
        data
    }};
}

// ==============================================================
// NodeLabel
// ==============================================================

fn encode_minimum_label(v: &[u8; 32]) -> Vec<u8> {
    if let Some(last_non_zero) = v.iter().rposition(|b| *b != 0) {
        v[..=last_non_zero].to_vec()
    } else {
        Vec::new()
    }
}

// Assumes that the caller has checked that the input slice's length is at most 32
fn decode_minimized_label(v: &[u8]) -> [u8; 32] {
    assert!(v.len() <= 32, "Label value is too long");
    let mut out = [0u8; 32];
    out[..v.len()].copy_from_slice(v);
    out
}

impl From<&crate::akd::NodeLabel> for specs::types::NodeLabel {
    fn from(input: &crate::akd::NodeLabel) -> Self {
        Self {
            label_len: Some(input.label_len),
            label_val: Some(encode_minimum_label(&input.label_val)),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::NodeLabel> for crate::akd::NodeLabel {
    type Error = ConversionError;

    fn try_from(input: &specs::types::NodeLabel) -> Result<Self, Self::Error> {
        require!(input, has_label_len);
        require!(input, has_label_val);

        let input_val = input.label_val();
        let label_len = input.label_len();
        if input_val.len() > 32 {
            return Err(ConversionError::Deserialization(format!(
                "Label value is too long: {len}",
                len = input_val.len()
            )));
        }

        if label_len > 256 {
            return Err(ConversionError::Deserialization(format!(
                "Label length is too long, should be at most 256: {len}",
                len = label_len
            )));
        }

        // Note that we do not check that the bits beyond label_len are all 0, because
        // some labels do actually set bits beyond label_len, for example the "empty
        // label", which is not user-supplied but instead used as a placeholder

        let label_val = decode_minimized_label(input_val);
        Ok(Self { label_len, label_val })
    }
}

// ==============================================================
// Node
// ==============================================================

impl From<&crate::akd::AzksElement> for specs::types::AzksElement {
    fn from(input: &crate::akd::AzksElement) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            value: Some(input.value.0.to_vec()),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::AzksElement> for crate::akd::AzksElement {
    type Error = ConversionError;

    fn try_from(input: &specs::types::AzksElement) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require!(input, has_value);
        let label: crate::akd::NodeLabel = input.label.as_ref().unwrap().try_into()?;

        // get the raw data & it's length, but at most crate::akd::DIGEST_BYTES bytes
        let value = hash_from_bytes!(input.value());

        Ok(Self { label, value: AzksValue(value) })
    }
}

// ==============================================================
// SiblingProof
// ==============================================================

impl From<&crate::akd::proofs::SiblingProof> for specs::types::SiblingProof {
    fn from(input: &crate::akd::proofs::SiblingProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            siblings: input.siblings.iter().map(|s| s.into()).collect(),
            direction: Some(input.direction as u32),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::SiblingProof> for crate::akd::proofs::SiblingProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::SiblingProof) -> Result<Self, Self::Error> {
        require!(input, has_direction);
        require_messagefield!(input, label);
        let label: crate::akd::NodeLabel = input.label.as_ref().unwrap().try_into()?;

        // get the raw data & it's length, but at most crate::akd::DIGEST_BYTES bytes
        let siblings = input.siblings.first();
        if siblings.is_none() {
            return Err(ConversionError::Deserialization(
                "Required field siblings missing".to_string(),
            ));
        }

        // blind out the highest bits to all 0's, since we're pulling it down to a u8
        let direction = (input.direction() & DIRECTION_BLINDING_FACTOR) as u8;
        let bit = match direction {
            0 => Bit::Zero,
            1 => Bit::One,
            _ => {
                return Err(ConversionError::Deserialization(format!(
                    "Invalid direction: {direction}"
                )));
            },
        };

        Ok(Self {
            label,
            siblings: [siblings.unwrap().try_into()?],
            direction: crate::akd::Direction::from(bit),
        })
    }
}

// ==============================================================
// MembershipProof
// ==============================================================

impl From<&crate::akd::proofs::MembershipProof> for specs::types::MembershipProof {
    fn from(input: &crate::akd::proofs::MembershipProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            hash_val: Some(input.hash_val.0.to_vec()),
            sibling_proofs: input
                .sibling_proofs
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::MembershipProof> for crate::akd::proofs::MembershipProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::MembershipProof) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require!(input, has_hash_val);

        let label: crate::akd::NodeLabel = input.label.as_ref().unwrap().try_into()?;
        let hash_val: Digest = hash_from_bytes!(input.hash_val());

        let mut sibling_proofs = vec![];
        for proof in input.sibling_proofs.iter() {
            sibling_proofs.push(proof.try_into()?);
        }

        Ok(Self {
            label,
            hash_val: AzksValue(hash_val),
            sibling_proofs,
        })
    }
}

// ==============================================================
// NonMembershipProof
// ==============================================================

impl From<&crate::akd::proofs::NonMembershipProof> for specs::types::NonMembershipProof {
    fn from(input: &crate::akd::proofs::NonMembershipProof) -> Self {
        Self {
            label: MessageField::some((&input.label).into()),
            longest_prefix: MessageField::some((&input.longest_prefix).into()),
            longest_prefix_children: input
                .longest_prefix_children
                .iter()
                .map(|child| child.into())
                .collect::<Vec<_>>(),
            longest_prefix_membership_proof: MessageField::some(
                (&input.longest_prefix_membership_proof).into(),
            ),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::NonMembershipProof> for crate::akd::proofs::NonMembershipProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::NonMembershipProof) -> Result<Self, Self::Error> {
        require_messagefield!(input, label);
        require_messagefield!(input, longest_prefix);
        require_messagefield!(input, longest_prefix_membership_proof);

        let label: crate::akd::NodeLabel = input.label.as_ref().unwrap().try_into()?;
        let longest_prefix: crate::akd::NodeLabel =
            input.longest_prefix.as_ref().unwrap().try_into()?;
        let longest_prefix_membership_proof: crate::akd::proofs::MembershipProof =
            input.longest_prefix_membership_proof.as_ref().unwrap().try_into()?;

        let mut longest_prefix_children = vec![];
        for child in input.longest_prefix_children.iter() {
            longest_prefix_children.push(child.try_into()?);
        }

        Ok(Self {
            label,
            longest_prefix,
            longest_prefix_children: longest_prefix_children.try_into().map_err(|_| {
                ConversionError::Deserialization(
                    "Required field longest_prefix_children must be 2 elements long".to_string(),
                )
            })?,
            longest_prefix_membership_proof,
        })
    }
}

// ==============================================================
// LookupProof
// ==============================================================

impl From<&crate::akd::proofs::LookupProof> for specs::types::LookupProof {
    fn from(input: &crate::akd::proofs::LookupProof) -> Self {
        Self {
            epoch: Some(input.epoch),
            value: Some(input.value.0.clone()),
            version: Some(input.version),
            existence_vrf_proof: Some(input.existence_vrf_proof.clone()),
            existence_proof: MessageField::some((&input.existence_proof).into()),
            marker_vrf_proof: Some(input.marker_vrf_proof.clone()),
            marker_proof: MessageField::some((&input.marker_proof).into()),
            freshness_vrf_proof: Some(input.freshness_vrf_proof.clone()),
            freshness_proof: MessageField::some((&input.freshness_proof).into()),
            commitment_nonce: Some(input.commitment_nonce.clone()),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::LookupProof> for crate::akd::proofs::LookupProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::LookupProof) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_value);
        require!(input, has_version);
        require!(input, has_existence_vrf_proof);
        require_messagefield!(input, existence_proof);
        require!(input, has_marker_vrf_proof);
        require_messagefield!(input, marker_proof);
        require!(input, has_freshness_vrf_proof);
        require_messagefield!(input, freshness_proof);
        require!(input, has_commitment_nonce);

        Ok(Self {
            epoch: input.epoch(),
            value: crate::akd::AkdValue(input.value().to_vec()),
            version: input.version(),
            existence_vrf_proof: input.existence_vrf_proof().to_vec(),
            existence_proof: input.existence_proof.as_ref().unwrap().try_into()?,
            marker_vrf_proof: input.marker_vrf_proof().to_vec(),
            marker_proof: input.marker_proof.as_ref().unwrap().try_into()?,
            freshness_vrf_proof: input.freshness_vrf_proof().to_vec(),
            freshness_proof: input.freshness_proof.as_ref().unwrap().try_into()?,
            commitment_nonce: input.commitment_nonce().to_vec(),
        })
    }
}

// ==============================================================
// UpdateProof
// ==============================================================

impl From<&crate::akd::proofs::UpdateProof> for specs::types::UpdateProof {
    fn from(input: &crate::akd::proofs::UpdateProof) -> Self {
        Self {
            epoch: Some(input.epoch),
            value: Some(input.value.0.clone()),
            version: Some(input.version),
            existence_vrf_proof: Some(input.existence_vrf_proof.clone()),
            existence_proof: MessageField::some((&input.existence_proof).into()),
            previous_version_vrf_proof: input.previous_version_vrf_proof.as_ref().cloned(),
            previous_version_proof: MessageField::from_option(
                input.previous_version_proof.as_ref().map(|p| p.into()),
            ),
            commitment_nonce: Some(input.commitment_nonce.clone()),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::UpdateProof> for crate::akd::proofs::UpdateProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::UpdateProof) -> Result<Self, Self::Error> {
        require!(input, has_epoch);
        require!(input, has_value);
        require!(input, has_version);
        require!(input, has_existence_vrf_proof);
        require_messagefield!(input, existence_proof);
        require!(input, has_commitment_nonce);
        let previous_version_vrf_proof =
            input.previous_version_vrf_proof.as_ref().map(|item| item.to_vec());
        let previous_version_proof: Option<crate::akd::proofs::MembershipProof> =
            input.previous_version_proof.as_ref().map(|item| item.try_into()).transpose()?;

        Ok(Self {
            epoch: input.epoch(),
            value: crate::akd::AkdValue(input.value().to_vec()),
            version: input.version(),
            existence_vrf_proof: input.existence_vrf_proof().to_vec(),
            existence_proof: input.existence_proof.as_ref().unwrap().try_into()?,
            previous_version_vrf_proof,
            previous_version_proof,
            commitment_nonce: input.commitment_nonce().to_vec(),
        })
    }
}

// ==============================================================
// HistoryProof
// ==============================================================

impl From<&crate::akd::proofs::HistoryProof> for specs::types::HistoryProof {
    fn from(input: &crate::akd::proofs::HistoryProof) -> Self {
        Self {
            update_proofs: input.update_proofs.iter().map(|proof| proof.into()).collect::<Vec<_>>(),
            past_marker_vrf_proofs: input.past_marker_vrf_proofs.to_vec(),
            existence_of_past_marker_proofs: input
                .existence_of_past_marker_proofs
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            future_marker_vrf_proofs: input.future_marker_vrf_proofs.to_vec(),
            non_existence_of_future_marker_proofs: input
                .non_existence_of_future_marker_proofs
                .iter()
                .map(|proof| proof.into())
                .collect::<Vec<_>>(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::HistoryProof> for crate::akd::proofs::HistoryProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::HistoryProof) -> Result<Self, Self::Error> {
        let update_proofs =
            convert_from_vector!(input.update_proofs, crate::akd::proofs::UpdateProof);

        let past_marker_vrf_proofs = input
            .past_marker_vrf_proofs
            .iter()
            .map(|item| item.to_vec())
            .collect::<Vec<_>>();
        let existence_of_past_marker_proofs = convert_from_vector!(
            input.existence_of_past_marker_proofs,
            crate::akd::proofs::MembershipProof
        );

        let future_marker_vrf_proofs = input
            .future_marker_vrf_proofs
            .iter()
            .map(|item| item.to_vec())
            .collect::<Vec<_>>();
        let non_existence_of_future_marker_proofs = convert_from_vector!(
            input.non_existence_of_future_marker_proofs,
            crate::akd::proofs::NonMembershipProof
        );

        Ok(Self {
            update_proofs,
            past_marker_vrf_proofs,
            existence_of_past_marker_proofs,
            future_marker_vrf_proofs,
            non_existence_of_future_marker_proofs,
        })
    }
}

// ==============================================================
// SingleAppendOnlyProof
// ==============================================================

impl From<&crate::akd::proofs::SingleAppendOnlyProof> for specs::types::SingleAppendOnlyProof {
    fn from(input: &crate::akd::proofs::SingleAppendOnlyProof) -> Self {
        Self {
            inserted: input.inserted.iter().map(|node| node.into()).collect::<Vec<_>>(),
            unchanged_nodes: input
                .unchanged_nodes
                .iter()
                .map(|node| node.into())
                .collect::<Vec<_>>(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::SingleAppendOnlyProof> for crate::akd::proofs::SingleAppendOnlyProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::SingleAppendOnlyProof) -> Result<Self, Self::Error> {
        let inserted = convert_from_vector!(input.inserted, crate::akd::AzksElement);
        let unchanged_nodes = convert_from_vector!(input.unchanged_nodes, crate::akd::AzksElement);
        Ok(Self { inserted, unchanged_nodes })
    }
}

// ==============================================================
// SingleAppendOnlyProof
// ==============================================================

impl From<&crate::akd::proofs::AppendOnlyProof> for specs::types::AppendOnlyProof {
    fn from(input: &crate::akd::proofs::AppendOnlyProof) -> Self {
        Self {
            proofs: input.proofs.iter().map(|proof| proof.into()).collect::<Vec<_>>(),
            epochs: input.epochs.clone(),
            ..Default::default()
        }
    }
}

impl TryFrom<&specs::types::AppendOnlyProof> for crate::akd::proofs::AppendOnlyProof {
    type Error = ConversionError;

    fn try_from(input: &specs::types::AppendOnlyProof) -> Result<Self, Self::Error> {
        let proofs = input
            .proofs
            .iter()
            .map(|proof| proof.try_into())
            .collect::<Result<Vec<_>, _>>()?;
        let epochs = input.epochs.clone();
        Ok(Self { proofs, epochs })
    }
}
