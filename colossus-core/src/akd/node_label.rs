//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! This module contains the specifics for NodeLabel only, other types don't have the
//! same level of detail and aren't broken into sub-modules

pub use super::{
    Bit, PrefixOrdering,
    serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex},
};
use crate::configuration::Configuration;
use alloc::{format, string::String, vec::Vec};
use rand::random;
use serde::{Deserialize, Serialize};

/// Represents the label of an AKD node
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeLabel {
    #[serde(serialize_with = "bytes_serialize_hex")]
    #[serde(deserialize_with = "bytes_deserialize_hex")]

    /// Stores a binary string as a 32-byte array of `u8`s
    pub label_val: [u8; 32],
    /// len keeps track of how long the binary string is in bits
    pub label_len: u32,
}

impl super::SizeOf for NodeLabel {
    fn size_of(&self) -> usize {
        self.label_val.len() + core::mem::size_of::<u32>()
    }
}

impl PartialOrd for NodeLabel {
    fn partial_cmp(&self, other: &Self) -> Option<core::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for NodeLabel {
    fn cmp(&self, other: &Self) -> core::cmp::Ordering {
        // `label_len`, `label_val`
        let len_cmp = self.label_len.cmp(&other.label_len);
        if let core::cmp::Ordering::Equal = len_cmp {
            self.label_val.cmp(&other.label_val)
        } else {
            len_cmp
        }
    }
}

impl core::fmt::Display for NodeLabel {
    fn fmt(&self, f: &mut core::fmt::Formatter) -> core::fmt::Result {
        write!(f, "(0x{}, {})", hex::encode(self.label_val), self.label_len)
    }
}

impl NodeLabel {
    /// Returns the value of the [NodeLabel]
    pub fn value<TC: Configuration>(&self) -> Vec<u8> {
        TC::compute_node_label_value(&self.to_bytes())
    }

    pub fn to_bytes(self) -> Vec<u8> {
        [&self.label_len.to_be_bytes(), &self.label_val[..]].concat()
    }

    /// Outputs whether or not self is a prefix of the other [NodeLabel]
    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.label_len > other.label_len {
            return false;
        }
        (0..self.label_len).all(|i| self.get_bit_at(i) == other.get_bit_at(i))
    }

    /// Takes as input a pointer to the caller and another [NodeLabel],
    /// returns a [NodeLabel] that is the longest common prefix of the two.
    pub fn get_longest_common_prefix<TC: Configuration>(&self, other: NodeLabel) -> Self {
        let empty_label = TC::empty_label();
        if *self == empty_label || other == empty_label {
            return empty_label;
        }

        let shorter_len = if self.label_len < other.label_len {
            self.label_len
        } else {
            other.label_len
        };

        let mut prefix_len = 0;
        while prefix_len < shorter_len
            && self.get_bit_at(prefix_len) == other.get_bit_at(prefix_len)
        {
            prefix_len += 1;
        }

        self.get_prefix(prefix_len)
    }

    /// Returns the bit at a specified index (either a 0 or a 1). Will
    /// throw an error if the index is out of range
    /// (exceeds or is equal to the length of the label in bits)
    ///
    /// Note that this is calculated from the right, for example:
    /// let mut label = [0u8; 32];
    /// label[0] = 0b10100000u8;
    /// We should get outputs as follows:
    /// * label.get_bit_at(0) = 1
    /// * label.get_bit_at(1) = 0
    /// * label.get_bit_at(2) = 1
    /// * label.get_bit_at(3) = 0
    /// * label.get_bit_at(4) = 0
    /// * label.get_bit_at(5) = 0
    /// * label.get_bit_at(6) = 0
    /// * label.get_bit_at(7) = 0
    pub fn get_bit_at(&self, index: u32) -> Result<Bit, String> {
        if index >= self.label_len {
            return Err(format!(
                "Index out of range: index = {index}, label_len = {label_len}",
                index = index,
                label_len = self.label_len
            ));
        }
        get_bit_from_slice(&self.label_val, index)
    }

    /// Returns the prefix of a specified length, and the entire value if the length is >= 256
    pub fn get_prefix(&self, len: u32) -> Self {
        if len >= 256 {
            return *self;
        }
        if len == 0 {
            return Self { label_val: [0u8; 32], label_len: 0 };
        }

        let usize_len: usize = (len - 1) as usize;
        let len_remainder = usize_len % 8;
        let len_div = usize_len / 8;

        let mut out_val = [0u8; 32];
        out_val[..len_div].clone_from_slice(&self.label_val[..len_div]);
        out_val[len_div] = (self.label_val[len_div] >> (7 - len_remainder)) << (7 - len_remainder);

        Self { label_val: out_val, label_len: len }
    }

    /// Creates a new NodeLabel representing the root.
    pub fn root() -> Self {
        Self::new([0u8; 32], 0)
    }

    /// Creates a new [NodeLabel] with the given value and len (in bits).
    pub fn new(val: [u8; 32], len: u32) -> Self {
        NodeLabel { label_val: val, label_len: len }
    }

    /// Gets the length of a NodeLabel in bits.
    pub fn get_len(&self) -> u32 {
        self.label_len
    }

    /// Gets the value of a NodeLabel.
    pub fn get_val(&self) -> [u8; 32] {
        self.label_val
    }

    /// Gets the prefix ordering of other with respect to self, if self is a prefix of other.
    /// If self is not a prefix of other, then this returns [PrefixOrdering::Invalid].
    pub fn get_prefix_ordering(&self, other: Self) -> PrefixOrdering {
        if self.get_len() >= other.get_len() {
            return PrefixOrdering::Invalid;
        }
        if other.get_prefix(self.get_len()) != self.get_prefix(self.get_len()) {
            // Note: we check self.get_prefix(self.get_len()) here instead of just *self
            // because equality checks for a [NodeLabel] do not ignore the bits of label_val set
            // beyond label_len.
            return PrefixOrdering::Invalid;
        }
        if let Ok(bit) = other.get_bit_at(self.get_len()) {
            return PrefixOrdering::from(bit);
        }

        PrefixOrdering::Invalid
    }
}

/// Returns the bit at a specified index (either a 0 or a 1) of a slice of bytes
///
/// If the index is out of range (exceeds or is equal to the length of the input in bytes * 8),
/// returns an error
fn get_bit_from_slice(input: &[u8], index: u32) -> Result<Bit, String> {
    if (input.len() as u32) * 8 <= index {
        return Err(format!("Input is too short: index = {index}, input.len() = {}", input.len()));
    }
    let usize_index: usize = index as usize;
    let index_full_blocks = usize_index / 8;
    let index_remainder = usize_index % 8;
    if (input[index_full_blocks] >> (7 - index_remainder)) & 1 == 0 {
        Ok(Bit::Zero)
    } else {
        Ok(Bit::One)
    }
}

// ================= Test helpers ================= //

pub fn random_label() -> NodeLabel {
    NodeLabel { label_val: random(), label_len: 256 }
}

// Creates a byte array of 32 bytes from a u64
// Note that this representation is big-endian, and
// places the bits to the front of the output byte_array.
pub fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

// Creates a byte array of 32 bytes from a u64
// Note that this representation is little-endian, and
// places the bits to the front of the output byte_array.
pub fn byte_arr_from_u64_le(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[cfg(test)]
mod test {
    use super::*;

    // This test tests get_bit_at on a small label of len 4.
    // The label is logically equal to the binary string "1010"
    // and should return the corresponding bits.
    #[test]
    fn test_get_bit_at_small() {
        let val = 0b1010u64 << 60;
        let expected = vec![Bit::One, Bit::Zero, Bit::One, Bit::Zero];
        let label = NodeLabel::new(byte_arr_from_u64(val), 4);
        for (index, item) in expected.iter().enumerate().take(4) {
            assert!(
                *item == label.get_bit_at(index as u32).unwrap(),
                "get_bit_at({}) wrong for the 4 digit label 0b1010! Expected {:?} and got {:?}",
                index,
                *item,
                label.get_bit_at(index as u32)
            )
        }
        for index in 4u32..256u32 {
            assert!(label.get_bit_at(index).is_err(), "Index {index} should be out of range");
        }
    }

    // In this test, we have a label of length 256, logically equal to
    // 1 followed by 255 0s. We want to make sure its 0th bit is read out as 1.
    #[test]
    fn test_get_bit_at_medium_1() {
        let val = 0b1u64 << 63;
        let expected = Bit::One;
        let label = NodeLabel::new(byte_arr_from_u64(val), 256);
        let computed = label.get_bit_at(0).unwrap();
        assert!(
            expected == computed,
            "{}",
            "get_bit_at(2) wrong for the 4 digit label 10! Expected {expected:?} and got {computed:?}"
        )
    }

    // In this test, we have a label of length 256, logically equal to
    // 1 followed by 255 0s. We want to make sure its 190th bit is read out as 0.
    // We have this because the string itself has only one non-zero bit and we still want
    // to check beyond the 0th index.
    #[test]
    fn test_get_bit_at_medium_2() {
        let val = 0b1u64 << 63;
        let expected = Bit::Zero;
        let label = NodeLabel::new(byte_arr_from_u64(val), 256);
        let computed = label.get_bit_at(190).unwrap();
        assert!(
            expected == computed,
            "{}",
            "get_bit_at(2) wrong for the 4 digit label 10! Expected {expected:?} and got {computed:?}"
        )
    }

    // This test creates a label of length 256 logically equal to
    // "0000 0000 0000 0000 1010 0000" followed by all 0s. We know that the
    // first non-zero bit is at position 16, and we want to check that.
    #[test]
    fn test_get_bit_at_large() {
        let mut val = [0u8; 32];
        // 128u8 = 0b1000 0000u8 and 32u8 = 0b10 0000u8, hence their
        // sum is "1010 0000"
        val[2] = 128u8 + 32u8;
        // create the label
        let label = NodeLabel::new(val, 256);
        // val[2] is positions 16-23 (both included),
        // so we want to check everything till there.
        let expected_raw =
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0];
        let expected = expected_raw
            .iter()
            .map(|x| if *x == 0 { Bit::Zero } else { Bit::One })
            .collect::<Vec<Bit>>();

        // the vector expected covers the first 24 indices.
        for (index, item) in expected.iter().enumerate().take(24) {
            let index_32 = index as u32;
            assert!(
                *item == label.get_bit_at(index_32).unwrap(),
                "get_bit_at({}) wrong for the 256 digit label 0000 0000 0000 0000 1010 0000! Expected {:?} and got {:?}",
                index,
                *item,
                label.get_bit_at(index_32)
            )
        }
        // Everything after the first 24 indixes is 0
        for index in 24..256 {
            let index_32 = index as u32;
            assert!(
                Bit::Zero == label.get_bit_at(index_32).unwrap(),
                "get_bit_at({}) wrong for the 256 digit label 0000 0000 0000 0000 1010 0000! Expected {:?} and got {:?}",
                index,
                Bit::Zero,
                label.get_bit_at(index_32)
            )
        }
    }

    // This test is testing our helper function byte_arr_from_u64, which
    // we mainly use for testing. Still we want it to be correct!
    // We call it "small" since it only tests what would
    // result in 1 non-zero byte.
    #[test]
    fn test_byte_arr_from_u64_small() {
        // This val is 2 copies of "10" followed by all 0s.
        // This should be converted into the byte array of all 0s
        // but with the first two byte 0b10100000u8.
        let val = 0b1010u64 << 60;
        let mut expected = [0u8; 32];
        expected[0] = 0b10100000u8;
        let computed = byte_arr_from_u64(val);
        assert!(
            expected == computed,
            "{}",
            "Byte from u64 conversion wrong for small u64! Expected {expected:?} and got {computed:?}"
        )
    }

    // This test is testing our helper function byte_arr_from_u64, which
    // we mainly use for testing. Still we want it to be correct!
    // It is only testing for 2 non-zero bytes.
    #[test]
    fn test_byte_arr_from_u64_medium() {
        // This val is 6 copies of "10" followed by all 0s.
        // This should be converted into the byte array of all 0s
        // but with the first two bytes 0b10101010u8 and 0b10100000u8.
        let val = 0b101010101010u64 << 52;
        let mut expected = [0u8; 32];
        expected[0] = 0b10101010u8;
        expected[1] = 0b10100000u8;
        let computed = byte_arr_from_u64(val);
        assert!(
            expected == computed,
            "{}",
            "Byte from u64 conversion wrong for medium, ~2 byte u64! Expected {expected:?} and got {computed:?}"
        )
    }

    // This test is testing our helper function byte_arr_from_u64, which
    // we mainly use for testing. Still we want it to be correct!
    // It is only testing for 3 non-zero bytes.
    #[test]
    fn test_byte_arr_from_u64_larger() {
        // This string was hand-generated for testing so that
        // all three non-zero bytes were distinct.
        let val = 0b01011010101101010101010u64 << 41;
        let mut expected = [0u8; 32];
        expected[0] = 0b01011010u8;
        expected[1] = 0b10110101u8;
        expected[2] = 0b01010100u8;

        let computed = byte_arr_from_u64(val);
        assert!(
            expected == computed,
            "{}",
            "Byte from u64 conversion wrong for larger, ~3 byte u64! Expected {expected:?} and got {computed:?}"
        )
    }

    // Test two NodeLabels for equality, when their leading bit is 1.
    #[test]
    fn test_node_label_equal_leading_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
        assert!(label_1 == label_2, "Identical labels with leading one not found equal!")
    }

    // Test two NodeLabels for equality, when their leading bit is 0.
    #[test]
    fn test_node_label_equal_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(100000000u64 << 55), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
        assert!(label_1 == label_2, "Identical labels with leading zero not found equal!")
    }

    // Test two NodeLabels for inequality, when their leading bit is 1.
    #[test]
    fn test_node_label_unequal_values() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(110000000u64), 9u32);
        assert!(label_1 != label_2, "Unequal labels found equal!")
    }

    // Test two NodeLabels for inequality due to differing length, when their leading bit is 1.
    #[test]
    fn test_node_label_equal_values_unequal_len() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
        assert!(label_1 != label_2, "Identical labels with unequal lengths not found equal!")
    }

    // This test gets a prefix for a hard-coded random string and makes sure it is equal to a hand-computed value.
    #[test]
    fn test_get_prefix_ordering_with_invalid_bits() {
        let invalid_label = NodeLabel::new(
            byte_arr_from_u64(
                0b0000101101110110110000000000110101110001000000000110011001000101u64,
            ),
            1u32,
        );

        // Simple test case
        let some_label = NodeLabel::new(byte_arr_from_u64(0u64), 64u32);
        assert_eq!(invalid_label.get_prefix_ordering(some_label), PrefixOrdering::WithZero);

        // Zero-length label should not return PrefixOrdering::Invalid
        let zero_length_invalid_bits_label = NodeLabel::new(byte_arr_from_u64(1), 0);
        assert_eq!(
            zero_length_invalid_bits_label.get_prefix_ordering(some_label),
            PrefixOrdering::WithZero
        );
    }
    // This test just serves as another example of get_dir and this time we want to use little endian encoding
    // since we are using more complex u64 values.
    #[test]
    fn test_get_dir_example() {
        // 23 in little endian is 10111 and 10049430782486799941u64 begins with
        // the prefix 00110100, hence, label_1 is not a prefix of label_2.
        let label_1 = NodeLabel::new(byte_arr_from_u64_le(10049430782486799941u64), 64u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64_le(23u64), 5u32);
        let expected = PrefixOrdering::Invalid;
        let computed = label_2.get_prefix_ordering(label_1);
        assert!(
            computed == expected,
            "{}",
            "Direction not equal to expected. Node = {label_1:?}, prefix = {label_2:?}, computed = {computed:?}"
        )
    }

    // This test gets a prefix for a hard-coded random string and makes sure it is equal to a hand-computed value.
    #[test]
    fn test_get_prefix_small() {
        let label_1 = NodeLabel::new(
            byte_arr_from_u64(
                0b1000101101110110110000000000110101110001000000000110011001000101u64,
            ),
            64u32,
        );
        let prefix_len = 10u32;
        let label_2 = NodeLabel::new(byte_arr_from_u64(0b1000101101u64 << 54), prefix_len);
        let computed = label_1.get_prefix(prefix_len);
        assert!(
            computed == label_2,
            "{}",
            "Direction not equal to expected. Node = {label_1:?}, prefix = {label_2:?}, computed = {computed:?}"
        )
    }
}
