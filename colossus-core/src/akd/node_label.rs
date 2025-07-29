pub use super::{
    Bit, PrefixOrdering,
    serde_helpers::{bytes_deserialize_hex, bytes_serialize_hex},
};
use crate::configuration::Configuration;
use alloc::{format, string::String, vec::Vec};
use rand::random;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct NodeLabel {
    #[serde(serialize_with = "bytes_serialize_hex")]
    #[serde(deserialize_with = "bytes_deserialize_hex")]
    pub label_val: [u8; 32],

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
    pub fn value<TC: Configuration>(&self) -> Vec<u8> {
        TC::compute_node_label_value(&self.to_bytes())
    }

    pub fn to_bytes(self) -> Vec<u8> {
        [&self.label_len.to_be_bytes(), &self.label_val[..]].concat()
    }

    pub fn is_prefix_of(&self, other: &Self) -> bool {
        if self.label_len > other.label_len {
            return false;
        }
        (0..self.label_len).all(|i| self.get_bit_at(i) == other.get_bit_at(i))
    }

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

    pub fn root() -> Self {
        Self::new([0u8; 32], 0)
    }

    pub fn new(val: [u8; 32], len: u32) -> Self {
        NodeLabel { label_val: val, label_len: len }
    }

    pub fn get_len(&self) -> u32 {
        self.label_len
    }

    pub fn get_val(&self) -> [u8; 32] {
        self.label_val
    }

    pub fn get_prefix_ordering(&self, other: Self) -> PrefixOrdering {
        if self.get_len() >= other.get_len() {
            return PrefixOrdering::Invalid;
        }
        if other.get_prefix(self.get_len()) != self.get_prefix(self.get_len()) {
            return PrefixOrdering::Invalid;
        }
        if let Ok(bit) = other.get_bit_at(self.get_len()) {
            return PrefixOrdering::from(bit);
        }

        PrefixOrdering::Invalid
    }
}

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

pub fn random_label() -> NodeLabel {
    NodeLabel { label_val: random(), label_len: 256 }
}

pub fn byte_arr_from_u64(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

pub fn byte_arr_from_u64_le(input_int: u64) -> [u8; 32] {
    let mut output_arr = [0u8; 32];
    let input_arr = input_int.to_be_bytes();
    output_arr[..8].clone_from_slice(&input_arr[..8]);
    output_arr
}

#[cfg(test)]
mod test {
    use super::*;

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

    #[test]
    fn test_get_bit_at_large() {
        let mut val = [0u8; 32];

        val[2] = 128u8 + 32u8;

        let label = NodeLabel::new(val, 256);

        let expected_raw =
            vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0];
        let expected = expected_raw
            .iter()
            .map(|x| if *x == 0 { Bit::Zero } else { Bit::One })
            .collect::<Vec<Bit>>();

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

    #[test]
    fn test_byte_arr_from_u64_small() {
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

    #[test]
    fn test_byte_arr_from_u64_medium() {
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

    #[test]
    fn test_byte_arr_from_u64_larger() {
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

    #[test]
    fn test_node_label_equal_leading_one() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
        assert!(label_1 == label_2, "Identical labels with leading one not found equal!")
    }

    #[test]
    fn test_node_label_equal_leading_zero() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(100000000u64 << 55), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
        assert!(label_1 == label_2, "Identical labels with leading zero not found equal!")
    }

    #[test]
    fn test_node_label_unequal_values() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64), 9u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(110000000u64), 9u32);
        assert!(label_1 != label_2, "Unequal labels found equal!")
    }

    #[test]
    fn test_node_label_equal_values_unequal_len() {
        let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
        let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 9u32);
        assert!(label_1 != label_2, "Identical labels with unequal lengths not found equal!")
    }

    #[test]
    fn test_get_prefix_ordering_with_invalid_bits() {
        let invalid_label = NodeLabel::new(
            byte_arr_from_u64(
                0b0000101101110110110000000000110101110001000000000110011001000101u64,
            ),
            1u32,
        );

        let some_label = NodeLabel::new(byte_arr_from_u64(0u64), 64u32);
        assert_eq!(invalid_label.get_prefix_ordering(some_label), PrefixOrdering::WithZero);

        let zero_length_invalid_bits_label = NodeLabel::new(byte_arr_from_u64(1), 0);
        assert_eq!(
            zero_length_invalid_bits_label.get_prefix_ordering(some_label),
            PrefixOrdering::WithZero
        );
    }

    #[test]
    fn test_get_dir_example() {
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
