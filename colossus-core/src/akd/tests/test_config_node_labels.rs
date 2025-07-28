use crate::{
    Configuration,
    akd::{NodeLabel, PrefixOrdering, random_label, utils::byte_arr_from_u64},
    test_config_sync,
};

test_config_sync!(test_node_label_lcp_with_zero_length_label);
fn test_node_label_lcp_with_zero_length_label<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0u64), 0u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0u64), 2u32);
    let expected = label_1;
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with zero-length label, not equal to zero-length label!"
    );
    assert!(
        label_2.get_longest_common_prefix::<TC>(label_1) == expected,
        "Longest common substring with zero-length label, not equal to zero-length label!"
    );
}

test_config_sync!(test_node_label_lcp_with_prefix_label);
fn test_node_label_lcp_with_prefix_label<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(01u64 << 62), 2u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(01u64 << 62), 3u32);
    let expected = label_1;
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with prefix label, not equal to prefix label!"
    );
    assert!(
        label_2.get_longest_common_prefix::<TC>(label_1) == expected,
        "Longest common substring with prefix label, not equal to prefix label!"
    );
}

test_config_sync!(test_node_label_lcp_with_self_leading_zero);
fn test_node_label_lcp_with_self_leading_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1000000u64 << 56), 9u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with self with leading zero, not equal to itself!"
    )
}

test_config_sync!(test_node_label_lcp_self_prefix_leading_one);
fn test_node_label_lcp_self_prefix_leading_one<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b1000u64 << 60), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1000u64 << 60), 4u32);
    let computed = label_1.get_longest_common_prefix::<TC>(label_2);
    assert!(
        computed == expected,
        "{}",
        "Longest common substring with self with leading one, not equal to itself! Expected: {expected:?}, Got: {computed:?}"
    )
}

test_config_sync!(test_node_label_lcp_self_prefix_leading_zero);
fn test_node_label_lcp_self_prefix_leading_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 7u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 7u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with self with leading zero, not equal to itself!"
    )
}

test_config_sync!(test_node_label_lcp_other_one);
fn test_node_label_lcp_other_one<TC: Configuration>() {
    let label_1: NodeLabel = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 63), 1u32);
    let computed = label_1.get_longest_common_prefix::<TC>(label_2);
    assert!(
        computed == expected,
        "{}",
        "Longest common substring with other with leading one, not equal to expected! Expected: {expected:?}, Computed: {computed:?}"
    )
}

test_config_sync!(test_node_label_lcp_other_zero);
fn test_node_label_lcp_other_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1u64 << 62), 2u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with other with leading zero, not equal to expected!"
    )
}

test_config_sync!(test_node_label_lcp_empty);
fn test_node_label_lcp_empty<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b10000000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b0u64), 0u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring should be empty!"
    )
}

test_config_sync!(test_node_label_lcp_some_leading_one);
fn test_node_label_lcp_some_leading_one<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 60), 4u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with other with leading one, not equal to expected!"
    )
}

test_config_sync!(test_node_label_lcp_some_leading_zero);
fn test_node_label_lcp_some_leading_zero<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b11010000u64 << 55), 9u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b11011000u64 << 55), 9u32);
    let expected = NodeLabel::new(byte_arr_from_u64(0b1101u64 << 59), 5u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with other with leading zero, not equal to expected!"
    )
}

test_config_sync!(test_get_dir_large);
fn test_get_dir_large<TC: Configuration>() {
    for i in 0..256 {
        let label_1 = random_label();
        let pos = i;

        let label_2 = label_1.get_prefix(pos);

        let expected = PrefixOrdering::from(label_1.get_bit_at(pos).unwrap());
        let computed = label_2.get_prefix_ordering(label_1);
        assert!(
            computed == expected,
            "{}",
            "Direction not equal to expected. Node = {label_1:?}, prefix = {label_2:?}"
        )
    }
}

test_config_sync!(test_node_label_lcp_with_self_leading_one);
fn test_node_label_lcp_with_self_leading_one<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    let expected = NodeLabel::new(byte_arr_from_u64(10000000u64 << 56), 8u32);
    assert!(
        label_1.get_longest_common_prefix::<TC>(label_2) == expected,
        "Longest common substring with self with leading one, not equal to itself!"
    )
}

test_config_sync!(test_is_prefix_of);
fn test_is_prefix_of<TC: Configuration>() {
    let label_1 = NodeLabel::new(byte_arr_from_u64(0b01u64 << 62), 4u32);
    let label_2 = NodeLabel::new(byte_arr_from_u64(0b010u64 << 61), 5u32);
    let label_3 = NodeLabel::new(byte_arr_from_u64(0b0u64), 4u32);

    assert_eq!(TC::empty_label().is_prefix_of(&label_1), true);
    assert_eq!(TC::empty_label().is_prefix_of(&label_2), true);
    assert_eq!(TC::empty_label().is_prefix_of(&label_3), true);

    assert_eq!(label_1.is_prefix_of(&label_1), true);
    assert_eq!(label_2.is_prefix_of(&label_2), true);
    assert_eq!(label_3.is_prefix_of(&label_3), true);

    assert_eq!(label_1.is_prefix_of(&label_2), true);

    assert_eq!(label_1.is_prefix_of(&label_3), false);
    assert_eq!(label_2.is_prefix_of(&label_1), false);
    assert_eq!(label_2.is_prefix_of(&label_3), false);
    assert_eq!(label_3.is_prefix_of(&label_1), false);
    assert_eq!(label_3.is_prefix_of(&label_2), false);
}
