use super::{AzksElement, Configuration, NodeLabel, PrefixOrdering};
use std::cmp::{Ord, Ordering};

#[derive(Debug, Clone, PartialEq)]
pub(crate) enum AzksElementSet {
    BinarySearchable(Vec<AzksElement>),
    Unsorted(Vec<AzksElement>),
}

impl core::ops::Deref for AzksElementSet {
    type Target = Vec<AzksElement>;

    fn deref(&self) -> &Self::Target {
        match self {
            AzksElementSet::BinarySearchable(nodes) => nodes,
            AzksElementSet::Unsorted(nodes) => nodes,
        }
    }
}

impl From<Vec<AzksElement>> for AzksElementSet {
    fn from(mut nodes: Vec<AzksElement>) -> Self {
        if !nodes.is_empty()
            && nodes.iter().all(|node| node.label.label_len == nodes[0].label.label_len)
        {
            nodes.sort_unstable();
            AzksElementSet::BinarySearchable(nodes)
        } else {
            AzksElementSet::Unsorted(nodes)
        }
    }
}

impl AzksElementSet {
    pub(crate) fn partition(self, prefix_label: NodeLabel) -> (AzksElementSet, AzksElementSet) {
        match self {
            AzksElementSet::BinarySearchable(mut nodes) => {
                let partition_point = nodes.partition_point(|candidate| {
                    match prefix_label.get_prefix_ordering(candidate.label) {
                        PrefixOrdering::WithZero | PrefixOrdering::Invalid => true,
                        PrefixOrdering::WithOne => false,
                    }
                });

                let right = nodes.split_off(partition_point);
                let mut left = nodes;

                while left.last().map(|node| prefix_label.get_prefix_ordering(node.label))
                    == Some(PrefixOrdering::Invalid)
                {
                    left.pop();
                }

                (AzksElementSet::BinarySearchable(left), AzksElementSet::BinarySearchable(right))
            },
            AzksElementSet::Unsorted(nodes) => {
                let (left, right) =
                    nodes.into_iter().fold((vec![], vec![]), |(mut left, mut right), node| {
                        match prefix_label.get_prefix_ordering(node.label) {
                            PrefixOrdering::WithZero => left.push(node),
                            PrefixOrdering::WithOne => right.push(node),
                            PrefixOrdering::Invalid => (),
                        };
                        (left, right)
                    });
                (AzksElementSet::Unsorted(left), AzksElementSet::Unsorted(right))
            },
        }
    }

    pub(crate) fn get_longest_common_prefix<TC: Configuration>(&self) -> NodeLabel {
        match self {
            AzksElementSet::BinarySearchable(nodes) => match (nodes.first(), nodes.last()) {
                (Some(first), Some(last)) => {
                    first.label.get_longest_common_prefix::<TC>(last.label)
                },
                _ => TC::empty_label(),
            },
            AzksElementSet::Unsorted(nodes) => {
                if nodes.is_empty() {
                    return TC::empty_label();
                }
                nodes.iter().skip(1).fold(nodes[0].label, |acc, node| {
                    node.label.get_longest_common_prefix::<TC>(acc)
                })
            },
        }
    }

    pub(crate) fn contains_prefix(&self, prefix_label: &NodeLabel) -> bool {
        match self {
            AzksElementSet::BinarySearchable(nodes) => nodes
                .binary_search_by(|candidate| {
                    match prefix_label.label_len == 0 || prefix_label.is_prefix_of(&candidate.label)
                    {
                        true => Ordering::Equal,
                        false => candidate.label.label_val.cmp(&prefix_label.label_val),
                    }
                })
                .is_ok(),
            AzksElementSet::Unsorted(nodes) => {
                nodes.iter().any(|node| prefix_label.is_prefix_of(&node.label))
            },
        }
    }
}
