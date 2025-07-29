use super::{Direction, NodeLabel};

#[derive(Debug, Eq, PartialEq)]
pub enum TreeNodeError {
    InvalidDirection(Direction),

    NoDirection(NodeLabel, Option<NodeLabel>),

    NoChildAtEpoch(u64, Direction),

    ParentNextEpochInvalid(u64),

    HashUpdateOrderInconsistent,

    NonexistentAtEpoch(NodeLabel, u64),

    NoStateAtEpoch(NodeLabel, u64),

    DigestDeserializationFailed(String),
}

impl std::error::Error for TreeNodeError {}

impl std::fmt::Display for TreeNodeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::InvalidDirection(dir) => {
                write!(f, "AKD is based on a binary tree. No child with a given direction: {dir:?}")
            },
            Self::NoDirection(node_label, child_label) => {
                let mut to_print = format!("no direction provided for the node {node_label:?}");

                if let Some(child_label) = child_label {
                    let child_str = format!(" and child {child_label:?}");
                    to_print.push_str(&child_str);
                }
                write!(f, "{to_print}")
            },
            Self::NoChildAtEpoch(epoch, direction) => {
                write!(f, "no node in direction {direction:?} at epoch {epoch}")
            },
            Self::ParentNextEpochInvalid(epoch) => {
                write!(f, "Next epoch of parent is invalid, epoch = {epoch}")
            },
            Self::HashUpdateOrderInconsistent => {
                write!(f, "Hash update in parent only allowed after node is inserted")
            },
            Self::NonexistentAtEpoch(label, epoch) => {
                write!(f, "This node, labelled {label:?}, did not exist at epoch {epoch:?}.")
            },
            Self::NoStateAtEpoch(label, epoch) => {
                write!(f, "This node, labelled {label:?}, did not exist at epoch {epoch:?}.")
            },
            Self::DigestDeserializationFailed(inner_error) => {
                write!(f, "Encountered a serialization error {inner_error}")
            },
        }
    }
}
