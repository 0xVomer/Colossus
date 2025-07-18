use super::{Direction, NodeLabel};

/// Errors thrown by TreeNodes
#[derive(Debug, Eq, PartialEq)]
pub enum TreeNodeError {
    /// At the moment the only supported dirs are 0, 1
    InvalidDirection(Direction),
    /// No direction provided for the node.
    /// Second parameter is the label of the child attempted to be set
    /// -- if there is one, otherwise it is None.
    NoDirection(NodeLabel, Option<NodeLabel>),
    /// The node didn't have a child in the given epoch
    NoChildAtEpoch(u64, Direction),
    /// The next epoch of this node's parent was invalid
    ParentNextEpochInvalid(u64),
    /// The hash of a parent was attempted to be updated, without setting the calling node as a child.
    HashUpdateOrderInconsistent,
    /// The node did not exist at epoch
    NonexistentAtEpoch(NodeLabel, u64),
    /// The state of a node did not exist at a given epoch
    NoStateAtEpoch(NodeLabel, u64),
    /// Failed to deserialize a digest
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
                // Add child info if given.
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
