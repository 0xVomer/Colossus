//! Forked Code from Meta Platforms AKD repository: https://github.com/facebook/akd
//! An implementation of an append-only zero knowledge set

mod element;
mod element_set;
mod parallelism;

#[cfg(test)]
mod tests;

use super::{
    ARITY, Digest, Direction, EMPTY_DIGEST, LookupInfo, NodeLabel, PrefixOrdering, SizeOf,
    auditor::audit_verify,
    errors::{AkdError, DirectoryError, ParallelismError, TreeNodeError},
    proofs::{
        AppendOnlyProof, MembershipProof, NonMembershipProof, SiblingProof, SingleAppendOnlyProof,
    },
    serde_helpers::{azks_value_hex_deserialize, azks_value_hex_serialize},
    tree_node::{
        NodeHashingMode, NodeKey, TreeNode, TreeNodeType, TreeNodeWithPreviousValue,
        new_interior_node, new_leaf_node, new_root_node, node_to_azks_value, node_to_label,
    },
    utils::byte_arr_from_u64,
    verify::{verify_membership_for_tests_only, verify_nonmembership_for_tests_only},
};
use crate::{
    configuration::Configuration,
    log::{debug, info},
    storage::{
        manager::StorageManager,
        traits::{Database, Storable},
        types::StorageType,
    },
};
use async_recursion::async_recursion;
pub use element::{AzksElement, AzksValue, AzksValueWithEpoch, TOMBSTONE};
use element_set::AzksElementSet;
pub use parallelism::{AzksParallelismConfig, AzksParallelismOption};
use serde::{Deserialize, Serialize};
use std::{marker::Sync, sync::Arc};
// #[cfg(feature = "greedy_lookup_preload")]
// use std::collections::HashSet;
//
/// The default azks key
pub const DEFAULT_AZKS_KEY: u8 = 1u8;

async fn tic_toc<T>(f: impl core::future::Future<Output = T>) -> (T, Option<f64>) {
    let tic = std::time::Instant::now();
    let out = f.await;
    let toc = std::time::Instant::now() - tic;
    (out, Some(toc.as_secs_f64()))
}

/// An azks is built both by the [crate::directory::Directory] and the auditor.
/// However, both constructions have very minor differences, and the insert
/// mode enum is used to differentiate between the two.
#[derive(Debug, Clone, Copy)]
pub enum InsertMode {
    /// The regular construction of the the tree.
    Directory,
    /// The auditor's mode of constructing the tree - last epochs of leaves are
    /// not included in node hashes.
    Auditor,
}

impl From<InsertMode> for NodeHashingMode {
    fn from(mode: InsertMode) -> Self {
        match mode {
            InsertMode::Directory => NodeHashingMode::WithLeafEpoch,
            InsertMode::Auditor => NodeHashingMode::NoLeafEpoch,
        }
    }
}

type AppendOnlyHelper = (Vec<AzksElement>, Vec<AzksElement>);

/// An append-only zero knowledge set, the data structure used to efficiently implement
/// a auditable key directory.
#[derive(Clone, Debug, Eq, PartialEq, Hash, PartialOrd, Ord, Deserialize, Serialize)]
#[serde(bound = "")]
pub struct Azks {
    /// The latest complete epoch
    pub latest_epoch: u64,
    /// The number of nodes is the total size of this tree
    pub num_nodes: u64,
}

impl SizeOf for Azks {
    fn size_of(&self) -> usize {
        std::mem::size_of::<u64>() * 2
    }
}

impl Storable for Azks {
    type StorageKey = u8;

    fn data_type() -> StorageType {
        StorageType::Azks
    }

    fn get_id(&self) -> u8 {
        DEFAULT_AZKS_KEY
    }

    fn get_full_binary_key_id(key: &u8) -> Vec<u8> {
        vec![StorageType::Azks as u8, *key]
    }

    fn key_from_full_binary(bin: &[u8]) -> Result<u8, String> {
        if bin.is_empty() || bin[0] != StorageType::Azks as u8 {
            return Err("Not an AZKS key".to_string());
        }
        Ok(DEFAULT_AZKS_KEY)
    }
}

unsafe impl Sync for Azks {}

impl Azks {
    /// Creates a new azks
    pub async fn new<TC: Configuration, S: Database>(
        storage: &StorageManager<S>,
    ) -> Result<Self, AkdError> {
        let root_node = new_root_node::<TC>();
        root_node.write_to_storage(storage, true).await?;

        let azks = Azks { latest_epoch: 0, num_nodes: 1 };

        Ok(azks)
    }

    /// Insert a batch of new leaves.
    pub async fn batch_insert_nodes<TC: Configuration, S: Database + 'static>(
        &mut self,
        storage: &StorageManager<S>,
        nodes: Vec<AzksElement>,
        insert_mode: InsertMode,
        parallelism_config: AzksParallelismConfig,
    ) -> Result<(), AkdError> {
        let azks_element_set = AzksElementSet::from(nodes);

        // preload the nodes that we will visit during the insertion
        let (fallible_load_count, time_s) =
            tic_toc(self.preload_nodes(storage, &azks_element_set, parallelism_config)).await;
        let load_count = fallible_load_count?;
        if let Some(time) = time_s {
            info!("Preload of nodes for insert ({} objects loaded), took {} s", load_count, time,);
        } else {
            info!("Preload of nodes for insert ({} objects loaded) completed.", load_count);
        }

        // increment the current epoch
        self.increment_epoch();

        if !azks_element_set.is_empty() {
            // call recursive batch insert on the root
            let (root_node, is_new, num_inserted) = Self::recursive_batch_insert_nodes::<TC, _>(
                storage,
                Some(NodeLabel::root()),
                azks_element_set,
                self.latest_epoch,
                insert_mode,
                parallelism_config.insertion.get_parallel_levels(),
            )
            .await?;
            root_node.write_to_storage(storage, is_new).await?;

            // update the number of nodes
            self.num_nodes += num_inserted;

            info!("Batch insert completed ({} new nodes)", num_inserted);
        }

        Ok(())
    }

    /// Inserts a batch of leaves recursively from a given node label. Note: it
    /// is the caller's responsibility to write the returned node to storage.
    /// This is done so that the caller may set the 'parent' field of a node
    /// before it is written to storage. The is_new flag indicates whether the
    /// returned node is new or not.
    #[async_recursion]
    #[allow(clippy::multiple_bound_locations)]
    pub(crate) async fn recursive_batch_insert_nodes<TC: Configuration, S: Database + 'static>(
        storage: &StorageManager<S>,
        node_label: Option<NodeLabel>,
        azks_element_set: AzksElementSet,
        epoch: u64,
        insert_mode: InsertMode,
        parallel_levels: Option<u8>,
    ) -> Result<(TreeNode, bool, u64), AkdError> {
        // Phase 1: Obtain the current root node of this subtree. If the node is
        // new, mark it as so and count it towards the number of inserted nodes.
        let mut current_node;
        let is_new;
        let mut num_inserted;

        match (node_label, &azks_element_set[..]) {
            (Some(node_label), _) => {
                // Case 1: The node label is not None, meaning that there was an
                // existing node at this level of the tree.
                let mut existing_node =
                    TreeNode::get_from_storage(storage, &NodeKey(node_label), epoch).await?;

                // compute the longest common prefix between all nodes in the
                // node set and the current node, and check if new nodes
                // have a longest common prefix shorter than the current node.
                let set_lcp_label = azks_element_set.get_longest_common_prefix::<TC>();
                let lcp_label = node_label.get_longest_common_prefix::<TC>(set_lcp_label);
                if lcp_label.get_len() < node_label.get_len() {
                    // Case 1a: The existing node needs to be decompressed, by
                    // pushing it down one level (away from root) in the tree
                    // and replacing it with a new node whose label is equal to
                    // the longest common prefix.
                    current_node = new_interior_node::<TC>(lcp_label, epoch);
                    current_node.set_child(&mut existing_node)?;
                    existing_node.write_to_storage(storage, false).await?;
                    is_new = true;
                    num_inserted = 1;
                } else {
                    // Case 1b: The existing node does not need to be
                    // decompressed as its label is longer than or equal to the
                    // longest common prefix of the node set.
                    current_node = existing_node;
                    is_new = false;
                    num_inserted = 0;
                }
            },
            (None, [node]) => {
                // Case 2: The node label is None and the node set has a
                // single element, meaning that a new leaf node should be
                // created to represent the element.
                current_node = new_leaf_node::<TC>(node.label, &node.value, epoch);
                is_new = true;
                num_inserted = 1;
            },
            (None, _) => {
                // Case 3: The node label is None and the insertion still has
                // multiple elements, meaning that a new interior node should be
                // created with a label equal to the longest common prefix of
                // the node set.
                let lcp_label = azks_element_set.get_longest_common_prefix::<TC>();
                current_node = new_interior_node::<TC>(lcp_label, epoch);
                is_new = true;
                num_inserted = 1;
            },
        }

        // Phase 2: Partition the node set based on the direction the leaf
        // nodes are located in with respect to the current node and call this
        // function recursively on the left and right child nodes. The current
        // node is updated with the new child nodes.
        let (left_azks_element_set, right_azks_element_set) =
            azks_element_set.partition(current_node.label);
        let child_parallel_levels =
            parallel_levels.and_then(|x| if x <= 1 { None } else { Some(x - 1) });

        // handle the left child
        let maybe_handle = if !left_azks_element_set.is_empty() {
            let storage_clone = storage.clone();
            let left_child_label = current_node.get_child_label(Direction::Left);
            let left_future = async move {
                Azks::recursive_batch_insert_nodes::<TC, _>(
                    &storage_clone,
                    left_child_label,
                    left_azks_element_set,
                    epoch,
                    insert_mode,
                    child_parallel_levels,
                )
                .await
            };

            if parallel_levels.is_some() {
                // spawn a task and return the handle if there are still levels
                // to be processed in parallel
                Some(tokio::task::spawn(left_future))
            } else {
                // else handle the left child in the current task
                let (mut left_node, left_is_new, left_num_inserted) = left_future.await?;

                current_node.set_child(&mut left_node)?;
                left_node.write_to_storage(storage, left_is_new).await?;
                num_inserted += left_num_inserted;
                None
            }
        } else {
            None
        };

        // handle the right child in the current task
        if !right_azks_element_set.is_empty() {
            let right_child_label = current_node.get_child_label(Direction::Right);
            let (mut right_node, right_is_new, right_num_inserted) =
                Azks::recursive_batch_insert_nodes::<TC, _>(
                    storage,
                    right_child_label,
                    right_azks_element_set,
                    epoch,
                    insert_mode,
                    child_parallel_levels,
                )
                .await?;

            current_node.set_child(&mut right_node)?;
            right_node.write_to_storage(storage, right_is_new).await?;
            num_inserted += right_num_inserted;
        }

        // join on the handle for the left child, if present
        if let Some(handle) = maybe_handle {
            let (mut left_node, left_is_new, left_num_inserted) = handle
                .await
                .map_err(|e| AkdError::Parallelism(ParallelismError::JoinErr(e.to_string())))??;
            current_node.set_child(&mut left_node)?;
            left_node.write_to_storage(storage, left_is_new).await?;
            num_inserted += left_num_inserted;
        }

        // Phase 3: Update the hash of the current node and return it along with
        // the number of nodes inserted.
        current_node
            .update_hash::<TC, _>(storage, NodeHashingMode::from(insert_mode))
            .await?;

        Ok((current_node, is_new, num_inserted))
    }

    // #[cfg(feature = "greedy_lookup_preload")]
    // async fn get_next_node_in_child_path_from_cache<S: Database + Send + Sync>(
    //     &self,
    //     storage: &StorageManager<S>,
    //     node: &TreeNode,
    //     target: &NodeLabel,
    // ) -> Option<TreeNode> {
    //     match (node.left_child, node.right_child) {
    //         (Some(l), _) if l.is_prefix_of(target) => {
    //             match storage
    //                 .get_from_cache_only::<crate::tree_node::TreeNodeWithPreviousValue>(&NodeKey(l))
    //                 .await
    //             {
    //                 Some(crate::storage::types::DbRecord::TreeNode(tnpv)) => {
    //                     tnpv.determine_node_to_get(self.latest_epoch).ok()
    //                 },
    //                 _ => None,
    //             }
    //         },
    //         (_, Some(r)) if r.is_prefix_of(target) => {
    //             match storage
    //                 .get_from_cache_only::<crate::tree_node::TreeNodeWithPreviousValue>(&NodeKey(r))
    //                 .await
    //             {
    //                 Some(crate::storage::types::DbRecord::TreeNode(tnpv)) => {
    //                     tnpv.determine_node_to_get(self.latest_epoch).ok()
    //                 },
    //                 _ => None,
    //             }
    //         },
    //         _ => None,
    //     }
    // }

    /// Builds all the POSSIBLE paths along the route from root node to
    /// leaf node. This will be grossly over-estimating the true size of the
    /// tree and the number of nodes required to be fetched, however
    /// it allows a single batch-get call in necessary scenarios
    // #[cfg(feature = "greedy_lookup_preload")]
    // pub(crate) async fn build_lookup_maximal_node_set<S: Database + Send + Sync>(
    //     &self,
    //     storage: &StorageManager<S>,
    //     li: LookupInfo,
    // ) -> Result<HashSet<NodeLabel>, AkdError> {
    //     let mut results = HashSet::new();
    //     let labels = [li.existent_label, li.marker_label, li.non_existent_label];

    //     let root_node: TreeNode =
    //         TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), self.latest_epoch)
    //             .await?;

    //     for label in labels {
    //         let mut cnode = root_node.clone();
    //         // walk through the cache to find the next node in the tree which isn't already loaded
    //         while let Some(node) =
    //             self.get_next_node_in_child_path_from_cache(storage, &cnode, &label).await
    //         {
    //             cnode = node;
    //         }
    //         // load the rest of the nodes in the path, as soon as a child node can't be resolved. In the worst-case
    //         // this is loading every possible node on the path (i.e. uninitialized cache)
    //         for len in cnode.label.label_len..256 {
    //             results.insert(label.get_prefix(len));
    //         }
    //     }

    //     Ok(results)
    // }

    /// Preload for a single lookup operation by loading all the nodes along
    /// the direct path, and the children of resolved nodes on the path. This
    /// minimizes the number of batch_get operations to the storage layer which are
    /// called
    // #[cfg(feature = "greedy_lookup_preload")]
    // pub(crate) async fn greedy_preload_lookup_nodes<S: Database + Send + Sync>(
    //     &self,
    //     storage: &StorageManager<S>,
    //     lookup_info: LookupInfo,
    // ) -> Result<u64, AkdError> {
    //     let mut count = 0u64;
    //     let mut requested_count = 0u64;

    //     // First try and load ALL possible nodes on the direct paths between the root and the target labels
    //     // For a lookup proof, there's 3 targets
    //     //
    //     // * existent_label
    //     // * marker_label
    //     // * non_existent_label
    //     let nodes = self
    //         .build_lookup_maximal_node_set(storage, lookup_info)
    //         .await?
    //         .into_iter()
    //         .map(NodeKey)
    //         .collect::<Vec<_>>();
    //     requested_count += nodes.len() as u64;

    //     let nodes = TreeNode::batch_get_from_storage(storage, &nodes, self.latest_epoch).await?;
    //     count += nodes.len() as u64;

    //     // Now load the children of the nodes resolved on the direct path, which
    //     // for non-already-loaded children will be the siblings necessary to
    //     // generate the required proof structs.
    //     let children = nodes
    //         .into_iter()
    //         .flat_map(|node| match (node.left_child, node.right_child) {
    //             (Some(l), Some(r)) => vec![NodeKey(l), NodeKey(r)],
    //             _ => vec![],
    //         })
    //         .collect::<Vec<_>>();
    //     requested_count += children.len() as u64;

    //     let children =
    //         TreeNode::batch_get_from_storage(storage, &children, self.latest_epoch).await?;
    //     count += children.len() as u64;

    //     log::info!("Greedy lookup proof preloading loaded {} of {} nodes", count, requested_count);

    //     Ok(count)
    // }

    pub(crate) async fn preload_lookup_nodes<S: Database + Send + Sync + 'static>(
        &self,
        storage: &StorageManager<S>,
        lookup_infos: &[LookupInfo],
        marker_labels: Option<Vec<NodeLabel>>,
    ) -> Result<u64, AkdError> {
        // Collect lookup labels needed and convert them into Nodes for preloading.
        let lookup_nodes: Vec<AzksElement> = lookup_infos
            .iter()
            .flat_map(|li| vec![li.existent_label, li.marker_label, li.non_existent_label])
            .chain(marker_labels.unwrap_or_default().iter().cloned())
            .map(|l| AzksElement { label: l, value: AzksValue(EMPTY_DIGEST) })
            .collect();

        // Load nodes without parallelism, since multiple lookups could be
        // happening and parallelism might consume too many resources.
        self.preload_nodes(
            storage,
            &AzksElementSet::from(lookup_nodes),
            AzksParallelismConfig::disabled(),
        )
        .await
    }

    /// Preloads given nodes using breadth-first search.
    pub(crate) async fn preload_nodes<S: Database + 'static>(
        &self,
        storage: &StorageManager<S>,
        azks_element_set: &AzksElementSet,
        parallelism_config: AzksParallelismConfig,
    ) -> Result<u64, AkdError> {
        if !storage.has_cache() {
            info!("No cache found, skipping preload");
            return Ok(0);
        }

        // We clone and wrap AzksElementSet in an Arc so that it can be passed
        // to another tokio task safely. The element set does not even need to
        // be cloned, since preloading never modifies it. However, a clone helps
        // avoid propagating the responsibility of creating an Arc to the caller.
        // We can consider doing away with it in future.
        let azks_element_set = Arc::new(azks_element_set.clone());
        let epoch = self.get_latest_epoch();
        let node_keys = vec![NodeKey(NodeLabel::root())];
        let parallel_levels = parallelism_config.preload.get_parallel_levels();

        let load_count = Azks::recursive_preload_nodes(
            storage,
            azks_element_set,
            epoch,
            node_keys,
            parallel_levels,
        )
        .await?;

        debug!("Preload of tree ({} nodes) completed", load_count);

        Ok(load_count)
    }

    #[async_recursion]
    #[allow(clippy::multiple_bound_locations)]
    async fn recursive_preload_nodes<S: Database + 'static>(
        storage: &StorageManager<S>,
        azks_element_set: Arc<AzksElementSet>,
        epoch: u64,
        node_keys: Vec<NodeKey>,
        parallel_levels: Option<u8>,
    ) -> Result<u64, AkdError> {
        if node_keys.is_empty() {
            return Ok(0);
        }

        let nodes = TreeNode::batch_get_from_storage(storage, &node_keys, epoch).await?;
        let mut load_count = node_keys.len() as u64;

        // Now that states are loaded in the cache, we can read and access them.
        // Note, we perform directional loads to avoid accessing remote storage
        // individually for each node's state.
        let mut next_nodes: Vec<NodeKey> = nodes
            .iter()
            .filter(|node| azks_element_set.contains_prefix(&node.label))
            .flat_map(|node| {
                [Direction::Left, Direction::Right]
                    .iter()
                    .filter_map(|dir| node.get_child_label(*dir).map(NodeKey))
                    .collect::<Vec<NodeKey>>()
            })
            .collect();

        if parallel_levels.is_some() {
            // Divide work into two equivalent chunks.
            let right_next_nodes = next_nodes.split_off(next_nodes.len() / 2);
            let left_next_nodes = next_nodes;
            let child_parallel_levels =
                parallel_levels.and_then(|x| if x <= 1 { None } else { Some(x - 1) });

            // Handle the left chunk in a different tokio task.
            let storage_clone = storage.clone();
            let azks_element_set_clone = azks_element_set.clone();
            let left_future = async move {
                Azks::recursive_preload_nodes(
                    &storage_clone,
                    azks_element_set_clone,
                    epoch,
                    left_next_nodes,
                    child_parallel_levels,
                )
                .await
            };
            let handle = tokio::task::spawn(left_future);

            // Handle the right chunk in the current task.
            let right_load_count = Azks::recursive_preload_nodes(
                storage,
                azks_element_set,
                epoch,
                right_next_nodes,
                child_parallel_levels,
            )
            .await?;
            load_count += right_load_count;

            // Join on the handle for the left chunk.
            let left_load_count = handle
                .await
                .map_err(|e| AkdError::Parallelism(ParallelismError::JoinErr(e.to_string())))??;
            load_count += left_load_count;
        } else {
            // Perform all the work in the current task.
            let next_load_count = Azks::recursive_preload_nodes(
                storage,
                azks_element_set,
                epoch,
                next_nodes,
                parallel_levels,
            )
            .await?;
            load_count += next_load_count;
        }

        Ok(load_count)
    }

    /// Returns the Merkle membership proof for the trie as it stood at epoch
    // Assumes the verifier has access to the root at epoch
    #[tracing::instrument(skip_all)]
    pub async fn get_membership_proof<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<MembershipProof, AkdError> {
        let (_, proof) =
            self.get_lcp_node_label_with_membership_proof::<TC, _>(storage, label).await?;
        Ok(proof)
    }

    /// In a compressed trie, the proof consists of the longest prefix
    /// of the label that is included in the trie, as well as its children, to show that
    /// none of the children is equal to the given label.
    #[tracing::instrument(skip_all)]
    pub async fn get_non_membership_proof<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<NonMembershipProof, AkdError> {
        let (lcp_node_label, longest_prefix_membership_proof) =
            self.get_lcp_node_label_with_membership_proof::<TC, _>(storage, label).await?;
        let lcp_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(lcp_node_label), self.get_latest_epoch())
                .await?;
        let longest_prefix = lcp_node.label;

        let empty_azks_element = AzksElement {
            label: TC::empty_label(),
            value: TC::empty_node_hash(),
        };

        let mut longest_prefix_children = [empty_azks_element; ARITY];
        for (i, dir) in [Direction::Left, Direction::Right].iter().enumerate() {
            match lcp_node.get_child_node(storage, *dir, self.latest_epoch).await? {
                None => {
                    longest_prefix_children[i] = empty_azks_element;
                },
                Some(child) => {
                    let unwrapped_child: TreeNode = TreeNode::get_from_storage(
                        storage,
                        &NodeKey(child.label),
                        self.get_latest_epoch(),
                    )
                    .await?;
                    longest_prefix_children[i] = AzksElement {
                        label: unwrapped_child.label,
                        value: node_to_azks_value::<TC>(
                            &Some(unwrapped_child),
                            NodeHashingMode::WithLeafEpoch,
                        ),
                    };
                },
            }
        }

        Ok(NonMembershipProof {
            label,
            longest_prefix,
            longest_prefix_children,
            longest_prefix_membership_proof,
        })
    }

    /// An append-only proof for going from `start_epoch` to `end_epoch` consists of roots of subtrees
    /// the azks tree that remain unchanged from `start_epoch` to `end_epoch` and the leaves inserted into the
    /// tree after `start_epoch` and  up until `end_epoch`.
    /// If there is no errors, this function returns an `Ok` result, containing the
    ///  append-only proof and otherwise, it returns an [AkdError].
    ///
    /// **RESTRICTIONS**: Note that `start_epoch` and `end_epoch` are valid only when the following are true
    /// * `start_epoch` <= `end_epoch`
    /// * `start_epoch` and `end_epoch` are both existing epochs of this AZKS
    #[tracing::instrument(skip_all)]
    pub async fn get_append_only_proof<TC: Configuration, S: Database + 'static>(
        &self,
        storage: &StorageManager<S>,
        start_epoch: u64,
        end_epoch: u64,
        parallelism_config: AzksParallelismConfig,
    ) -> Result<AppendOnlyProof, AkdError> {
        let latest_epoch = self.get_latest_epoch();
        if latest_epoch < end_epoch || end_epoch <= start_epoch {
            return Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Start epoch must be less than end epoch, and end epoch must be at most the latest epoch. \
                Start epoch: {start_epoch}, end epoch: {end_epoch}, latest_epoch: {latest_epoch}."
            ))));
        }

        let mut proofs = Vec::<SingleAppendOnlyProof>::new();
        let mut epochs = Vec::<u64>::new();
        // Suppose the epochs start_epoch and end_epoch exist in the set.
        // This function should return the proof that nothing was removed/changed from the tree
        // between these epochs.
        let (fallible_load_count, time_s) = tic_toc(self.preload_audit_nodes::<_>(
            storage,
            latest_epoch,
            start_epoch,
            end_epoch,
            parallelism_config,
        ))
        .await;
        let load_count = fallible_load_count?;
        if let Some(time) = time_s {
            info!("Preload of nodes for audit ({} objects loaded), took {} s", load_count, time,);
        } else {
            info!("Preload of nodes for audit ({} objects loaded) completed.", load_count);
        }
        storage.log_metrics().await;

        let node =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), latest_epoch).await?;

        for ep in start_epoch..end_epoch {
            let (unchanged, leaves) = Self::get_append_only_proof_helper::<TC, _>(
                latest_epoch,
                storage,
                node.clone(),
                ep,
                ep + 1,
                0,
                parallelism_config.insertion.get_parallel_levels(),
            )
            .await?;
            info!("Generated audit proof for {} -> {}", ep, ep + 1);
            proofs.push(SingleAppendOnlyProof {
                inserted: leaves,
                unchanged_nodes: unchanged,
            });
            epochs.push(ep);
        }

        Ok(AppendOnlyProof { proofs, epochs })
    }

    async fn preload_audit_nodes<S: Database + 'static>(
        &self,
        storage: &StorageManager<S>,
        latest_epoch: u64,
        start_epoch: u64,
        end_epoch: u64,
        parallelism_config: AzksParallelismConfig,
    ) -> Result<u64, AkdError> {
        if !storage.has_cache() {
            info!("No cache found, skipping preload");
            return Ok(0);
        }

        let node_keys = vec![NodeKey(NodeLabel::root())];
        let parallel_levels = parallelism_config.preload.get_parallel_levels();

        let load_count = Azks::recursive_preload_audit_nodes(
            storage,
            node_keys,
            latest_epoch,
            start_epoch,
            end_epoch,
            parallel_levels,
        )
        .await?;

        Ok(load_count)
    }

    #[async_recursion]
    #[allow(clippy::multiple_bound_locations)]
    async fn recursive_preload_audit_nodes<S: Database + 'static>(
        storage: &StorageManager<S>,
        node_keys: Vec<NodeKey>,
        latest_epoch: u64,
        start_epoch: u64,
        end_epoch: u64,
        parallel_levels: Option<u8>,
    ) -> Result<u64, AkdError> {
        if node_keys.is_empty() {
            return Ok(0);
        }

        let nodes = TreeNode::batch_get_from_storage(storage, &node_keys, latest_epoch).await?;
        let mut load_count = node_keys.len() as u64;

        let mut next_nodes: Vec<NodeKey> = nodes
            .iter()
            .filter(|node| {
                node.node_type != TreeNodeType::Leaf
                    && node.get_latest_epoch() > start_epoch
                    && node.min_descendant_epoch <= end_epoch
            })
            .flat_map(|node| {
                [Direction::Left, Direction::Right]
                    .iter()
                    .filter_map(|dir| node.get_child_label(*dir).map(NodeKey))
                    .collect::<Vec<NodeKey>>()
            })
            .collect();

        if parallel_levels.is_some() {
            // Divide work into two equivalent chunks.
            let right_next_nodes = next_nodes.split_off(next_nodes.len() / 2);
            let left_next_nodes = next_nodes;
            let child_parallel_levels =
                parallel_levels.and_then(|x| if x <= 1 { None } else { Some(x - 1) });

            // Handle the left chunk in a different tokio task.
            let storage_clone = storage.clone();
            let left_future = async move {
                Azks::recursive_preload_audit_nodes(
                    &storage_clone,
                    left_next_nodes,
                    latest_epoch,
                    start_epoch,
                    end_epoch,
                    child_parallel_levels,
                )
                .await
            };
            let handle = tokio::task::spawn(left_future);

            // Handle the right chunk in the current task.
            let right_load_count = Azks::recursive_preload_audit_nodes(
                storage,
                right_next_nodes,
                latest_epoch,
                start_epoch,
                end_epoch,
                child_parallel_levels,
            )
            .await?;
            load_count += right_load_count;

            // Join on the handle for the left chunk.
            let left_load_count = handle
                .await
                .map_err(|e| AkdError::Parallelism(ParallelismError::JoinErr(e.to_string())))??;
            load_count += left_load_count;
        } else {
            // Perform all the work in the current task.
            let next_load_count = Azks::recursive_preload_audit_nodes(
                storage,
                next_nodes,
                latest_epoch,
                start_epoch,
                end_epoch,
                parallel_levels,
            )
            .await?;
            load_count += next_load_count;
        }

        Ok(load_count)
    }

    #[async_recursion]
    #[allow(clippy::type_complexity)]
    #[allow(clippy::multiple_bound_locations)]
    async fn get_append_only_proof_helper<TC: Configuration, S: Database + 'static>(
        latest_epoch: u64,
        storage: &StorageManager<S>,
        node: TreeNode,
        start_epoch: u64,
        end_epoch: u64,
        level: u64,
        parallel_levels: Option<u8>,
    ) -> Result<AppendOnlyHelper, AkdError> {
        let mut unchanged = Vec::<AzksElement>::new();
        let mut leaves = Vec::<AzksElement>::new();

        if node.get_latest_epoch() <= start_epoch {
            if node.node_type == TreeNodeType::Root {
                // this is the case where the root is unchanged since the last epoch
                return Ok((unchanged, leaves));
            }
            unchanged.push(AzksElement {
                label: node.label,
                value: node_to_azks_value::<TC>(&Some(node), NodeHashingMode::WithLeafEpoch),
            });

            return Ok((unchanged, leaves));
        }

        if node.min_descendant_epoch > end_epoch {
            return Ok((unchanged, leaves));
        }

        if node.node_type == TreeNodeType::Leaf {
            leaves.push(AzksElement { label: node.label, value: node.hash });
        } else {
            let maybe_task: Option<
                tokio::task::JoinHandle<Result<(Vec<AzksElement>, Vec<AzksElement>), AkdError>>,
            > = if let Some(left_child) = node.left_child {
                if parallel_levels.map(|p| p as u64 > level).unwrap_or(false) {
                    // we can parallelise further!
                    let storage_clone = storage.clone();
                    let tsk: tokio::task::JoinHandle<Result<_, AkdError>> =
                        tokio::spawn(async move {
                            let my_storage = storage_clone;
                            let child_node = TreeNode::get_from_storage(
                                &my_storage,
                                &NodeKey(left_child),
                                latest_epoch,
                            )
                            .await?;
                            Self::get_append_only_proof_helper::<TC, _>(
                                latest_epoch,
                                &my_storage,
                                child_node,
                                start_epoch,
                                end_epoch,
                                level + 1,
                                parallel_levels,
                            )
                            .await
                        });

                    Some(tsk)
                } else {
                    // Enough parallelism already, STOP IT! Don't make me get the belt!
                    let child_node =
                        TreeNode::get_from_storage(storage, &NodeKey(left_child), latest_epoch)
                            .await?;
                    let (mut inner_unchanged, mut inner_leaf) =
                        Self::get_append_only_proof_helper::<TC, _>(
                            latest_epoch,
                            storage,
                            child_node,
                            start_epoch,
                            end_epoch,
                            level + 1,
                            parallel_levels,
                        )
                        .await?;
                    unchanged.append(&mut inner_unchanged);
                    leaves.append(&mut inner_leaf);
                    None
                }
            } else {
                None
            };

            if let Some(right_child) = node.right_child {
                let child_node =
                    TreeNode::get_from_storage(storage, &NodeKey(right_child), latest_epoch)
                        .await?;
                let (mut inner_unchanged, mut inner_leaf) =
                    Self::get_append_only_proof_helper::<TC, _>(
                        latest_epoch,
                        storage,
                        child_node,
                        start_epoch,
                        end_epoch,
                        level + 1,
                        parallel_levels,
                    )
                    .await?;
                unchanged.append(&mut inner_unchanged);
                leaves.append(&mut inner_leaf);
            }

            if let Some(task) = maybe_task {
                let (mut inner_unchanged, mut inner_leaf) = task.await.map_err(|join_err| {
                    AkdError::Parallelism(ParallelismError::JoinErr(join_err.to_string()))
                })??;
                unchanged.append(&mut inner_unchanged);
                leaves.append(&mut inner_leaf);
            }
        }
        Ok((unchanged, leaves))
    }

    /// Gets the root hash for this azks
    #[tracing::instrument(skip_all)]
    pub async fn get_root_hash<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
    ) -> Result<Digest, AkdError> {
        self.get_root_hash_safe::<TC, _>(storage, self.get_latest_epoch()).await
    }

    /// Gets the root hash of the tree at the latest epoch if the passed epoch
    /// is equal to the latest epoch. Will return an error otherwise.
    #[tracing::instrument(skip_all)]
    pub(crate) async fn get_root_hash_safe<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        epoch: u64,
    ) -> Result<Digest, AkdError> {
        if self.latest_epoch != epoch {
            // cannot retrieve information for non-latest epoch
            return Err(AkdError::Directory(DirectoryError::InvalidEpoch(format!(
                "Passed epoch ({}) was not the latest epoch ({}).",
                epoch, self.latest_epoch
            ))));
        }
        let root_node: TreeNode =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), self.latest_epoch)
                .await?;
        Ok(TC::compute_root_hash_from_val(&root_node.hash))
    }

    /// Gets the latest epoch of this azks. If an update aka epoch transition
    /// is in progress, this should return the most recent completed epoch.
    pub fn get_latest_epoch(&self) -> u64 {
        self.latest_epoch
    }

    fn increment_epoch(&mut self) {
        let epoch = self.latest_epoch + 1;
        self.latest_epoch = epoch;
    }

    /// Gets the sibling node of the passed node's child in the "opposite" of the passed direction.
    async fn get_child_azks_element_in_dir<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        curr_node: &TreeNode,
        dir: Direction,
        latest_epoch: u64,
    ) -> Result<AzksElement, AkdError> {
        // Find the sibling in the "other" direction
        let sibling = curr_node.get_child_node(storage, dir, latest_epoch).await?;
        Ok(AzksElement {
            label: node_to_label::<TC>(&sibling),
            value: node_to_azks_value::<TC>(&sibling, NodeHashingMode::WithLeafEpoch),
        })
    }

    /// This function returns the node label for the node whose label is the longest common
    /// prefix for the queried label. It also returns a membership proof for said label.
    /// This is meant to be used in both getting membership proofs and getting non-membership proofs.
    async fn get_lcp_node_label_with_membership_proof<TC: Configuration, S: Database>(
        &self,
        storage: &StorageManager<S>,
        label: NodeLabel,
    ) -> Result<(NodeLabel, MembershipProof), AkdError> {
        let mut sibling_proofs = Vec::new();
        let latest_epoch = self.get_latest_epoch();

        // Perform a traversal from the root to the node corresponding to the queried label
        let mut curr_node =
            TreeNode::get_from_storage(storage, &NodeKey(NodeLabel::root()), latest_epoch).await?;

        let mut prefix_ordering = curr_node.label.get_prefix_ordering(label);
        let mut equal = label == curr_node.label;
        let mut prev_node = curr_node.clone();
        while !equal && prefix_ordering != PrefixOrdering::Invalid {
            let direction = Direction::try_from(prefix_ordering).map_err(|_| {
                AkdError::TreeNode(TreeNodeError::NoDirection(curr_node.label, None))
            })?;
            let child = curr_node.get_child_node(storage, direction, latest_epoch).await?;
            if child.is_none() {
                // Special case, if the root node has a direction with no child there
                break;
            }

            // Find the sibling node. Note that for ARITY = 2, this does not need to be
            // an array, as it can just be a single node.
            let child_azks_element = self
                .get_child_azks_element_in_dir::<TC, _>(
                    storage,
                    &curr_node,
                    direction.other(),
                    latest_epoch,
                )
                .await?;
            sibling_proofs.push(SiblingProof {
                label: curr_node.label,
                siblings: [child_azks_element],
                direction,
            });

            prev_node = curr_node.clone();
            match child {
                Some(n) => curr_node = n,
                None => {
                    return Err(AkdError::TreeNode(TreeNodeError::NoChildAtEpoch(
                        latest_epoch,
                        direction,
                    )));
                },
            }
            prefix_ordering = curr_node.label.get_prefix_ordering(label);
            equal = label == curr_node.label;
        }

        if !equal {
            curr_node = prev_node;
            sibling_proofs.pop();
        }
        let hash_val = if curr_node.node_type == TreeNodeType::Leaf {
            AzksValue(TC::hash_leaf_with_commitment(curr_node.hash, curr_node.last_epoch).0)
        } else {
            curr_node.hash
        };

        Ok((
            curr_node.label,
            MembershipProof {
                label: curr_node.label,
                hash_val,
                sibling_proofs,
            },
        ))
    }
}
