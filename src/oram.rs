/*
A Path ORAM implementation for privacy-preserving identifier-UUID mapping
*/

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, trace};
use tracing_attributes::instrument;
use zeroize::{Zeroize, ZeroizeOnDrop};

// The depth of the ORAM tree determining the total nodes
pub const ORAM_DEPTH: usize = 20;
// The number of blocks that can be stored in each node of the tree
pub const BUCKET_SIZE: usize = 4;
// Number of dummy accesses to perform for each real access
pub const DUMMY_ACCESSES: usize = 3;

// Read/Write ORAM operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operation {
    Read,
    Write,
}

// Represents a block of data in the ORAM
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ORAMBlock {
    pub blinded_identifier: Vec<u8>,     // Blinded identifier
    pub blinded_user_id: Vec<u8>,   // Blinded UUID
}

// The main Path ORAM structure
#[derive(Debug)]
pub struct PathORAM {
    // The binary tree structure. Each node is a bucket that can hold up to BUCKET_SIZE blocks
    tree: Vec<Vec<Option<ORAMBlock>>>,
    // Maps commitment prefixes to their current path in the tree
    position_map: HashMap<[u8; 8], usize>,
    // Temporary storage for blocks during ORAM operations
    stash: Vec<ORAMBlock>,
}

impl PathORAM {
    // Initialize a new Path ORAM structure
    pub fn new() -> Self {
        // Create a binary tree with empty buckets
        let tree = vec![vec![None; BUCKET_SIZE]; (1 << (ORAM_DEPTH + 1)) - 1];
        PathORAM {
            tree,
            position_map: HashMap::new(),
            stash: Vec::new(),
        }
    }

    // Main access function for reading or writing data
    #[instrument(skip(self, rng), fields(prefix = ?prefix, operation = ?op), ret)]
    pub fn access(
        &mut self,
        op: Operation,
        prefix: [u8; 8],
        block: Option<ORAMBlock>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Option<Vec<ORAMBlock>> {
        // Get current path for the prefix
        let path = *self
            .position_map
            .entry(prefix)
            .or_insert_with(|| rng.next_u32() as usize % (1 << ORAM_DEPTH));

        // Generate new path for next access
        let new_path = rng.next_u32() as usize % (1 << ORAM_DEPTH);

        // Read path into stash
        let blocks = self.read_path(path);
        self.stash.extend(blocks);

        // Perform the actual operation
        let result = match op {
            Operation::Read => {
                // Find all blocks with matching prefix
                let matching_blocks: Vec<ORAMBlock> = self.stash
                    .iter()
                    .filter(|b| get_prefix(&b.blinded_identifier) == prefix)
                    .cloned()
                    .collect();
                Some(matching_blocks)
            }
            Operation::Write => {
                if let Some(block) = block {
                    // Add new block to stash
                    self.stash.push(block);
                    // Update position map
                    self.position_map.insert(prefix, new_path);
                }
                None
            }
        };

        // Write blocks back to tree along new path
        self.write_path(new_path);

        // Perform dummy accesses to hide access patterns
        for _ in 0..DUMMY_ACCESSES {
            let dummy_path = rng.next_u32() as usize % (1 << ORAM_DEPTH);
            let dummy_blocks = self.read_path(dummy_path);
            self.stash.extend(dummy_blocks);
            // Write back along a new random path
            let new_dummy_path = rng.next_u32() as usize % (1 << ORAM_DEPTH);
            self.write_path(new_dummy_path);
        }

        // Evict blocks from stash
        self.evict_from_stash(rng);

        result
    }

    // Read all blocks along a specific path in the tree
    #[instrument(skip(self), fields(leaf = %leaf), ret)]
    fn read_path(&mut self, leaf: usize) -> Vec<ORAMBlock> {
        let mut path = Vec::new();
        let mut node = leaf + (1 << ORAM_DEPTH) - 1;
        // Traverse from leaf to root, collecting all blocks
        while node > 0 {
            path.extend(self.tree[node].iter().filter_map(|b| b.clone()));
            node = (node - 1) / 2;
        }
        // Add root node blocks
        path.extend(self.tree[0].iter().filter_map(|b| b.clone()));
        path
    }

    // Write blocks from the stash back to the tree along a specific path
    #[instrument(skip(self), fields(leaf = %leaf), ret)]
    fn write_path(&mut self, leaf: usize) {
        let mut node = leaf + (1 << ORAM_DEPTH) - 1;
        // Traverse from leaf to root, writing blocks at each node
        while node > 0 {
            self.write_bucket(node);
            node = (node - 1) / 2;
        }
        // Write to root node
        self.write_bucket(0);
    }

    // Write blocks to a specific bucket (node) in the tree
    fn write_bucket(&mut self, node: usize) {
        let path_to_root = self.path_to_root(node);
        let mut bucket = Vec::new();
        // Select blocks from the stash that belong to this path
        self.stash.retain(|block| {
            let prefix = get_prefix(&block.blinded_identifier);
            if bucket.len() < BUCKET_SIZE
                && path_to_root.contains(&(self.position_map[&prefix] + (1 << ORAM_DEPTH) - 1))
            {
                bucket.push(Some(block.clone()));
                false // Remove from stash
            } else {
                true // Keep in stash
            }
        });
        // Fill remaining space in bucket with dummy blocks
        while bucket.len() < BUCKET_SIZE {
            bucket.push(None);
        }
        self.tree[node] = bucket;
    }

    // Calculate the path from a given node to the root
    fn path_to_root(&self, mut node: usize) -> Vec<usize> {
        let mut path = vec![node];
        while node > 0 {
            node = (node - 1) / 2;
            path.push(node);
        }
        path
    }

    // Securely delete the ORAM structure
    pub fn secure_delete(&mut self) {
        for bucket in self.tree.iter_mut() {
            for block in bucket.iter_mut() {
                if let Some(b) = block {
                    b.zeroize();
                }
            }
        }
        self.tree.zeroize();
        self.position_map.clear();
        self.position_map.shrink_to_fit();
        self.stash.zeroize();
    }

    // Helper function to check if a block exists
    pub fn contains(&self, prefix: &[u8; 8]) -> bool {
        if self.position_map.contains_key(prefix) {
            return true;
        }

        // Also check stash and tree for the block
        if self.stash.iter().any(|block| get_prefix(&block.blinded_identifier) == *prefix) {
            return true;
        }

        for bucket in &self.tree {
            if bucket
                .iter()
                .any(|block| block.as_ref().map_or(false, |b| get_prefix(&b.blinded_identifier) == *prefix))
            {
                return true;
            }
        }

        false
    }

    // Helper methods for benchmarking
    pub fn get_tree_height(&self) -> usize {
        ORAM_DEPTH
    }

    pub fn get_position_map_size(&self) -> usize {
        self.position_map.len()
    }

    pub fn get_stash_size(&self) -> usize {
        self.stash.len()
    }

    pub fn get_total_blocks(&self) -> usize {
        let mut total = 0;
        for bucket in &self.tree {
            total += bucket.iter().filter(|block| block.is_some()).count();
        }
        total + self.stash.len()
    }

    // Helper function to evict blocks from stash
    fn evict_from_stash(&mut self, rng: &mut (impl CryptoRng + RngCore)) {
        // Try to evict blocks while stash is larger than threshold
        while self.stash.len() > BUCKET_SIZE * ORAM_DEPTH {
            // Choose a random path to evict along
            let evict_path = rng.next_u32() as usize % (1 << ORAM_DEPTH);
            
            // Get all nodes along the path
            let mut current_node = evict_path + (1 << ORAM_DEPTH) - 1;
            let mut path_nodes = vec![current_node];
            while current_node > 0 {
                current_node = (current_node - 1) / 2;
                path_nodes.push(current_node);
            }

            // Try to evict blocks that can go along this path
            let mut remaining_stash = Vec::new();
            for block in self.stash.drain(..) {
                let block_prefix = get_prefix(&block.blinded_identifier);
                let block_path = self.position_map[&block_prefix];
                
                // Check if block can go on eviction path
                if path_nodes.iter().any(|&node| {
                    let bucket = &mut self.tree[node];
                    if let Some(empty_slot) = bucket.iter_mut().find(|slot| slot.is_none()) {
                        *empty_slot = Some(block.clone());
                        true
                    } else {
                        false
                    }
                }) {
                    // Block was evicted successfully
                    continue;
                }
                
                // Block couldn't be evicted, keep in stash
                remaining_stash.push(block);
            }
            
            self.stash = remaining_stash;
            
            // If we can't evict any more blocks, stop trying
            if self.stash.len() >= BUCKET_SIZE * ORAM_DEPTH {
                break;
            }
        }
    }
}

// Helper function to get prefix from commitment
fn get_prefix(commitment: &[u8]) -> [u8; 8] {
    let mut prefix = [0u8; 8];
    prefix.copy_from_slice(&commitment[..8]);
    prefix
}
