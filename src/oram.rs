/*
A simple Path ORAM implementation
*/

use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use tracing::{debug, trace};
use zeroize::{Zeroize, ZeroizeOnDrop};

// The depth of the ORAM tree determining the total nodes
const ORAM_DEPTH: usize = 20;
// The number of blocks that can be stored in each node of the tree
const BUCKET_SIZE: usize = 4;

// Read/Write ORAM operations
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Operation {
    Read,
    Write,
}

// Represents a block of data in the ORAM
// Zeroize and ZeroizeOnDrop ensure secure deletion of sensitive data
#[derive(Serialize, Deserialize, Clone, Debug, Zeroize, ZeroizeOnDrop)]
pub struct ORAMBlock {
    id: u64,       // Unique identifier for the block
    data: Vec<u8>, // The actual data stored in the block
}

// The main Path ORAM structure
#[derive(Debug)]
pub struct PathORAM {
    // The binary tree structure. Each node is a bucket that can hold up to BUCKET_SIZE blocks
    tree: Vec<Vec<Option<ORAMBlock>>>,
    // Maps block IDs to their current path in the tree
    position_map: HashMap<u64, usize>,
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
    pub fn access(
        &mut self,
        op: Operation,
        id: u64,
        data: Option<Vec<u8>>,
        rng: &mut (impl CryptoRng + RngCore),
    ) -> Option<Vec<u8>> {
        trace!("ORAM access: {:?} for ID {}", op, id);
        // Get current path, or assign a random one if this is a new block
        let path = *self
            .position_map
            .entry(id)
            .or_insert_with(|| rng.next_u32() as usize % (1 << ORAM_DEPTH));

        // Generate new path for next access
        let new_path = rng.next_u32() as usize % (1 << ORAM_DEPTH);

        // Read path into stash
        let blocks = self.read_path(path);
        self.stash.extend(blocks);

        // Find the target block in stash
        let result = match op {
            Operation::Read => self
                .stash
                .iter()
                .find(|b| b.id == id)
                .map(|b| b.data.clone()),
            Operation::Write => {
                if let Some(data) = data {
                    // Update existing block or add new one
                    if let Some(block) = self.stash.iter_mut().find(|b| b.id == id) {
                        block.data = data;
                    } else {
                        self.stash.push(ORAMBlock { id, data });
                    }
                    // Update position map
                    self.position_map.insert(id, new_path);
                }
                None
            }
        };

        // Write blocks back to tree
        self.write_path(new_path);

        // Ensure stash doesn't grow unbounded
        while self.stash.len() > BUCKET_SIZE * ORAM_DEPTH {
            if let Some(block) = self.stash.pop() {
                let block_path = self.position_map[&block.id];
                let mut current_node = block_path + (1 << ORAM_DEPTH) - 1;
                while current_node > 0 {
                    if let Some(empty_slot) = self.tree[current_node]
                        .iter_mut()
                        .find(|slot| slot.is_none())
                    {
                        *empty_slot = Some(block);
                        break;
                    }
                    current_node = (current_node - 1) / 2;
                }
            }
        }

        result
    }

    // Read all blocks along a specific path in the tree
    fn read_path(&mut self, leaf: usize) -> Vec<ORAMBlock> {
        trace!("Reading path for leaf {}", leaf);
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
    fn write_path(&mut self, leaf: usize) {
        trace!("Writing path for leaf {}", leaf);
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
            if bucket.len() < BUCKET_SIZE
                && path_to_root.contains(&(self.position_map[&block.id] + (1 << ORAM_DEPTH) - 1))
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

    pub fn get_all_identifiers(&self) -> Vec<u64> {
        self.position_map.keys().cloned().collect()
    }

    // Helper function to check if a block exists
    pub fn contains(&self, id: u64) -> bool {
        if self.position_map.contains_key(&id) {
            return true;
        }

        // Also check stash and tree for the block
        if self.stash.iter().any(|block| block.id == id) {
            return true;
        }

        for bucket in &self.tree {
            if bucket
                .iter()
                .any(|block| block.as_ref().map_or(false, |b| b.id == id))
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
}
