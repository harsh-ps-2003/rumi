/*
A simple Path ORAM implementation
*/

use blake3::Hasher;
use rand::{CryptoRng, RngCore};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use zeroize::{Zeroize, ZeroizeOnDrop};

// The depth of the ORAM tree determining the total nodes
const ORAM_DEPTH: usize = 20;
// The number of blocks that can be stored in each node of the tree
const BUCKET_SIZE: usize = 4;

// Read/Write ORAM operations
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
        // Retrieve the current path for the block and generate a new random path
        let path = *self
            .position_map
            .entry(id)
            .or_insert_with(|| rng.next_u32() as usize % (1 << ORAM_DEPTH));
        let new_path = rng.next_u32() as usize % (1 << ORAM_DEPTH);
        self.position_map.insert(id, new_path);

        // Read all blocks along the current path
        let blocks = self.read_path(path);

        // Add the read blocks to the stash
        self.stash.extend(blocks);

        // Perform the requested operation (read or write)
        let result = match op {
            Operation::Read => self
                .stash
                .iter()
                .find(|b| b.id == id)
                .map(|b| b.data.clone()),
            Operation::Write => {
                if let Some(data) = data {
                    if let Some(block) = self.stash.iter_mut().find(|b| b.id == id) {
                        block.data = data;
                    } else {
                        self.stash.push(ORAMBlock { id, data });
                    }
                }
                None
            }
        };

        // Write blocks back along the new path
        self.write_path(new_path);

        result
    }

    // Read all blocks along a specific path in the tree
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
}
