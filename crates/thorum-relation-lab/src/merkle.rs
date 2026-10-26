use crate::{hash_fields, ChainId, Digest64, RelationError};

pub const MAX_MERKLE_DEPTH: usize = 32;

/// Local membership witness with an exact index range for its depth.
pub struct MerklePath {
    index: u64,
    siblings: Vec<Digest64>,
}

impl MerklePath {
    pub fn new(index: u64, siblings: Vec<Digest64>) -> Result<Self, RelationError> {
        if siblings.len() > MAX_MERKLE_DEPTH || index >> siblings.len() != 0 {
            return Err(RelationError::InvalidPath);
        }
        Ok(Self { index, siblings })
    }

    pub fn root(&self, chain: &ChainId, commitment: &Digest64) -> Digest64 {
        let mut root = merkle_leaf(chain, commitment);
        for (level, sibling) in self.siblings.iter().enumerate() {
            root = if (self.index >> level) & 1 == 0 {
                merkle_parent(chain, &root, sibling)
            } else {
                merkle_parent(chain, sibling, &root)
            };
        }
        root
    }
}

pub fn merkle_leaf(chain: &ChainId, commitment: &Digest64) -> Digest64 {
    hash_fields(b"thorum.relation-lab.merkle-leaf.v1", &[chain, commitment])
}

pub fn merkle_parent(chain: &ChainId, left: &Digest64, right: &Digest64) -> Digest64 {
    hash_fields(b"thorum.relation-lab.merkle-node.v1", &[chain, left, right])
}
