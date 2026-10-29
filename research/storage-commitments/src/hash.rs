use p3_baby_bear::BabyBear;
use p3_field::PrimeField32;
use p3_symmetric::CryptographicHasher;
use sha3::{Digest, Sha3_512};

fn begin(domain: &[u8]) -> Sha3_512 {
    let mut hash = Sha3_512::new();
    hash.update((domain.len() as u32).to_be_bytes());
    hash.update(domain);
    hash
}

fn digest_words(bytes: [u8; 64]) -> [u64; 8] {
    core::array::from_fn(|i| u64::from_le_bytes(bytes[8 * i..8 * i + 8].try_into().unwrap()))
}

#[derive(Clone, Debug)]
pub struct LeafHash;

impl CryptographicHasher<BabyBear, [u64; 8]> for LeafHash {
    fn hash_iter<I: IntoIterator<Item = BabyBear>>(&self, values: I) -> [u64; 8] {
        let mut hash = begin(b"kova.storage-commitments.leaf.v1");
        let mut count = 0u64;
        for value in values {
            hash.update(value.as_canonical_u32().to_le_bytes());
            count += 1;
        }
        hash.update(count.to_be_bytes());
        digest_words(hash.finalize().into())
    }
}

#[derive(Clone, Debug)]
pub struct NodeHash;

impl CryptographicHasher<u64, [u64; 8]> for NodeHash {
    fn hash_iter<I: IntoIterator<Item = u64>>(&self, values: I) -> [u64; 8] {
        let mut hash = begin(b"kova.storage-commitments.node.v1");
        let mut count = 0u64;
        for value in values {
            hash.update(value.to_le_bytes());
            count += 1;
        }
        hash.update(count.to_be_bytes());
        digest_words(hash.finalize().into())
    }
}
