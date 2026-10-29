pub mod air;
pub mod hash;
pub mod store;

use p3_baby_bear::BabyBear;
use p3_challenger::{HashChallenger, SerializingChallenger32};
use p3_commit::ExtensionMmcs;
use p3_dft::Radix2DitParallel;
use p3_field::extension::BinomialExtensionField;
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::CompressionFunctionFromHasher;
use p3_uni_stark::StarkConfig;
use rand::{SeedableRng, rngs::StdRng};

use hash::{LeafHash, NodeHash, TranscriptHash};

pub type Challenge = BinomialExtensionField<BabyBear, 4>;
type Compress = CompressionFunctionFromHasher<NodeHash, 2, 8>;
type InputMmcs = MerkleTreeHidingMmcs<BabyBear, u64, LeafHash, Compress, StdRng, 2, 8, 16>;
type ExtMmcs = ExtensionMmcs<BabyBear, Challenge, InputMmcs>;
pub type Challenger = SerializingChallenger32<BabyBear, HashChallenger<u8, TranscriptHash, 64>>;
pub type DensePcs =
    p3_fri::HidingFriPcs<BabyBear, Radix2DitParallel<BabyBear>, InputMmcs, ExtMmcs, StdRng>;
pub type AdaptedPcs<S = kova_storage_fri::storage::DenseStore> = kova_storage_fri::HidingFriPcs<
    BabyBear,
    Radix2DitParallel<BabyBear>,
    InputMmcs,
    ExtMmcs,
    StdRng,
    S,
>;
pub type DenseConfig = StarkConfig<DensePcs, Challenge, Challenger>;
pub type StoredConfig = StarkConfig<AdaptedPcs<store::FileStore>, Challenge, Challenger>;

fn input() -> InputMmcs {
    InputMmcs::new(
        LeafHash,
        Compress::new(NodeHash),
        0,
        StdRng::from_seed([19; 32]),
    )
}

pub fn challenger() -> Challenger {
    Challenger::new(HashChallenger::new(
        b"kova.storage-pcs.quartic.v1".to_vec(),
        TranscriptHash,
    ))
}

pub fn dense() -> DenseConfig {
    let input = input();
    let ext = ExtMmcs::new(input.clone());
    let params = p3_fri::FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 64,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ext,
    };
    StarkConfig::new(
        DensePcs::new(
            Radix2DitParallel::default(),
            input,
            params,
            4,
            StdRng::from_seed([7; 32]),
        ),
        challenger(),
    )
}

pub fn adapted() -> AdaptedPcs {
    let input = input();
    let ext = ExtMmcs::new(input.clone());
    let params = kova_storage_fri::FriParameters {
        log_blowup: 3,
        log_final_poly_len: 0,
        max_log_arity: 1,
        num_queries: 64,
        batch_proof_of_work_bits: 0,
        commit_proof_of_work_bits: 0,
        query_proof_of_work_bits: 0,
        mmcs: ext,
    };
    AdaptedPcs::new(
        Radix2DitParallel::default(),
        input,
        params,
        4,
        StdRng::from_seed([7; 32]),
    )
}

pub fn stored(store: store::FileStore) -> StoredConfig {
    StarkConfig::new(adapted().with_storage(store), challenger())
}
