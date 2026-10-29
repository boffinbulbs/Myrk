use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Seek, SeekFrom, Write};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::sync::atomic::{AtomicUsize, Ordering};

use kova_storage_matrix::{CheckedFileMatrix, StorageAccessFailure, StorageError};
use p3_baby_bear::BabyBear;
use p3_commit::{BatchOpening, BatchOpeningRef, Mmcs};
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{dense::RowMajorMatrix, Dimensions};
use p3_merkle_tree::MerkleTreeHidingMmcs;
use p3_symmetric::{CompressionFunctionFromHasher, CryptographicHasher};
use rand::{rngs::StdRng, SeedableRng};
use serde::{Deserialize, Serialize};

use crate::hash::{LeafHash, NodeHash};

type Compress = CompressionFunctionFromHasher<NodeHash, 2, 8>;
type HidingMmcs = MerkleTreeHidingMmcs<BabyBear, u64, LeafHash, Compress, StdRng, 2, 8, 16>;
static NEXT: AtomicUsize = AtomicUsize::new(0);

fn mmcs(id: u8) -> HidingMmcs {
    let input = HidingMmcs::new(
        LeafHash,
        Compress::new(NodeHash),
        0,
        StdRng::from_seed([id; 32]),
    );
    // Exercise the retained seed fork before the first input salt draw.
    let _extension_child = input.clone();
    input
}

fn cases() -> Vec<(u8, Vec<[usize; 2]>)> {
    vec![
        (1, vec![[8, 1]]),
        (2, vec![[16, 4]]),
        (3, vec![[256, 8]]),
        (4, vec![[64, 4], [256, 8], [64, 1]]),
    ]
}

fn word(id: u8, matrix: usize, row: usize, column: usize) -> u32 {
    ((u64::from(id) * 1009
        + matrix as u64 * 65537
        + row as u64 * 97
        + column as u64 * 13
        + row as u64 * column as u64 * 17)
        % 2_013_265_921) as u32
}

fn dense(id: u8, dimensions: &[[usize; 2]]) -> Vec<RowMajorMatrix<BabyBear>> {
    dimensions
        .iter()
        .enumerate()
        .map(|(m, &[height, width])| {
            let values = (0..height)
                .flat_map(|r| (0..width).map(move |c| BabyBear::from_u32(word(id, m, r, c))))
                .collect();
            RowMajorMatrix::new(values, width)
        })
        .collect()
}

fn dims(dimensions: &[[usize; 2]]) -> Vec<Dimensions> {
    dimensions
        .iter()
        .map(|&[height, width]| Dimensions { height, width })
        .collect()
}

struct Files {
    directory: PathBuf,
    paths: Vec<PathBuf>,
}

impl Files {
    fn new(id: u8, dimensions: &[[usize; 2]]) -> Self {
        let directory = std::env::temp_dir().join(format!(
            "kova_commitments_{}_{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&directory).unwrap();
        let mut paths = Vec::new();
        for (m, &[height, width]) in dimensions.iter().enumerate() {
            let path = directory.join(format!("matrix_{m}.bin"));
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&path)
                .unwrap();
            for r in 0..height {
                for c in 0..width {
                    file.write_all(&word(id, m, r, c).to_le_bytes()).unwrap();
                }
            }
            file.sync_all().unwrap();
            paths.push(path);
        }
        Self { directory, paths }
    }

    fn matrices(&self, dimensions: &[[usize; 2]]) -> Vec<CheckedFileMatrix> {
        self.paths
            .iter()
            .zip(dimensions)
            .map(|(p, &[h, w])| CheckedFileMatrix::open(p, h, w).unwrap())
            .collect()
    }

    fn change_first_word(&self, value: u32) {
        let mut file = OpenOptions::new().write(true).open(&self.paths[0]).unwrap();
        file.seek(SeekFrom::Start(0)).unwrap();
        file.write_all(&value.to_le_bytes()).unwrap();
        file.sync_all().unwrap();
    }
}

impl Drop for Files {
    fn drop(&mut self) {
        for path in &self.paths {
            fs::remove_file(path).unwrap();
        }
        fs::remove_dir(&self.directory).unwrap();
    }
}

#[derive(Serialize, Deserialize)]
struct SaltCase {
    id: u8,
    dimensions: Vec<[usize; 2]>,
    root: [u64; 8],
    salts: Vec<Vec<Vec<u32>>>,
}

#[derive(Deserialize)]
struct HashVector {
    values: Vec<u64>,
    digest: [u64; 8],
}

#[derive(Deserialize)]
struct RootCase {
    id: u8,
    dimensions: Vec<[usize; 2]>,
    root: [u64; 8],
}

#[derive(Deserialize)]
struct IndependentReference {
    cases: Vec<RootCase>,
    leaf_vector: HashVector,
    node_vector: HashVector,
}

#[test]
#[ignore = "Explicit synthetic fixture export, not part of ordinary validation"]
fn export_public_synthetic_salts() {
    let output = std::env::var_os("KOVA_SYNTHETIC_SALT_OUTPUT").expect("explicit new output path");
    let mut records = Vec::new();
    for (id, dimensions) in cases() {
        let scheme = mmcs(id);
        let (root, data) = scheme.commit(dense(id, &dimensions));
        let maximum = dimensions.iter().map(|d| d[0]).max().unwrap();
        let salts = dimensions
            .iter()
            .enumerate()
            .map(|(m, &[height, _])| {
                (0..height)
                    .map(|row| {
                        scheme
                            .open_batch(row * (maximum / height), &data)
                            .opening_proof
                            .0[m]
                            .iter()
                            .map(|v| v.as_canonical_u32())
                            .collect()
                    })
                    .collect()
            })
            .collect();
        records.push(SaltCase {
            id,
            dimensions,
            root: root.roots()[0],
            salts,
        });
    }
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(output)
        .unwrap();
    serde_json::to_writer_pretty(&mut file, &records).unwrap();
    file.write_all(b"\n").unwrap();
    file.sync_all().unwrap();
}

#[test]
fn framed_hashes_and_all_salt_rows_match_independent_references() {
    let reference: IndependentReference =
        serde_json::from_str(include_str!("../fixtures/reference.json")).unwrap();
    let corpus: Vec<SaltCase> =
        serde_json::from_str(include_str!("../fixtures/salts.json")).unwrap();
    assert_eq!(reference.cases.len(), 4);
    assert_eq!(corpus.len(), 4);
    let leaf = LeafHash.hash_iter(reference.leaf_vector.values.iter().map(|&v| {
        let word = u32::try_from(v).unwrap();
        assert!(word < BabyBear::ORDER_U32);
        BabyBear::from_u32(word)
    }));
    assert_eq!(leaf, reference.leaf_vector.digest);
    assert_eq!(
        NodeHash.hash_iter(reference.node_vector.values),
        reference.node_vector.digest
    );
    for (((id, dimensions), captured), expected) in
        cases().into_iter().zip(corpus).zip(reference.cases)
    {
        assert_eq!(captured.id, id);
        assert_eq!(expected.id, id);
        assert_eq!(captured.dimensions, dimensions);
        assert_eq!(expected.dimensions, dimensions);
        assert_eq!(captured.root, expected.root);
        let files = Files::new(id, &dimensions);
        let scheme = mmcs(id);
        let (root, data) = scheme.commit(files.matrices(&dimensions));
        assert_eq!(root.roots()[0], expected.root);
        let maximum = dimensions.iter().map(|d| d[0]).max().unwrap();
        assert_eq!(captured.salts.len(), dimensions.len());
        for (m, &[height, _]) in dimensions.iter().enumerate() {
            assert_eq!(captured.salts[m].len(), height);
            for row in 0..height {
                let opening = scheme.open_batch(row * (maximum / height), &data);
                let salts: Vec<_> = opening.opening_proof.0[m]
                    .iter()
                    .map(|v| v.as_canonical_u32())
                    .collect();
                assert_eq!(salts, captured.salts[m][row]);
            }
        }
    }
}

#[test]
fn dense_and_storage_commitments_openings_and_multiproofs_match() {
    for (id, dimensions) in cases() {
        let files = Files::new(id, &dimensions);
        let memory = mmcs(id);
        let storage = mmcs(id);
        let (a, ad) = memory.commit(dense(id, &dimensions));
        let (b, bd) = storage.commit(files.matrices(&dimensions));
        assert_eq!(a, b);
        let shape = dims(&dimensions);
        let height = dimensions.iter().map(|d| d[0]).max().unwrap();
        let indices: Vec<_> = [0, 1, height / 2, height - 2, height - 1]
            .into_iter()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        for &index in &indices {
            let x = memory.open_batch(index, &ad);
            let y = storage.open_batch(index, &bd);
            assert_eq!(
                serde_json::to_vec(&x).unwrap(),
                serde_json::to_vec(&y).unwrap()
            );
            let decoded: BatchOpening<BabyBear, HidingMmcs> =
                serde_json::from_slice(&serde_json::to_vec(&y).unwrap()).unwrap();
            memory
                .verify_batch(&a, &shape, index, (&decoded).into())
                .unwrap();
            memory.verify_batch(&a, &shape, index, (&y).into()).unwrap();
            for (m, &[h, w]) in dimensions.iter().enumerate() {
                let expected: Vec<_> = (0..w)
                    .map(|c| word(id, m, index / (height / h), c))
                    .collect();
                assert_eq!(
                    y.opened_values[m]
                        .iter()
                        .map(|v| v.as_canonical_u32())
                        .collect::<Vec<_>>(),
                    expected
                );
            }
            let mut changed = y.clone();
            changed.opened_values[0][0] += BabyBear::ONE;
            assert!(memory
                .verify_batch(&a, &shape, index, (&changed).into())
                .is_err());
            let mut changed = y.clone();
            changed.opening_proof.0[0][0] += BabyBear::ONE;
            assert!(memory
                .verify_batch(&a, &shape, index, (&changed).into())
                .is_err());
            let mut changed = y.clone();
            changed.opening_proof.1[0][0] ^= 1;
            assert!(memory
                .verify_batch(&a, &shape, index, (&changed).into())
                .is_err());
            assert!(memory
                .verify_batch(&a, &shape, index ^ 1, (&y).into())
                .is_err());
            let mut changed = y.clone();
            changed.opened_values[0].push(BabyBear::ZERO);
            changed.opening_proof.0[0].pop();
            assert!(memory
                .verify_batch(&a, &shape, index, (&changed).into())
                .is_err());
            let mut wrong_shape = shape.clone();
            wrong_shape[0].width += 1;
            assert!(memory
                .verify_batch(&a, &wrong_shape, index, (&y).into())
                .is_err());
        }
        let (av, ap) = memory.open_multi_batch(&indices, &ad);
        let (bv, bp) = storage.open_multi_batch(&indices, &bd);
        assert_eq!(
            serde_json::to_vec(&(&av, &ap)).unwrap(),
            serde_json::to_vec(&(&bv, &bp)).unwrap()
        );
        memory
            .verify_multi_batch(&a, &shape, &indices, &bv, &bp)
            .unwrap();
        let mut changed = bv.clone();
        changed[0][0][0] += BabyBear::ONE;
        assert!(memory
            .verify_multi_batch(&a, &shape, &indices, &changed, &bp)
            .is_err());
    }
}

#[test]
fn canonical_storage_change_is_rejected_by_actual_opening_verification() {
    let dimensions = [[256, 8]];
    let files = Files::new(5, &dimensions);
    let scheme = mmcs(5);
    let (root, data) = scheme.commit(files.matrices(&dimensions));
    let original = scheme.open_batch(0, &data);
    scheme
        .verify_batch(&root, &dims(&dimensions), 0, (&original).into())
        .unwrap();
    files.change_first_word(word(5, 0, 0, 0) + 1);
    let changed = scheme.open_batch(0, &data);
    assert_ne!(original.opened_values, changed.opened_values);
    assert!(scheme
        .verify_batch(
            &root,
            &dims(&dimensions),
            0,
            BatchOpeningRef::from(&changed)
        )
        .is_err());
    // The unchanged original opening remains valid against the original root.
    scheme
        .verify_batch(&root, &dims(&dimensions), 0, (&original).into())
        .unwrap();
}

#[test]
fn storage_failures_abort_commitment_opening_without_a_proof_verdict() {
    for truncated in [false, true] {
        let dimensions = [[16, 4]];
        let files = Files::new(6, &dimensions);
        let scheme = mmcs(6);
        let (_root, data) = scheme.commit(files.matrices(&dimensions));
        if truncated {
            OpenOptions::new()
                .write(true)
                .open(&files.paths[0])
                .unwrap()
                .set_len(4)
                .unwrap();
        } else {
            files.change_first_word(2_013_265_921);
        }
        let error = catch_unwind(AssertUnwindSafe(|| {
            let _ = scheme.open_batch(0, &data);
        }))
        .unwrap_err();
        let failure = error.downcast_ref::<StorageAccessFailure>().unwrap();
        assert_eq!(
            failure.0,
            if truncated {
                StorageError::Length
            } else {
                StorageError::NonCanonicalField
            }
        );
    }
}

#[test]
fn continuing_commitments_preserve_the_salt_stream_and_forks_are_distinct() {
    let dimensions = [[16, 4]];
    let files = Files::new(7, &dimensions);
    let memory = mmcs(7);
    let storage = mmcs(7);
    let (first, _) = storage.commit(files.matrices(&dimensions));
    let (memory_first, _) = memory.commit(dense(7, &dimensions));
    assert_eq!(first, memory_first);
    let (second, _) = storage.commit(files.matrices(&dimensions));
    let (memory_second, _) = memory.commit(dense(7, &dimensions));
    assert_eq!(second, memory_second);
    assert_ne!(first, second);
    let child = storage.clone();
    let (parent_root, _) = storage.commit(files.matrices(&dimensions));
    let (child_root, _) = child.commit(files.matrices(&dimensions));
    assert_ne!(parent_root, child_root);
}
