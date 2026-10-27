use thorum_core::Amount;
use thorum_crypto_lab::{AuthorizationKey, RecipientKey};
use thorum_owner_binding_proof_lab::{
    Error, Statement, Witness, prove_owner_binding, verify_owner_binding,
};
use thorum_relation_lab::{
    MerklePath, NATIVE_ASSET_ID, NoteOpening, NoteParameters, NotePolicy, NullifierSecret,
    RecipientCapability, RecoveryContext, merkle_leaf, merkle_parent,
};

type Siblings = [[[u8; 64]; 32]; 2];

fn independent_paths(
    chain: &[u8; 32],
    inputs: &[[u8; 64]; 2],
    extra_commitment: Option<[u8; 64]>,
) -> ([u8; 64], Siblings) {
    let mut empty = [[0; 64]; 32];
    empty[0] = merkle_leaf(chain, &[0; 64]);
    for level in 1..32 {
        empty[level] = merkle_parent(chain, &empty[level - 1], &empty[level - 1]);
    }
    let mut siblings = [empty; 2];
    siblings[0][0] = merkle_leaf(chain, &inputs[1]);
    siblings[1][0] = merkle_leaf(chain, &inputs[0]);
    if let Some(extra) = extra_commitment {
        let right_subtree = merkle_parent(chain, &merkle_leaf(chain, &extra), &empty[0]);
        siblings[0][1] = right_subtree;
        siblings[1][1] = right_subtree;
    }
    let root = MerklePath::new(0, siblings[0].to_vec())
        .unwrap()
        .root(chain, &inputs[0]);
    assert_eq!(
        root,
        MerklePath::new(1, siblings[1].to_vec())
            .unwrap()
            .root(chain, &inputs[1])
    );
    (root, siblings)
}

#[test]
fn recovered_notes_bind_their_actual_owner_keys_under_new_roots_and_contexts() {
    let chain = [0x27; 32];
    let owners: [AuthorizationKey; 2] =
        core::array::from_fn(|_| AuthorizationKey::generate().unwrap());
    let encryption: [RecipientKey; 2] = core::array::from_fn(|_| RecipientKey::generate().unwrap());
    let authority: [NullifierSecret; 2] =
        core::array::from_fn(|_| NullifierSecret::generate().unwrap());
    let capabilities: [RecipientCapability; 2] = core::array::from_fn(|index| {
        RecipientCapability::new(
            chain,
            &owners[index].public_key(),
            &encryption[index].public_key(),
            &authority[index],
        )
        .unwrap()
    });
    let amounts = [50, 50, 60, 39, 1];
    let versions = [1, 3, 5, 8, 9];
    let notes: [NoteOpening; 5] = core::array::from_fn(|index| {
        NoteOpening::new_recipient(
            NoteParameters {
                chain_id: chain,
                creation_version: versions[index],
                asset_id: NATIVE_ASSET_ID,
                amount: Amount::from_atomic(amounts[index]),
                serial: [0x31 + index as u8; 32],
                policy: NotePolicy::Payment,
            },
            &capabilities[index % 2],
            [0x41 + index as u8; 32],
        )
        .unwrap()
    });
    let commitments = notes.each_ref().map(NoteOpening::commitment);
    let nullifiers: [[u8; 64]; 2] =
        core::array::from_fn(|index| notes[index].nullifier(&authority[index]).unwrap());
    assert_ne!(nullifiers[0], nullifiers[1]);
    let restored: [NullifierSecret; 2] = core::array::from_fn(|index| {
        NullifierSecret::from_bytes(*authority[index].export_backup())
    });
    let recovered: [NoteOpening; 2] = core::array::from_fn(|index| {
        NoteOpening::recover_recipient(
            notes[index].private_opening_bytes().as_slice(),
            &RecoveryContext {
                chain_id: chain,
                creation_version: versions[index],
                expected_commitment: commitments[index],
            },
            &capabilities[index],
            &restored[index],
        )
        .unwrap()
    });
    for index in 0..2 {
        assert_eq!(
            recovered[index].nullifier(&restored[index]).unwrap(),
            nullifiers[index]
        );
        assert!(
            NoteOpening::recover_recipient(
                notes[index].private_opening_bytes().as_slice(),
                &RecoveryContext {
                    chain_id: chain,
                    creation_version: versions[index],
                    expected_commitment: commitments[index],
                },
                &capabilities[index],
                &restored[1 - index],
            )
            .is_err()
        );
    }
    let owner_keys: [[u8; 2592]; 2] =
        core::array::from_fn(|index| owners[index].public_key().try_into().unwrap());
    assert_ne!(owner_keys[0], owner_keys[1]);
    let make_witness = |siblings, keys| {
        Witness::from_openings_keys_secrets_and_paths(
            core::array::from_fn(|index| {
                if index < 2 {
                    recovered[index]
                        .private_opening_bytes()
                        .as_slice()
                        .try_into()
                        .unwrap()
                } else {
                    notes[index]
                        .private_opening_bytes()
                        .as_slice()
                        .try_into()
                        .unwrap()
                }
            }),
            keys,
            core::array::from_fn(|index| *restored[index].export_backup()),
            [0, 1],
            siblings,
        )
    };
    let inputs = [commitments[0], commitments[1]];
    let (root, siblings) = independent_paths(&chain, &inputs, None);
    let statement = Statement {
        fee: 1,
        chain,
        output_creation_versions: [versions[2], versions[3]],
        asset: NATIVE_ASSET_ID,
        root,
        output_commitments: [commitments[2], commitments[3]],
        nullifiers,
        context: [0x66; 64],
    };
    let witness = make_witness(siblings, owner_keys);
    let mut substituted_keys = owner_keys;
    substituted_keys[0] = owner_keys[1];
    assert_eq!(
        prove_owner_binding(&make_witness(siblings, substituted_keys), &statement),
        Err(Error::InvalidWitness)
    );
    let proof = prove_owner_binding(&witness, &statement).unwrap();
    verify_owner_binding(&proof, &statement).unwrap();
    let (new_root, new_siblings) = independent_paths(&chain, &inputs, Some(commitments[4]));
    assert_ne!(root, new_root);
    let mut changed = statement;
    changed.root = new_root;
    changed.context = [0x77; 64];
    assert_eq!(changed.nullifiers, statement.nullifiers);
    assert_eq!(
        verify_owner_binding(&proof, &changed),
        Err(Error::InvalidProof)
    );
    let new_proof = prove_owner_binding(&make_witness(new_siblings, owner_keys), &changed).unwrap();
    verify_owner_binding(&new_proof, &changed).unwrap();
    assert_eq!(
        verify_owner_binding(&new_proof, &statement),
        Err(Error::InvalidProof)
    );
    let mut wrong_nullifier = changed;
    wrong_nullifier.nullifiers[0][63] ^= 1;
    assert_eq!(
        verify_owner_binding(&new_proof, &wrong_nullifier),
        Err(Error::InvalidProof)
    );
    let mut duplicate = statement;
    duplicate.nullifiers[1] = duplicate.nullifiers[0];
    assert_eq!(
        prove_owner_binding(&witness, &duplicate),
        Err(Error::DuplicateNullifier)
    );
    assert_eq!(
        verify_owner_binding(&proof, &duplicate),
        Err(Error::DuplicateNullifier)
    );
}
