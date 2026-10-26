use thorum_core::Amount;
use thorum_crypto_lab::{AuthorizationKey, RecipientKey};
use thorum_membership_proof_lab::{Error, Statement, Witness, prove_membership, verify_membership};
use thorum_relation_lab::{
    MerklePath, NATIVE_ASSET_ID, NoteOpening, NoteParameters, NotePolicy, NullifierSecret,
    RecipientCapability, merkle_leaf, merkle_parent,
};

#[test]
fn existing_recipient_notes_and_private_paths_share_the_same_proof() {
    let chain = [0x27; 32];
    let owner = AuthorizationKey::generate().unwrap();
    let encryption = RecipientKey::generate().unwrap();
    let nullifier = NullifierSecret::generate().unwrap();
    let capability = RecipientCapability::new(
        chain,
        &owner.public_key(),
        &encryption.public_key(),
        &nullifier,
    )
    .unwrap();
    let amounts = [50, 50, 60, 39];
    let versions = [1, 3, 5, 8];
    let notes: [NoteOpening; 4] = core::array::from_fn(|index| {
        NoteOpening::new_recipient(
            NoteParameters {
                chain_id: chain,
                creation_version: versions[index],
                asset_id: NATIVE_ASSET_ID,
                amount: Amount::from_atomic(amounts[index]),
                serial: [0x31 + index as u8; 32],
                policy: NotePolicy::Payment,
            },
            &capability,
            [0x41 + index as u8; 32],
        )
        .unwrap()
    });
    let commitments = notes.each_ref().map(NoteOpening::commitment);
    let mut empty = [[0; 64]; 32];
    empty[0] = merkle_leaf(&chain, &[0; 64]);
    for level in 1..32 {
        empty[level] = merkle_parent(&chain, &empty[level - 1], &empty[level - 1]);
    }
    let mut siblings = [empty; 2];
    siblings[0][0] = merkle_leaf(&chain, &commitments[1]);
    siblings[1][0] = merkle_leaf(&chain, &commitments[0]);
    let root = MerklePath::new(0, siblings[0].to_vec())
        .unwrap()
        .root(&chain, &commitments[0]);
    assert_eq!(
        root,
        MerklePath::new(1, siblings[1].to_vec())
            .unwrap()
            .root(&chain, &commitments[1])
    );
    let statement = Statement {
        fee: 1,
        chain,
        output_creation_versions: [versions[2], versions[3]],
        asset: NATIVE_ASSET_ID,
        root,
        output_commitments: [commitments[2], commitments[3]],
        context: [0x66; 64],
    };
    let witness = Witness::from_openings_and_paths(
        core::array::from_fn(|index| {
            notes[index]
                .private_opening_bytes()
                .as_slice()
                .try_into()
                .unwrap()
        }),
        [0, 1],
        siblings,
    );
    let proof = prove_membership(&witness, &statement).unwrap();
    verify_membership(&proof, &statement).unwrap();
    let mut wrong = statement;
    wrong.root[63] ^= 1;
    assert_eq!(verify_membership(&proof, &wrong), Err(Error::InvalidProof));
}
