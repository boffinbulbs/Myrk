use thorum_core::Amount;
use thorum_crypto_lab::{AuthorizationKey, RecipientKey};
use thorum_note_proof_lab::{
    Error, Statement, Witness, prove_note_conservation, verify_note_conservation,
};
use thorum_relation_lab::{
    NATIVE_ASSET_ID, NoteOpening, NoteParameters, NotePolicy, NullifierSecret, RecipientCapability,
};

#[test]
fn actual_recipient_note_commitments_and_amounts_share_one_hiding_proof() {
    let chain = [0x19; 32];
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
                serial: [0x30 + index as u8; 32],
                policy: NotePolicy::Payment,
            },
            &capability,
            [0x40 + index as u8; 32],
        )
        .unwrap()
    });
    let statement = Statement {
        fee: 1,
        chain,
        creation_versions: versions,
        asset: NATIVE_ASSET_ID,
        commitments: notes.each_ref().map(NoteOpening::commitment),
        context: [0x55; 64],
    };
    let witness = Witness::from_openings(core::array::from_fn(|index| {
        notes[index]
            .private_opening_bytes()
            .as_slice()
            .try_into()
            .unwrap()
    }));
    let proof = prove_note_conservation(&witness, &statement).unwrap();
    verify_note_conservation(&proof, &statement).unwrap();
    for index in 0..4 {
        let mut changed = statement;
        changed.commitments[index][63] ^= 1;
        assert_eq!(
            verify_note_conservation(&proof, &changed),
            Err(Error::InvalidProof)
        );
    }
    let mut changed = statement;
    changed.asset[31] ^= 1;
    assert_eq!(
        verify_note_conservation(&proof, &changed),
        Err(Error::InvalidProof)
    );
}
