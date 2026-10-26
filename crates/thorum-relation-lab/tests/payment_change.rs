use std::collections::BTreeSet;

use thorum_core::Amount;
use thorum_crypto_lab::{seal_for_relation, AuthorizationKey, RecipientKey};
use thorum_relation_lab::*;

fn note(
    owner: &AuthorizationKey,
    asset: AssetId,
    amount: u64,
    serial: u8,
) -> (NoteOpening, NullifierSecret) {
    let secret = NullifierSecret::from_bytes([serial; 32]);
    let opening = NoteOpening::new(
        NoteParameters {
            chain_id: [0x27; 32],
            creation_version: 1,
            asset_id: asset,
            amount: Amount::from_atomic(amount),
            serial: [serial; 32],
            policy: NotePolicy::Payment,
        },
        &owner.public_key(),
        &secret,
        [serial.wrapping_add(1); 32],
    )
    .unwrap();
    (opening, secret)
}

#[test]
fn separate_owners_authorize_two_assets_with_native_change_and_recipient_recovery() {
    let chain = [0x27; 32];
    let tag = [0x38; 32];
    let asset = [0xA7; 32];
    let native_owner = AuthorizationKey::generate().unwrap();
    let asset_owner = AuthorizationKey::generate().unwrap();
    let receiver_owner = AuthorizationKey::generate().unwrap();
    let receiver = RecipientKey::generate().unwrap();
    let change_receiver = RecipientKey::generate().unwrap();
    let (native_input, native_secret) = note(&native_owner, NATIVE_ASSET_ID, 100, 1);
    let (asset_input, asset_secret) = note(&asset_owner, asset, 7, 2);
    let leaves = [
        merkle_leaf(&chain, &native_input.commitment()),
        merkle_leaf(&chain, &asset_input.commitment()),
    ];
    let anchor = merkle_parent(&chain, &leaves[0], &leaves[1]);
    let mut statement = PaymentStatement {
        chain_id: chain,
        protocol_version: 1,
        validation_tag: tag,
        anchor,
        input_nullifiers: vec![
            native_input.nullifier(&native_secret).unwrap(),
            asset_input.nullifier(&asset_secret).unwrap(),
        ],
        outputs: vec![],
        native_fee: Amount::from_atomic(1),
    };
    let mut witness = PaymentWitness {
        inputs: vec![
            InputWitness {
                opening: native_input,
                nullifier_secret: native_secret,
                membership: MerklePath::new(0, vec![leaves[1]]).unwrap(),
                owner_public_key: native_owner.public_key(),
                authorization: vec![],
            },
            InputWitness {
                opening: asset_input,
                nullifier_secret: asset_secret,
                membership: MerklePath::new(1, vec![leaves[0]]).unwrap(),
                owner_public_key: asset_owner.public_key(),
                authorization: vec![],
            },
        ],
        outputs: vec![],
    };
    let output_specs = [
        (&receiver_owner, &receiver, NATIVE_ASSET_ID, 60),
        (&native_owner, &change_receiver, NATIVE_ASSET_ID, 39),
        (&receiver_owner, &receiver, asset, 7),
    ];
    for (index, (owner, recipient, output_asset, amount)) in output_specs.iter().enumerate() {
        let (opening, _) = note(owner, *output_asset, *amount, index as u8 + 3);
        let commitment = opening.commitment();
        let context = output_encryption_context(chain, 1, tag, index as u32, &commitment).unwrap();
        let (envelope, encryption) = seal_for_relation(
            &recipient.public_key(),
            &context,
            &opening.private_opening_bytes(),
        )
        .unwrap();
        statement.outputs.push(PaymentOutput {
            commitment,
            envelope,
        });
        witness.outputs.push(OutputWitness {
            opening,
            recipient_public_key: recipient.public_key(),
            encryption,
        });
    }
    let message = statement.authorization_message().unwrap();
    let authorization_context = statement.authorization_context().unwrap();
    for (input, owner) in witness.inputs.iter_mut().zip([&native_owner, &asset_owner]) {
        input.authorization = owner.sign(&authorization_context, &message).unwrap();
    }
    let anchors = BTreeSet::from([anchor]);
    let spent = BTreeSet::new();
    let context = PaymentContext {
        chain_id: chain,
        protocol_version: 1,
        validation_tag: tag,
        accepted_anchors: &anchors,
        spent_nullifiers: &spent,
    };
    check_payment(&statement, &witness, &context).unwrap();
    for (index, (_, recipient, _, _)) in output_specs.iter().enumerate() {
        let output = &statement.outputs[index];
        let envelope_context =
            output_encryption_context(chain, 1, tag, index as u32, &output.commitment).unwrap();
        assert_eq!(
            recipient
                .open(&envelope_context, &output.envelope)
                .unwrap()
                .as_slice(),
            witness.outputs[index]
                .opening
                .private_opening_bytes()
                .as_slice()
        );
    }
    witness.inputs[1].authorization = native_owner.sign(&authorization_context, &message).unwrap();
    assert!(matches!(
        check_payment(&statement, &witness, &context),
        Err(RelationError::Crypto(_))
    ));
    witness.inputs[1].authorization = asset_owner.sign(&authorization_context, &message).unwrap();
    statement.native_fee = Amount::from_atomic(2);
    let changed_message = statement.authorization_message().unwrap();
    let changed_context = statement.authorization_context().unwrap();
    for (input, owner) in witness.inputs.iter_mut().zip([&native_owner, &asset_owner]) {
        input.authorization = owner.sign(&changed_context, &changed_message).unwrap();
    }
    assert_eq!(
        check_payment(&statement, &witness, &context),
        Err(RelationError::ConservationFailed)
    );
    assert!(spent.is_empty());
}
