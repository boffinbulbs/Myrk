use std::collections::BTreeSet;

use thorum_core::Amount;
use thorum_crypto_lab::{seal_for_relation, AuthorizationKey, RecipientKey, SealedNote};
use thorum_relation_lab::*;

const CHAIN: ChainId = [0x11; 32];
const TAG: [u8; 32] = [0x22; 32];

fn note(
    owner: &AuthorizationKey,
    asset_id: AssetId,
    amount: u64,
    serial: u8,
    version: u32,
) -> (NoteOpening, NullifierSecret) {
    let secret = NullifierSecret::from_bytes([serial; 32]);
    let opening = NoteOpening::new(
        NoteParameters {
            chain_id: CHAIN,
            creation_version: version,
            asset_id,
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

struct Fixture {
    owner: AuthorizationKey,
    receiver_owner: AuthorizationKey,
    recipient: RecipientKey,
    statement: PaymentStatement,
    witness: PaymentWitness,
    anchors: BTreeSet<Digest64>,
    spent: BTreeSet<Digest64>,
}

impl Fixture {
    fn new(input: u64, output: u64, fee: u64, input_asset: AssetId, output_asset: AssetId) -> Self {
        let owner = AuthorizationKey::generate().unwrap();
        let receiver_owner = AuthorizationKey::generate().unwrap();
        let recipient = RecipientKey::generate().unwrap();
        let (input_note, input_secret) = note(&owner, input_asset, input, 1, 1);
        let (output_note, _) = note(&receiver_owner, output_asset, output, 2, 1);
        let input_nf = input_note.nullifier(&input_secret).unwrap();
        let anchor = merkle_leaf(&CHAIN, &input_note.commitment());
        let commitment = output_note.commitment();
        let encryption_context = output_encryption_context(CHAIN, 1, TAG, 0, &commitment).unwrap();
        let (envelope, encryption) = seal_for_relation(
            &recipient.public_key(),
            &encryption_context,
            &output_note.private_opening_bytes(),
        )
        .unwrap();
        let statement = PaymentStatement {
            chain_id: CHAIN,
            protocol_version: 1,
            validation_tag: TAG,
            anchor,
            input_nullifiers: vec![input_nf],
            outputs: vec![PaymentOutput {
                commitment,
                envelope,
            }],
            native_fee: Amount::from_atomic(fee),
        };
        let witness = PaymentWitness {
            inputs: vec![InputWitness {
                opening: input_note,
                nullifier_secret: input_secret,
                membership: MerklePath::new(0, vec![]).unwrap(),
                owner_public_key: owner.public_key(),
                authorization: vec![],
            }],
            outputs: vec![OutputWitness {
                opening: output_note,
                recipient_public_key: recipient.public_key(),
                encryption,
            }],
        };
        let mut fixture = Self {
            owner,
            receiver_owner,
            recipient,
            statement,
            witness,
            anchors: BTreeSet::from([anchor]),
            spent: BTreeSet::new(),
        };
        fixture.resign();
        fixture
    }

    fn valid() -> Self {
        Self::new(100, 99, 1, NATIVE_ASSET_ID, NATIVE_ASSET_ID)
    }

    fn resign(&mut self) {
        let message = self.statement.authorization_message().unwrap();
        let context = self.statement.authorization_context().unwrap();
        for input in &mut self.witness.inputs {
            input.authorization = self.owner.sign(&context, &message).unwrap();
        }
    }

    fn check(&self) -> Result<(), RelationError> {
        check_payment(
            &self.statement,
            &self.witness,
            &PaymentContext {
                chain_id: CHAIN,
                protocol_version: self.statement.protocol_version,
                validation_tag: TAG,
                accepted_anchors: &self.anchors,
                spent_nullifiers: &self.spent,
            },
        )
    }
}

#[test]
fn valid_payment_checks_locally_and_delivery_contains_the_nullifier_secret() {
    let fixture = Fixture::valid();
    fixture.check().unwrap();
    let context =
        output_encryption_context(CHAIN, 1, TAG, 0, &fixture.statement.outputs[0].commitment)
            .unwrap();
    let recovered = fixture
        .recipient
        .open(&context, &fixture.statement.outputs[0].envelope)
        .unwrap();
    assert_eq!(
        recovered.as_slice(),
        fixture.witness.outputs[0]
            .opening
            .private_opening_bytes()
            .as_slice()
    );
    let mut remaining = recovered.as_slice();
    let mut fields = Vec::new();
    while !remaining.is_empty() {
        let length = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        fields.push(&remaining[4..4 + length]);
        remaining = &remaining[4 + length..];
    }
    assert_eq!(fields[8], [2; 32]);
    let recovered_secret = NullifierSecret::from_bytes(fields[8].try_into().unwrap());
    let sender_known_secret = NullifierSecret::from_bytes([2; 32]);
    let output = &fixture.witness.outputs[0].opening;
    // The current sender knows this nullifier. This test does not claim sender unlinkability.
    assert_eq!(
        output.nullifier(&recovered_secret).unwrap(),
        output.nullifier(&sender_known_secret).unwrap()
    );
    assert!(fixture.spent.is_empty());
}

#[test]
fn wrong_owner_key_signature_and_authorization_domain_are_rejected() {
    let mut fixture = Fixture::valid();
    fixture.witness.inputs[0].authorization[0] ^= 1;
    assert!(matches!(fixture.check(), Err(RelationError::Crypto(_))));
    fixture.resign();
    let mut wrong_context = fixture.statement.authorization_context().unwrap();
    wrong_context.output_tag[0] ^= 1;
    fixture.witness.inputs[0].authorization = fixture
        .owner
        .sign(
            &wrong_context,
            &fixture.statement.authorization_message().unwrap(),
        )
        .unwrap();
    assert!(matches!(fixture.check(), Err(RelationError::Crypto(_))));
    let voting_key = AuthorizationKey::generate().unwrap();
    fixture.witness.inputs[0].owner_public_key = voting_key.public_key();
    fixture.witness.inputs[0].authorization = voting_key
        .sign(
            &fixture.statement.authorization_context().unwrap(),
            &fixture.statement.authorization_message().unwrap(),
        )
        .unwrap();
    assert_eq!(fixture.check(), Err(RelationError::OwnerKeyMismatch));
}

#[test]
fn changed_opening_nullifier_secret_and_untrusted_anchor_are_rejected() {
    let mut fixture = Fixture::valid();
    fixture.witness.inputs[0].nullifier_secret = NullifierSecret::from_bytes([9; 32]);
    assert_eq!(fixture.check(), Err(RelationError::NullifierSecretMismatch));
    fixture.witness.inputs[0].nullifier_secret = NullifierSecret::from_bytes([1; 32]);
    let (wrong_opening, _) = note(&fixture.owner, NATIVE_ASSET_ID, 101, 1, 1);
    fixture.witness.inputs[0].opening = wrong_opening;
    assert_eq!(fixture.check(), Err(RelationError::NullifierMismatch));
    fixture.anchors.clear();
    assert_eq!(fixture.check(), Err(RelationError::UntrustedAnchor));
}

#[test]
fn explicit_spent_set_rejects_replay_without_mutating_external_state() {
    let mut fixture = Fixture::valid();
    fixture.check().unwrap();
    fixture.check().unwrap();
    fixture.spent.insert(fixture.statement.input_nullifiers[0]);
    let before = fixture.spent.clone();
    assert_eq!(fixture.check(), Err(RelationError::AlreadySpent));
    assert_eq!(fixture.spent, before);
}

#[test]
fn exact_envelope_bytes_are_authorized_and_encryption_is_checked_after_resigning() {
    let mut fixture = Fixture::valid();
    fixture.statement.outputs[0].envelope.ciphertext[0] ^= 1;
    assert!(matches!(
        fixture.check(),
        Err(RelationError::Crypto(
            thorum_crypto_lab::Error::SignatureFailed
        ))
    ));
    fixture.resign();
    assert!(matches!(
        fixture.check(),
        Err(RelationError::Crypto(
            thorum_crypto_lab::Error::AuthenticationFailed
        ))
    ));
}

#[test]
fn wrong_recipient_and_wrong_sender_encryption_witness_are_rejected() {
    let mut fixture = Fixture::valid();
    let context =
        output_encryption_context(CHAIN, 1, TAG, 0, &fixture.statement.outputs[0].commitment)
            .unwrap();
    let (_, wrong_witness) = seal_for_relation(
        &fixture.recipient.public_key(),
        &context,
        &fixture.witness.outputs[0].opening.private_opening_bytes(),
    )
    .unwrap();
    fixture.witness.outputs[0].encryption = wrong_witness;
    assert!(matches!(
        fixture.check(),
        Err(RelationError::Crypto(
            thorum_crypto_lab::Error::AuthenticationFailed
        ))
    ));
    let mut fixture = Fixture::valid();
    fixture.witness.outputs[0].recipient_public_key =
        RecipientKey::generate().unwrap().public_key();
    assert!(matches!(
        fixture.check(),
        Err(RelationError::Crypto(
            thorum_crypto_lab::Error::AuthenticationFailed
        ))
    ));
}

#[test]
fn bond_exit_is_not_enabled_by_an_owner_payment_signature() {
    let mut fixture = Fixture::valid();
    let voter = AuthorizationKey::generate().unwrap();
    let secret = NullifierSecret::from_bytes([1; 32]);
    let bond = NoteOpening::new(
        NoteParameters {
            chain_id: CHAIN,
            creation_version: 1,
            asset_id: NATIVE_ASSET_ID,
            amount: Amount::from_atomic(100),
            serial: [1; 32],
            policy: NotePolicy::Bond(BondPolicy::new(&voter.public_key(), 1, 2, 20).unwrap()),
        },
        &fixture.owner.public_key(),
        &secret,
        [2; 32],
    )
    .unwrap();
    fixture.statement.input_nullifiers[0] = bond.nullifier(&secret).unwrap();
    fixture.statement.anchor = merkle_leaf(&CHAIN, &bond.commitment());
    fixture.anchors = BTreeSet::from([fixture.statement.anchor]);
    fixture.witness.inputs[0].opening = bond;
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::BondSpendUnsupported));
}

#[test]
fn output_opening_and_context_substitution_are_rejected() {
    let mut fixture = Fixture::valid();
    let (wrong, _) = note(&fixture.receiver_owner, NATIVE_ASSET_ID, 98, 2, 1);
    fixture.witness.outputs[0].opening = wrong;
    assert_eq!(fixture.check(), Err(RelationError::CommitmentMismatch));
    fixture.statement.chain_id[0] ^= 1;
    assert_eq!(fixture.check(), Err(RelationError::ChainMismatch));
    fixture.statement.chain_id = CHAIN;
    fixture.statement.validation_tag[0] ^= 1;
    assert_eq!(fixture.check(), Err(RelationError::ContextMismatch));
}

#[test]
fn duplicate_output_is_distinct_from_a_mismatched_opening() {
    fn second_output(fixture: &Fixture, serial: u8) -> (PaymentOutput, OutputWitness) {
        let (opening, _) = note(&fixture.receiver_owner, NATIVE_ASSET_ID, 49, serial, 1);
        let commitment = opening.commitment();
        let context = output_encryption_context(CHAIN, 1, TAG, 1, &commitment).unwrap();
        let public_key = fixture.recipient.public_key();
        let (envelope, encryption) =
            seal_for_relation(&public_key, &context, &opening.private_opening_bytes()).unwrap();
        (
            PaymentOutput {
                commitment,
                envelope,
            },
            OutputWitness {
                opening,
                recipient_public_key: public_key,
                encryption,
            },
        )
    }

    // Public synthetic values: 99 = 49 + 49 + 1 native fee.
    let mut fixture = Fixture::new(99, 49, 1, NATIVE_ASSET_ID, NATIVE_ASSET_ID);
    let first_commitment = fixture.statement.outputs[0].commitment;
    let (distinct_output, distinct_witness) = second_output(&fixture, 3);
    assert_ne!(distinct_output.commitment, first_commitment);
    fixture.statement.outputs.push(distinct_output);
    fixture.witness.outputs.push(distinct_witness);
    fixture.resign();
    assert_eq!(fixture.check(), Ok(()));

    // A public duplicate with a different private opening fails the earlier comparison.
    let distinct_commitment = fixture.statement.outputs[1].commitment;
    fixture.statement.outputs[1].commitment = first_commitment;
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::CommitmentMismatch));
    fixture.statement.outputs[1].commitment = distinct_commitment;
    fixture.resign();
    assert_eq!(fixture.check(), Ok(()));

    // Recreate the first opening, with a fresh envelope bound to output index one.
    let (duplicate_output, duplicate_witness) = second_output(&fixture, 2);
    assert_eq!(duplicate_output.commitment, first_commitment);
    let saved_output = std::mem::replace(&mut fixture.statement.outputs[1], duplicate_output);
    let saved_witness = std::mem::replace(&mut fixture.witness.outputs[1], duplicate_witness);
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::DuplicateOutputCommitment));
    fixture.statement.outputs[1] = saved_output;
    fixture.witness.outputs[1] = saved_witness;
    fixture.resign();
    assert_eq!(fixture.check(), Ok(()));
}

#[test]
fn ordinary_payment_rejects_mint_asset_substitution_and_non_native_fee_funding() {
    for fixture in [
        Fixture::new(100, 101, 0, NATIVE_ASSET_ID, NATIVE_ASSET_ID),
        Fixture::new(100, 100, 1, NATIVE_ASSET_ID, NATIVE_ASSET_ID),
        Fixture::new(100, 100, 0, [3; 32], [4; 32]),
        Fixture::new(100, 99, 1, [3; 32], [3; 32]),
    ] {
        assert_eq!(fixture.check(), Err(RelationError::ConservationFailed));
    }
    Fixture::new(100, 100, 0, [3; 32], [3; 32]).check().unwrap();
}

#[test]
fn duplicate_input_cannot_choose_a_fresh_nullifier_or_count_value_twice() {
    let mut fixture = Fixture::valid();
    let (opening, secret) = note(&fixture.owner, NATIVE_ASSET_ID, 100, 1, 1);
    fixture.witness.inputs.push(InputWitness {
        opening,
        nullifier_secret: secret,
        membership: MerklePath::new(0, vec![]).unwrap(),
        owner_public_key: fixture.owner.public_key(),
        authorization: vec![],
    });
    fixture
        .statement
        .input_nullifiers
        .push(fixture.statement.input_nullifiers[0]);
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::DuplicateNullifier));
    fixture.statement.input_nullifiers[1][0] ^= 1;
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::NullifierMismatch));
}

#[test]
fn checked_per_asset_totals_reject_overflow() {
    let mut fixture = Fixture::new(u64::MAX, u64::MAX, 0, NATIVE_ASSET_ID, NATIVE_ASSET_ID);
    let (second, second_secret) = note(&fixture.owner, NATIVE_ASSET_ID, u64::MAX, 3, 1);
    let first_leaf = merkle_leaf(&CHAIN, &fixture.witness.inputs[0].opening.commitment());
    let second_leaf = merkle_leaf(&CHAIN, &second.commitment());
    let root = merkle_parent(&CHAIN, &first_leaf, &second_leaf);
    fixture.witness.inputs[0].membership = MerklePath::new(0, vec![second_leaf]).unwrap();
    fixture
        .statement
        .input_nullifiers
        .push(second.nullifier(&second_secret).unwrap());
    fixture.witness.inputs.push(InputWitness {
        opening: second,
        nullifier_secret: second_secret,
        membership: MerklePath::new(1, vec![first_leaf]).unwrap(),
        owner_public_key: fixture.owner.public_key(),
        authorization: vec![],
    });
    fixture.statement.anchor = root;
    fixture.anchors = BTreeSet::from([root]);
    fixture.resign();
    assert_eq!(fixture.check(), Err(RelationError::AmountOverflow));
}

#[test]
fn existing_note_nullifier_survives_another_anchor_and_current_protocol_version() {
    let mut fixture = Fixture::valid();
    let original = fixture.statement.input_nullifiers[0];
    let path = MerklePath::new(0, vec![[0x81; 64]]).unwrap();
    let anchor = path.root(&CHAIN, &fixture.witness.inputs[0].opening.commitment());
    fixture.witness.inputs[0].membership = path;
    fixture.statement.anchor = anchor;
    fixture.anchors = BTreeSet::from([anchor]);
    fixture.statement.protocol_version = 2;
    let (output, _) = note(&fixture.receiver_owner, NATIVE_ASSET_ID, 99, 2, 2);
    let commitment = output.commitment();
    let context = output_encryption_context(CHAIN, 2, TAG, 0, &commitment).unwrap();
    let (envelope, encryption) = seal_for_relation(
        &fixture.recipient.public_key(),
        &context,
        &output.private_opening_bytes(),
    )
    .unwrap();
    fixture.statement.outputs[0] = PaymentOutput {
        commitment,
        envelope,
    };
    fixture.witness.outputs[0].opening = output;
    fixture.witness.outputs[0].encryption = encryption;
    fixture.resign();
    fixture.check().unwrap();
    assert_eq!(
        fixture.witness.inputs[0]
            .opening
            .nullifier(&fixture.witness.inputs[0].nullifier_secret)
            .unwrap(),
        original
    );
}

#[test]
fn merkle_index_depth_and_statement_resource_bounds_are_enforced() {
    assert!(matches!(
        MerklePath::new(1, vec![]),
        Err(RelationError::InvalidPath)
    ));
    assert!(matches!(
        MerklePath::new(2, vec![[0; 64]]),
        Err(RelationError::InvalidPath)
    ));
    assert!(matches!(
        MerklePath::new(1_u64 << 32, vec![[0; 64]; 32]),
        Err(RelationError::InvalidPath)
    ));
    assert!(matches!(
        MerklePath::new(0, vec![[0; 64]; 33]),
        Err(RelationError::InvalidPath)
    ));
    assert!(MerklePath::new((1_u64 << 32) - 1, vec![[0; 64]; 32]).is_ok());
    let mut fixture = Fixture::valid();
    fixture.statement.input_nullifiers.clear();
    assert_eq!(
        fixture.statement.canonical_bytes(),
        Err(RelationError::LimitExceeded)
    );
    fixture.statement.input_nullifiers = vec![[0; 64]; 9];
    assert_eq!(
        fixture.statement.canonical_bytes(),
        Err(RelationError::LimitExceeded)
    );
    fixture.statement.input_nullifiers = vec![[0; 64]];
    let large = PaymentOutput {
        commitment: [1; 64],
        envelope: SealedNote {
            kem_ciphertext: vec![0; 1568],
            nonce: [0; 12],
            ciphertext: vec![0; 16 * 1024 + 16],
        },
    };
    fixture.statement.outputs = vec![large; 8];
    assert_eq!(
        fixture.statement.canonical_bytes(),
        Err(RelationError::LimitExceeded)
    );
}
