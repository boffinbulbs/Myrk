use std::collections::BTreeSet;

use thorum_core::Amount;
use thorum_crypto_lab::{
    seal_for_relation, verify_encryption_witness, AuthorizationKey, Error as CryptoError, RecipientKey,
};
use thorum_relation_lab::*;

const CHAIN: ChainId = [0x11; 32];
const TAG: [u8; 32] = [0x22; 32];

struct Receiver {
    owner: AuthorizationKey,
    kem: RecipientKey,
    secret: NullifierSecret,
    capability: RecipientCapability,
}

impl Receiver {
    fn new() -> Self {
        let owner = AuthorizationKey::generate().unwrap();
        let kem = RecipientKey::generate().unwrap();
        let secret = NullifierSecret::from_bytes([0xf9; 32]);
        let capability =
            RecipientCapability::new(CHAIN, &owner.public_key(), &kem.public_key(), &secret)
                .unwrap();
        Self {
            owner,
            kem,
            secret,
            capability,
        }
    }

    fn opening(&self, policy: NotePolicy) -> NoteOpening {
        public_output(&self.capability, 1, 99, policy)
    }
}

// The sender interface receives no nullifier secret or receiver private key.
fn public_output(
    capability: &RecipientCapability,
    version: u32,
    amount: u64,
    policy: NotePolicy,
) -> NoteOpening {
    NoteOpening::new_recipient(
        NoteParameters {
            chain_id: CHAIN,
            creation_version: version,
            asset_id: NATIVE_ASSET_ID,
            amount: Amount::from_atomic(amount),
            serial: [0x33; 32],
            policy,
        },
        capability,
        [0x44; 32],
    )
    .unwrap()
}

fn transaction(
    input: NoteOpening,
    secret: NullifierSecret,
    owner: &AuthorizationKey,
    output: NoteOpening,
    recipient_key: &[u8],
    version: u32,
    path: MerklePath,
) -> (PaymentStatement, PaymentWitness) {
    let anchor = path.root(&CHAIN, &input.commitment());
    let nullifier = input.nullifier(&secret).unwrap();
    let commitment = output.commitment();
    let context = output_encryption_context(CHAIN, version, TAG, 0, &commitment).unwrap();
    let (envelope, encryption) =
        seal_for_relation(recipient_key, &context, &output.private_opening_bytes()).unwrap();
    let statement = PaymentStatement {
        chain_id: CHAIN,
        protocol_version: version,
        validation_tag: TAG,
        anchor,
        input_nullifiers: vec![nullifier],
        outputs: vec![PaymentOutput {
            commitment,
            envelope,
        }],
        native_fee: Amount::from_atomic(1),
    };
    let signature = owner
        .sign(
            &statement.authorization_context().unwrap(),
            &statement.authorization_message().unwrap(),
        )
        .unwrap();
    let witness = PaymentWitness {
        inputs: vec![InputWitness {
            opening: input,
            nullifier_secret: secret,
            membership: path,
            owner_public_key: owner.public_key(),
            authorization: signature,
        }],
        outputs: vec![OutputWitness {
            opening: output,
            recipient_public_key: recipient_key.to_vec(),
            encryption,
        }],
    };
    (statement, witness)
}

fn sender_payment(
    capability: &RecipientCapability,
    delivery_key: &[u8],
) -> (PaymentStatement, PaymentWitness) {
    let owner = AuthorizationKey::generate().unwrap();
    let secret = NullifierSecret::from_bytes([1; 32]);
    let input = NoteOpening::new(
        NoteParameters {
            chain_id: CHAIN,
            creation_version: 1,
            asset_id: NATIVE_ASSET_ID,
            amount: Amount::from_atomic(100),
            serial: [1; 32],
            policy: NotePolicy::Payment,
        },
        &owner.public_key(),
        &secret,
        [2; 32],
    )
    .unwrap();
    transaction(
        input,
        secret,
        &owner,
        public_output(capability, 1, 99, NotePolicy::Payment),
        delivery_key,
        1,
        MerklePath::new(0, vec![]).unwrap(),
    )
}

fn check(statement: &PaymentStatement, witness: &PaymentWitness) -> Result<(), RelationError> {
    check_payment(
        statement,
        witness,
        &PaymentContext {
            chain_id: CHAIN,
            protocol_version: statement.protocol_version,
            validation_tag: TAG,
            accepted_anchors: &BTreeSet::from([statement.anchor]),
            spent_nullifiers: &BTreeSet::new(),
        },
    )
}

fn recovery_context(note: &NoteOpening) -> RecoveryContext {
    RecoveryContext {
        chain_id: CHAIN,
        creation_version: 1,
        expected_commitment: note.commitment(),
    }
}

fn fields(bytes: &[u8]) -> Vec<Vec<u8>> {
    let mut remaining = bytes;
    let mut result = vec![];
    while !remaining.is_empty() {
        let len = u32::from_be_bytes(remaining[..4].try_into().unwrap()) as usize;
        result.push(remaining[4..4 + len].to_vec());
        remaining = &remaining[4 + len..];
    }
    result
}

fn encode(fields: &[Vec<u8>]) -> Vec<u8> {
    let mut bytes = vec![];
    for field in fields {
        bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
        bytes.extend_from_slice(field);
    }
    bytes
}

#[test]
fn generated_authority_has_explicit_backup_restore_and_chain_binding() {
    let owner = AuthorizationKey::generate().unwrap();
    let kem = RecipientKey::generate().unwrap();
    let secret = NullifierSecret::generate().unwrap();
    let restored = NullifierSecret::from_bytes(*secret.export_backup());
    let first =
        RecipientCapability::new(CHAIN, &owner.public_key(), &kem.public_key(), &secret).unwrap();
    let second =
        RecipientCapability::new(CHAIN, &owner.public_key(), &kem.public_key(), &restored).unwrap();
    assert!(first == second);
    let other_chain =
        RecipientCapability::new([9; 32], &owner.public_key(), &kem.public_key(), &restored)
            .unwrap();
    assert_ne!(
        first.nullifier_secret_binding(),
        other_chain.nullifier_secret_binding()
    );
    assert_ne!(
        first.encryption_key_binding(),
        other_chain.encryption_key_binding()
    );
}

#[test]
fn capability_codec_rejects_every_truncation_bad_lengths_versions_keys_and_trailing_bytes() {
    let receiver = Receiver::new();
    let bytes = receiver.capability.to_bytes();
    assert!(RecipientCapability::from_bytes(&bytes, CHAIN).unwrap() == receiver.capability);
    for end in 0..bytes.len() {
        assert!(
            RecipientCapability::from_bytes(&bytes[..end], CHAIN).is_err(),
            "truncation {end}"
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert!(RecipientCapability::from_bytes(&trailing, CHAIN).is_err());
    assert!(RecipientCapability::from_bytes(&bytes, [9; 32]).is_err());
    assert!(RecipientCapability::from_bytes(&vec![0; MAX_CAPABILITY_BYTES + 1], CHAIN).is_err());
    for (index, value) in [
        (0, b"thorum.relation-lab.recipient-capability.v1".to_vec()),
        (1, 3u16.to_be_bytes().to_vec()),
        (2, vec![0; 31]),
        (3, vec![0; 63]),
        (4, vec![0; 65]),
        (5, vec![0; 1567]),
        (5, vec![0xff; 1568]),
    ] {
        let mut mutated = fields(&bytes);
        mutated[index] = value;
        assert!(RecipientCapability::from_bytes(&encode(&mutated), CHAIN).is_err());
    }
    let mut oversized_field = bytes;
    oversized_field[..4].copy_from_slice(&u32::MAX.to_be_bytes());
    assert!(RecipientCapability::from_bytes(&oversized_field, CHAIN).is_err());
}

#[test]
fn typed_recovery_is_exact_bounded_and_never_accepts_legacy_or_unknown_policy() {
    let receiver = Receiver::new();
    let note = receiver.opening(NotePolicy::Payment);
    let context = recovery_context(&note);
    let bytes = note.private_opening_bytes();
    let recover = |payload: &[u8]| {
        NoteOpening::recover_recipient(payload, &context, &receiver.capability, &receiver.secret)
    };
    let recovered = recover(&bytes).unwrap();
    assert_eq!(recovered.encoding_version(), 2);
    assert_eq!(
        recovered.private_opening_bytes().as_slice(),
        bytes.as_slice()
    );
    assert!(!bytes.windows(32).any(|window| window == [0xf9; 32]));
    for end in 0..bytes.len() {
        assert!(recover(&bytes[..end]).is_err(), "truncation {end}");
    }
    let mut trailing = bytes.to_vec();
    trailing.push(0);
    assert!(recover(&trailing).is_err());
    assert!(recover(&vec![0; MAX_RECIPIENT_OPENING_BYTES + 1]).is_err());
    for (index, value) in [
        (0, b"thorum.relation-lab.note-opening.v1".to_vec()),
        (1, 1u16.to_be_bytes().to_vec()),
        (1, 3u16.to_be_bytes().to_vec()),
        (2, vec![0; 31]),
        (3, vec![0; 8]),
        (4, vec![0; 33]),
        (5, vec![0; 7]),
        (6, vec![0; 63]),
        (7, vec![0; 65]),
        (8, vec![0; 32]),
        (9, vec![0; 31]),
        (10, vec![0; 33]),
        (11, vec![2]),
        (11, vec![0, 0]),
    ] {
        let mut mutated = fields(&bytes);
        mutated[index] = value;
        assert!(recover(&encode(&mutated)).is_err(), "field {index}");
    }
    let legacy = NoteOpening::new(
        NoteParameters {
            chain_id: CHAIN,
            creation_version: 1,
            asset_id: NATIVE_ASSET_ID,
            amount: Amount::from_atomic(99),
            serial: [0x33; 32],
            policy: NotePolicy::Payment,
        },
        &receiver.owner.public_key(),
        &receiver.secret,
        [0x44; 32],
    )
    .unwrap();
    assert!(recover(&legacy.private_opening_bytes()).is_err());
    assert_ne!(legacy.commitment(), note.commitment());
}

#[test]
fn recovery_requires_authenticated_creation_commitment_capability_and_receiver_secret() {
    let receiver = Receiver::new();
    let note = receiver.opening(NotePolicy::Payment);
    let bytes = note.private_opening_bytes();
    let mut context = recovery_context(&note);
    context.chain_id = [9; 32];
    assert!(NoteOpening::recover_recipient(
        &bytes,
        &context,
        &receiver.capability,
        &receiver.secret
    )
    .is_err());
    context = recovery_context(&note);
    context.creation_version = 2;
    assert!(NoteOpening::recover_recipient(
        &bytes,
        &context,
        &receiver.capability,
        &receiver.secret
    )
    .is_err());
    context = recovery_context(&note);
    context.expected_commitment[63] ^= 1;
    assert!(matches!(
        NoteOpening::recover_recipient(&bytes, &context, &receiver.capability, &receiver.secret),
        Err(RelationError::CommitmentMismatch)
    ));
    context = recovery_context(&note);
    let wrong_secret = NullifierSecret::from_bytes([8; 32]);
    assert!(matches!(
        NoteOpening::recover_recipient(&bytes, &context, &receiver.capability, &wrong_secret),
        Err(RelationError::NullifierSecretMismatch)
    ));
    assert_eq!(
        note.nullifier(&wrong_secret),
        Err(RelationError::NullifierSecretMismatch)
    );
    let original_nf = note.nullifier(&receiver.secret).unwrap();
    let replacement_kem = RecipientKey::generate().unwrap();
    let replacement_owner = AuthorizationKey::generate().unwrap();
    for replacement in [
        RecipientCapability::new(
            CHAIN,
            &replacement_owner.public_key(),
            &receiver.kem.public_key(),
            &receiver.secret,
        )
        .unwrap(),
        RecipientCapability::new(
            CHAIN,
            &receiver.owner.public_key(),
            &replacement_kem.public_key(),
            &receiver.secret,
        )
        .unwrap(),
        RecipientCapability::new(
            CHAIN,
            &receiver.owner.public_key(),
            &receiver.kem.public_key(),
            &wrong_secret,
        )
        .unwrap(),
    ] {
        assert!(matches!(
            NoteOpening::recover_recipient(&bytes, &context, &replacement, &receiver.secret),
            Err(RelationError::CapabilityMismatch)
        ));
    }
    assert_eq!(original_nf, note.nullifier(&receiver.secret).unwrap());
    for index in [4, 5, 9, 10] {
        let mut mutated = fields(&bytes);
        mutated[index][0] ^= 1;
        assert!(matches!(
            NoteOpening::recover_recipient(
                &encode(&mutated),
                &context,
                &receiver.capability,
                &receiver.secret
            ),
            Err(RelationError::CommitmentMismatch)
        ));
    }
}

#[test]
fn recovered_bond_policy_rejects_invalid_epoch_order_and_owner_vote_equality() {
    let receiver = Receiver::new();
    let voter = AuthorizationKey::generate().unwrap();
    let policy = BondPolicy::new(&voter.public_key(), 1, 4, 20).unwrap();
    let note = receiver.opening(NotePolicy::Bond(policy));
    let bytes = note.private_opening_bytes();
    let context = recovery_context(&note);
    NoteOpening::recover_recipient(&bytes, &context, &receiver.capability, &receiver.secret)
        .unwrap();
    for (index, value, expected) in [
        (
            13,
            5u64.to_be_bytes().to_vec(),
            RelationError::InvalidBondPolicy,
        ),
        (
            15,
            4u64.to_be_bytes().to_vec(),
            RelationError::InvalidBondPolicy,
        ),
        (
            12,
            receiver.capability.owner_key_binding().to_vec(),
            RelationError::RestrictedKeyNotDistinct,
        ),
    ] {
        let mut mutated = fields(&bytes);
        mutated[index] = value;
        assert!(
            matches!(NoteOpening::recover_recipient(&encode(&mutated), &context, &receiver.capability, &receiver.secret), Err(error) if error == expected)
        );
    }
    let same_key = BondPolicy::new(&receiver.owner.public_key(), 1, 4, 20).unwrap();
    assert!(matches!(
        NoteOpening::new_recipient(
            NoteParameters {
                chain_id: CHAIN,
                creation_version: 1,
                asset_id: NATIVE_ASSET_ID,
                amount: Amount::from_atomic(99),
                serial: [3; 32],
                policy: NotePolicy::Bond(same_key),
            },
            &receiver.capability,
            [4; 32]
        ),
        Err(RelationError::RestrictedKeyNotDistinct)
    ));
}

#[test]
fn public_capability_output_survives_sender_discard_and_receiver_recovers_and_spends() {
    let receiver = Receiver::new();
    let statement = {
        let (statement, witness) = sender_payment(
            &receiver.capability,
            receiver.capability.recipient_public_key(),
        );
        check(&statement, &witness).unwrap();
        // Dropping all sender witnesses leaves only the authorized public statement.
        statement
    };
    let delivered = &statement.outputs[0];
    let creation = RecoveryContext {
        chain_id: CHAIN,
        creation_version: 1,
        expected_commitment: delivered.commitment,
    };
    let opening = statement
        .recover_recipient_output(
            0,
            TAG,
            &creation,
            &receiver.kem,
            &receiver.capability,
            &receiver.secret,
        )
        .unwrap();
    let stable_nf = opening.nullifier(&receiver.secret).unwrap();
    for version in [1, 7] {
        let restored = statement
            .recover_recipient_output(
                0,
                TAG,
                &creation,
                &receiver.kem,
                &receiver.capability,
                &receiver.secret,
            )
            .unwrap();
        let path = if version == 1 {
            MerklePath::new(0, vec![]).unwrap()
        } else {
            MerklePath::new(1, vec![[0x55; 64]]).unwrap()
        };
        let (spend, mut witness) = transaction(
            restored,
            NullifierSecret::from_bytes(*receiver.secret.export_backup()),
            &receiver.owner,
            public_output(&receiver.capability, version, 98, NotePolicy::Payment),
            receiver.capability.recipient_public_key(),
            version,
            path,
        );
        assert_eq!(spend.input_nullifiers, vec![stable_nf]);
        check(&spend, &witness).unwrap();
        witness.inputs[0].nullifier_secret = NullifierSecret::from_bytes([1; 32]);
        assert_eq!(
            check(&spend, &witness),
            Err(RelationError::NullifierSecretMismatch)
        );
        witness.inputs[0].nullifier_secret =
            NullifierSecret::from_bytes(*receiver.secret.export_backup());
        let restricted_key = AuthorizationKey::generate().unwrap();
        witness.inputs[0].owner_public_key = restricted_key.public_key();
        witness.inputs[0].authorization = restricted_key
            .sign(
                &spend.authorization_context().unwrap(),
                &spend.authorization_message().unwrap(),
            )
            .unwrap();
        assert_eq!(
            check(&spend, &witness),
            Err(RelationError::OwnerKeyMismatch)
        );
    }
}

fn recover_output(
    statement: &PaymentStatement,
    index: usize,
    tag: [u8; 32],
    creation: &RecoveryContext,
    receiver: &Receiver,
) -> Result<NoteOpening, RelationError> {
    statement.recover_recipient_output(
        index,
        tag,
        creation,
        &receiver.kem,
        &receiver.capability,
        &receiver.secret,
    )
}

#[test]
fn statement_recovery_binds_creation_context_and_retained_authority() {
    let receiver = Receiver::new();
    let (mut statement, witness) = sender_payment(
        &receiver.capability,
        receiver.capability.recipient_public_key(),
    );
    check(&statement, &witness).unwrap();
    let mut creation = recovery_context(&witness.outputs[0].opening);
    let expected_nullifier = witness.outputs[0]
        .opening
        .nullifier(&receiver.secret)
        .unwrap();
    drop(witness);
    let recovered = recover_output(&statement, 0, TAG, &creation, &receiver).unwrap();
    assert_eq!(recovered.commitment(), creation.expected_commitment);
    assert_eq!(
        recovered.nullifier(&receiver.secret).unwrap(),
        expected_nullifier
    );

    for index in [1, usize::MAX] {
        assert_eq!(
            recover_output(&statement, index, TAG, &creation, &receiver).err(),
            Some(RelationError::LimitExceeded)
        );
    }
    for count in [0, 9] {
        let mut changed = statement.clone();
        changed.outputs.resize(count, statement.outputs[0].clone());
        assert_eq!(
            recover_output(&changed, 0, TAG, &creation, &receiver).err(),
            Some(RelationError::LimitExceeded)
        );
    }
    creation.chain_id[0] ^= 1;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::ChainMismatch)
    );
    creation.chain_id[0] ^= 1;
    creation.creation_version = 2;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::VersionMismatch)
    );
    creation.creation_version = 1;
    assert_eq!(
        recover_output(&statement, 0, [9; 32], &creation, &receiver).err(),
        Some(RelationError::ContextMismatch)
    );
    creation.expected_commitment[63] ^= 1;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::CommitmentMismatch)
    );
    creation.expected_commitment[63] ^= 1;

    statement.validation_tag[0] ^= 1;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::ContextMismatch)
    );
    assert_eq!(
        recover_output(&statement, 0, statement.validation_tag, &creation, &receiver).err(),
        Some(RelationError::Crypto(CryptoError::AuthenticationFailed))
    );
    statement.validation_tag[0] ^= 1;
    statement.outputs[0].commitment[63] ^= 1;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::CommitmentMismatch)
    );
    creation.expected_commitment[63] ^= 1;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::Crypto(CryptoError::AuthenticationFailed))
    );
    statement.outputs[0].commitment[63] ^= 1;
    creation.expected_commitment[63] ^= 1;
    statement.outputs[0].envelope.ciphertext[0] ^= 1;
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::Crypto(CryptoError::AuthenticationFailed))
    );
    statement.outputs[0].envelope.ciphertext[0] ^= 1;

    let wrong_key = RecipientKey::generate().unwrap();
    assert_eq!(
        statement
            .recover_recipient_output(
                0,
                TAG,
                &creation,
                &wrong_key,
                &receiver.capability,
                &receiver.secret,
            )
            .err(),
        Some(RelationError::RecipientKeyMismatch)
    );
    let wrong_secret = NullifierSecret::from_bytes([8; 32]);
    assert_eq!(
        statement
            .recover_recipient_output(
                0,
                TAG,
                &creation,
                &receiver.kem,
                &receiver.capability,
                &wrong_secret,
            )
            .err(),
        Some(RelationError::NullifierSecretMismatch)
    );
    let wrong_capability = RecipientCapability::new(
        CHAIN,
        &receiver.owner.public_key(),
        &receiver.kem.public_key(),
        &wrong_secret,
    )
    .unwrap();
    assert_eq!(
        statement
            .recover_recipient_output(
                0,
                TAG,
                &creation,
                &receiver.kem,
                &wrong_capability,
                &receiver.secret,
            )
            .err(),
        Some(RelationError::CapabilityMismatch)
    );
    let restored = recover_output(&statement, 0, TAG, &creation, &receiver).unwrap();
    assert_eq!(restored.commitment(), creation.expected_commitment);
    assert_eq!(
        restored.nullifier(&receiver.secret).unwrap(),
        expected_nullifier
    );
}

#[test]
fn statement_recovery_binds_the_actual_second_output_index() {
    let sender = Receiver::new();
    let receiver = Receiver::new();
    let input = public_output(&sender.capability, 1, 100, NotePolicy::Payment);
    let first = public_output(&receiver.capability, 1, 49, NotePolicy::Payment);
    let second = public_output(&receiver.capability, 1, 50, NotePolicy::Payment);
    let creation = recovery_context(&second);
    let expected_nullifier = second.nullifier(&receiver.secret).unwrap();
    let (mut statement, mut witness) = transaction(
        input,
        NullifierSecret::from_bytes(*sender.secret.export_backup()),
        &sender.owner,
        first,
        receiver.capability.recipient_public_key(),
        1,
        MerklePath::new(0, vec![]).unwrap(),
    );
    let context = output_encryption_context(CHAIN, 1, TAG, 1, &creation.expected_commitment).unwrap();
    let (envelope, encryption) = seal_for_relation(
        receiver.capability.recipient_public_key(),
        &context,
        &second.private_opening_bytes(),
    )
    .unwrap();
    statement.outputs.push(PaymentOutput {
        commitment: creation.expected_commitment,
        envelope,
    });
    witness.outputs.push(OutputWitness {
        opening: second,
        recipient_public_key: receiver.kem.public_key(),
        encryption,
    });
    let message = statement.authorization_message().unwrap();
    let authorization_context = statement.authorization_context().unwrap();
    for input in &mut witness.inputs {
        input.authorization = sender
            .owner
            .sign(&authorization_context, &message)
            .unwrap();
    }
    check(&statement, &witness).unwrap();
    drop(witness);
    let recovered = recover_output(&statement, 1, TAG, &creation, &receiver).unwrap();
    assert_eq!(recovered.commitment(), creation.expected_commitment);
    assert_eq!(
        recovered.nullifier(&receiver.secret).unwrap(),
        expected_nullifier
    );
    statement.outputs.swap(0, 1);
    assert_eq!(
        recover_output(&statement, 0, TAG, &creation, &receiver).err(),
        Some(RelationError::Crypto(CryptoError::AuthenticationFailed))
    );
    statement.outputs.swap(0, 1);
    let restored = recover_output(&statement, 1, TAG, &creation, &receiver).unwrap();
    assert_eq!(restored.commitment(), creation.expected_commitment);
    assert_eq!(
        restored.nullifier(&receiver.secret).unwrap(),
        expected_nullifier
    );
}

#[test]
fn legitimate_sender_signature_cannot_authorize_delivery_key_substitution() {
    let receiver = Receiver::new();
    let attacker = RecipientKey::generate().unwrap();
    let (statement, witness) = sender_payment(&receiver.capability, &attacker.public_key());
    let output = &witness.outputs[0];
    let context =
        output_encryption_context(CHAIN, 1, TAG, 0, &statement.outputs[0].commitment).unwrap();
    // The ciphertext and sender witness are valid for the attacker key. Ownership
    // and statement authorization are also valid, so the committed key is decisive.
    verify_encryption_witness(
        &attacker.public_key(),
        &context,
        &output.opening.private_opening_bytes(),
        &output.encryption,
        &statement.outputs[0].envelope,
    )
    .unwrap();
    assert_eq!(
        check(&statement, &witness),
        Err(RelationError::RecipientKeyMismatch)
    );
}

#[test]
fn whole_capability_substitution_is_detected_during_expected_receiver_recovery() {
    let intended = Receiver::new();
    let attacker = Receiver::new();
    let (statement, witness) = sender_payment(
        &attacker.capability,
        attacker.capability.recipient_public_key(),
    );
    // A self consistent alternate capability passes the relation. Routing must
    // authenticate the intended capability before payment construction.
    check(&statement, &witness).unwrap();
    let note = &witness.outputs[0].opening;
    let context = recovery_context(note);
    assert!(matches!(
        NoteOpening::recover_recipient(
            &note.private_opening_bytes(),
            &context,
            &intended.capability,
            &intended.secret
        ),
        Err(RelationError::CapabilityMismatch)
    ));
}

#[test]
fn restricted_v2_voting_uses_deliberately_shared_authority_and_stable_note_format() {
    let receiver = Receiver::new();
    let voter = AuthorizationKey::generate().unwrap();
    let policy = BondPolicy::new(&voter.public_key(), 1, 4, 20).unwrap();
    let bond = receiver.opening(NotePolicy::Bond(policy));
    let plaintext = bond.private_opening_bytes();
    let recovery = recovery_context(&bond);
    let duty = [0x66; 32];
    let vote_nf = bond.vote_nullifier(&receiver.secret, 12, &duty).unwrap();
    for version in [1, 7] {
        let opening = NoteOpening::recover_recipient(
            &plaintext,
            &recovery,
            &receiver.capability,
            &receiver.secret,
        )
        .unwrap();
        let path = if version == 1 {
            MerklePath::new(0, vec![]).unwrap()
        } else {
            MerklePath::new(0, vec![[0x77; 64]]).unwrap()
        };
        let anchor = path.root(&CHAIN, &opening.commitment());
        let statement = StakeStatement {
            chain_id: CHAIN,
            protocol_version: version,
            validation_tag: TAG,
            snapshot_anchor: anchor,
            snapshot_epoch: 10,
            epoch: 12,
            duty_id: duty,
            decision_digest: [0x88; 64],
            required_lock_through_epoch: 13,
            claims: vec![StakeClaim {
                vote_nullifier: vote_nf,
                voting_key_binding: key_binding(&voter.public_key()).unwrap(),
                weight: Amount::from_atomic(99),
            }],
        };
        let signature = voter
            .sign(
                &statement.authorization_context().unwrap(),
                &statement.authorization_message().unwrap(),
            )
            .unwrap();
        let mut witnesses = vec![BondWitness {
            opening,
            nullifier_secret: NullifierSecret::from_bytes(*receiver.secret.export_backup()),
            membership: path,
            voting_public_key: voter.public_key(),
            authorization: signature,
        }];
        let spent = BTreeSet::new();
        let used = BTreeSet::new();
        let context = StakeContext {
            chain_id: CHAIN,
            protocol_version: version,
            validation_tag: TAG,
            snapshot_anchor: anchor,
            snapshot_epoch: 10,
            epoch: 12,
            duty_id: duty,
            required_lock_through_epoch: 13,
            spent_bond_nullifiers: &spent,
            used_vote_nullifiers: &used,
        };
        assert_eq!(
            check_stake_eligibility(&statement, &witnesses, &context),
            Ok(Amount::from_atomic(99))
        );
        witnesses[0].nullifier_secret = NullifierSecret::from_bytes([1; 32]);
        assert_eq!(
            check_stake_eligibility(&statement, &witnesses, &context),
            Err(RelationError::NullifierSecretMismatch)
        );
    }
}
