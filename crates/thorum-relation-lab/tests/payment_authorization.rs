//! Public synthetic authorization mapping. No keys, RNG or private witnesses.

use sha3::{Digest, Sha3_512};
use thorum_core::Amount;
use thorum_crypto_lab::{Context, Error as CryptoError, SealedNote};
use thorum_relation_lab::{Digest64, PaymentOutput, PaymentStatement, RelationError};

fn synthetic_statement() -> PaymentStatement {
    PaymentStatement {
        chain_id: [0x11; 32],
        protocol_version: 0x01020304,
        validation_tag: [0x22; 32],
        anchor: [0x33; 64],
        input_nullifiers: vec![[0x44; 64]],
        outputs: vec![PaymentOutput {
            commitment: [0x55; 64],
            envelope: SealedNote {
                kem_ciphertext: vec![0x66; 1568],
                nonce: [0x77; 12],
                ciphertext: vec![0x88; 16],
            },
        }],
        native_fee: Amount::from_atomic(0x0102030405060708),
    }
}

fn independently_framed_context(statement: &PaymentStatement, message: &Digest64) -> Context {
    let mut preimage = [0; 115];
    preimage[0..4].copy_from_slice(&[0, 0, 0, 43]);
    preimage[4..47].copy_from_slice(b"thorum.relation-lab.payment-auth-context.v1");
    preimage[47..51].copy_from_slice(&[0, 0, 0, 64]);
    preimage[51..115].copy_from_slice(message);
    let tag_digest: Digest64 = Sha3_512::digest(preimage).into();
    Context {
        chain_id: statement.chain_id,
        protocol_version: statement.protocol_version,
        output_tag: tag_digest[..32].try_into().unwrap(),
    }
}

#[test]
fn authorization_uses_the_exact_statement_digest_and_context_framing() {
    let mut statement = synthetic_statement();
    let canonical = statement.canonical_bytes().unwrap();
    assert_eq!(canonical.len(), 1984);
    let mut preimage = [0; 2036];
    preimage[0..4].copy_from_slice(&[0, 0, 0, 44]);
    preimage[4..48].copy_from_slice(b"thorum.relation-lab.payment-authorization.v1");
    preimage[48..52].copy_from_slice(&[0, 0, 7, 192]);
    preimage[52..2036].copy_from_slice(&canonical);
    let message: Digest64 = Sha3_512::digest(preimage).into();
    let context = independently_framed_context(&statement, &message);
    assert_eq!(statement.authorization_message().unwrap(), message);
    assert_eq!(statement.authorization_context().unwrap(), context);

    statement.native_fee = Amount::from_atomic(0x0102030405060709);
    preimage[52..2036].copy_from_slice(&statement.canonical_bytes().unwrap());
    let changed_message: Digest64 = Sha3_512::digest(preimage).into();
    let changed_context = independently_framed_context(&statement, &changed_message);
    assert_ne!(changed_message, message);
    assert_ne!(changed_context, context);
    assert_eq!(statement.authorization_message().unwrap(), changed_message);
    assert_eq!(statement.authorization_context().unwrap(), changed_context);

    statement.native_fee = Amount::from_atomic(0x0102030405060708);
    assert_eq!(statement.authorization_message().unwrap(), message);
    assert_eq!(statement.authorization_context().unwrap(), context);
}

fn assert_public_error(statement: &PaymentStatement, expected: RelationError) {
    assert_eq!(statement.authorization_message(), Err(expected));
    assert_eq!(statement.authorization_context(), Err(expected));
}

#[test]
fn both_public_authorization_methods_preserve_structural_refusals() {
    for count in [0, 9] {
        let mut statement = synthetic_statement();
        statement.input_nullifiers.resize(count, [0x44; 64]);
        assert_public_error(&statement, RelationError::LimitExceeded);

        let mut statement = synthetic_statement();
        let output = statement.outputs[0].clone();
        statement.outputs.resize(count, output);
        assert_public_error(&statement, RelationError::LimitExceeded);
    }
    for length in [1567, 1569] {
        let mut statement = synthetic_statement();
        statement.outputs[0].envelope.kem_ciphertext.resize(length, 0x66);
        assert_public_error(&statement, RelationError::Crypto(CryptoError::InvalidEncoding));
    }
    for (length, expected) in [
        (0, CryptoError::InvalidEncoding),
        (15, CryptoError::InvalidEncoding),
        (16401, CryptoError::LimitExceeded),
    ] {
        let mut statement = synthetic_statement();
        statement.outputs[0].envelope.ciphertext.resize(length, 0x88);
        assert_public_error(&statement, RelationError::Crypto(expected));
    }
}
