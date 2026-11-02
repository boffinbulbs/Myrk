//! Public synthetic codec inputs. No keys, witnesses, RNG or cryptographic checks.

use thorum_core::Amount;
use thorum_crypto_lab::{Error as CryptoError, SealedNote};
use thorum_relation_lab::{
    PaymentOutput, PaymentStatement, RelationError, MAX_PAYMENT_ITEMS, MAX_STATEMENT_BYTES,
};

// Independently specified byte positions for one input and one minimum envelope.
// The payload bytes are synthetic and have no encryption authenticity claim.
fn fixed_wire() -> Vec<u8> {
    let mut bytes = vec![0; 1984];
    bytes[0..4].copy_from_slice(&[0, 0, 0, 40]);
    bytes[4..44].copy_from_slice(b"thorum.relation-lab.payment-statement.v1");
    bytes[44..48].copy_from_slice(&[0, 0, 0, 2]);
    bytes[48..50].copy_from_slice(&[0, 1]);
    bytes[50..54].copy_from_slice(&[0, 0, 0, 32]);
    bytes[54..86].fill(0x11);
    bytes[86..90].copy_from_slice(&[0, 0, 0, 4]);
    bytes[90..94].copy_from_slice(&[1, 2, 3, 4]);
    bytes[94..98].copy_from_slice(&[0, 0, 0, 32]);
    bytes[98..130].fill(0x22);
    bytes[130..134].copy_from_slice(&[0, 0, 0, 64]);
    bytes[134..198].fill(0x33);
    bytes[198..202].copy_from_slice(&[0, 0, 0, 4]);
    bytes[202..206].copy_from_slice(&[0, 0, 0, 1]);
    bytes[206..210].copy_from_slice(&[0, 0, 0, 64]);
    bytes[210..274].fill(0x44);
    bytes[274..278].copy_from_slice(&[0, 0, 0, 4]);
    bytes[278..282].copy_from_slice(&[0, 0, 0, 1]);
    bytes[282..286].copy_from_slice(&[0, 0, 0, 64]);
    bytes[286..350].fill(0x55);
    bytes[350..354].copy_from_slice(&[0, 0, 6, 82]); // 1618 bytes.
    bytes[354..362].copy_from_slice(b"THMLAB01");
    bytes[362..364].copy_from_slice(&[0, 1]);
    bytes[364..368].copy_from_slice(&[0, 0, 6, 32]); // 1568 KEM bytes.
    bytes[368..1936].fill(0x66);
    bytes[1936..1940].copy_from_slice(&[0, 0, 0, 12]);
    bytes[1940..1952].fill(0x77);
    bytes[1952..1956].copy_from_slice(&[0, 0, 0, 16]);
    bytes[1956..1972].fill(0x88);
    bytes[1972..1976].copy_from_slice(&[0, 0, 0, 8]);
    bytes[1976..1984].copy_from_slice(&[1, 2, 3, 4, 5, 6, 7, 8]);
    bytes
}

fn synthetic_statement(inputs: usize, outputs: usize, ciphertext_len: usize) -> PaymentStatement {
    assert!((1..=8).contains(&inputs));
    assert!((1..=8).contains(&outputs));
    assert!((16..=16400).contains(&ciphertext_len));
    PaymentStatement {
        chain_id: [0x11; 32],
        protocol_version: 0x01020304,
        validation_tag: [0x22; 32],
        anchor: [0x33; 64],
        input_nullifiers: (0..inputs)
            .map(|index| [0x44 + index as u8; 64])
            .collect(),
        outputs: (0..outputs)
            .map(|index| PaymentOutput {
                commitment: [0x55 + index as u8; 64],
                envelope: SealedNote {
                    kem_ciphertext: vec![0x66; 1568],
                    nonce: [0x77; 12],
                    ciphertext: vec![0x88; ciphertext_len],
                },
            })
            .collect(),
        native_fee: Amount::from_atomic(0x0102030405060708),
    }
}

#[test]
fn independently_specified_wire_decodes_and_reencodes_exactly() {
    let wire = fixed_wire();
    let expected = synthetic_statement(1, 1, 16);
    assert_eq!(PaymentStatement::from_bytes(&wire).unwrap(), expected);
    assert_eq!(expected.canonical_bytes().unwrap(), wire);
}

#[test]
fn every_truncated_prefix_and_trailing_data_refuse() {
    let wire = fixed_wire();
    for end in 0..wire.len() {
        assert!(PaymentStatement::from_bytes(&wire[..end]).is_err(), "prefix {end}");
    }
    for suffix in [vec![0], vec![0, 0, 0, 0]] {
        let mut changed = wire.clone();
        changed.extend_from_slice(&suffix);
        assert_eq!(PaymentStatement::from_bytes(&changed), Err(RelationError::InvalidEncoding));
    }
}

#[test]
fn counts_are_checked_before_reading_items() {
    for (offset, end) in [(202, 206), (278, 282)] {
        for count in [0_u32, 9, u32::MAX] {
            let mut wire = fixed_wire();
            wire[offset..offset + 4].copy_from_slice(&count.to_be_bytes());
            wire.truncate(end);
            assert_eq!(PaymentStatement::from_bytes(&wire), Err(RelationError::LimitExceeded));
        }
    }
}

#[test]
fn domain_version_and_every_fixed_field_width_are_exact() {
    let mut wire = fixed_wire();
    wire[4] ^= 1;
    assert_eq!(PaymentStatement::from_bytes(&wire), Err(RelationError::UnsupportedEncoding));
    let mut wire = fixed_wire();
    wire[49] = 2;
    assert_eq!(PaymentStatement::from_bytes(&wire), Err(RelationError::UnsupportedEncoding));
    for (offset, width) in [
        (44, 2_u32),
        (50, 32),
        (86, 4),
        (94, 32),
        (130, 64),
        (198, 4),
        (206, 64),
        (274, 4),
        (282, 64),
        (1972, 8),
    ] {
        let mut wire = fixed_wire();
        wire[offset..offset + 4].copy_from_slice(&(width - 1).to_be_bytes());
        assert_eq!(PaymentStatement::from_bytes(&wire), Err(RelationError::InvalidEncoding));
    }
    for offset in [0, 50, 198, 206, 350] {
        let mut wire = fixed_wire();
        wire[offset..offset + 4].copy_from_slice(&u32::MAX.to_be_bytes());
        assert!(PaymentStatement::from_bytes(&wire).is_err());
    }
}

#[test]
fn nested_envelope_errors_and_nested_suffix_propagate() {
    let invalid = Err(RelationError::Crypto(CryptoError::InvalidEncoding));
    for offset in [354, 1939, 1955] {
        let mut wire = fixed_wire();
        wire[offset] ^= 1;
        assert_eq!(PaymentStatement::from_bytes(&wire), invalid);
    }
    let mut wire = fixed_wire();
    wire[363] = 2;
    assert_eq!(
        PaymentStatement::from_bytes(&wire),
        Err(RelationError::Crypto(CryptoError::UnsupportedSuite)),
    );
    let mut wire = fixed_wire();
    wire[364..368].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(PaymentStatement::from_bytes(&wire), invalid);
    let mut wire = fixed_wire();
    wire.insert(1972, 0);
    wire[350..354].copy_from_slice(&1619_u32.to_be_bytes());
    assert_eq!(PaymentStatement::from_bytes(&wire), invalid);
}

#[test]
fn all_supported_counts_preserve_order_and_public_scalar_bits() {
    for inputs in 1..=MAX_PAYMENT_ITEMS {
        for outputs in 1..=MAX_PAYMENT_ITEMS {
            let mut expected = synthetic_statement(inputs, outputs, 16);
            expected.protocol_version = u32::MAX;
            expected.native_fee = Amount::from_atomic(u64::MAX);
            let wire = expected.canonical_bytes().unwrap();
            assert_eq!(PaymentStatement::from_bytes(&wire).unwrap(), expected);
        }
    }
}

#[test]
fn full_outer_byte_bound_is_preserved() {
    let mut expected = synthetic_statement(1, 4, 16400);
    expected.outputs[3].envelope.ciphertext.truncate(9346);
    let mut wire = expected.canonical_bytes().unwrap();
    assert_eq!(wire.len(), 65536);
    assert_eq!(wire.len(), MAX_STATEMENT_BYTES);
    assert_eq!(PaymentStatement::from_bytes(&wire).unwrap(), expected);
    wire.push(0);
    assert_eq!(PaymentStatement::from_bytes(&wire), Err(RelationError::LimitExceeded));
    expected.outputs[3].envelope.ciphertext.push(0);
    assert_eq!(expected.canonical_bytes(), Err(RelationError::LimitExceeded));
}

#[test]
fn parsing_does_not_grant_spending_or_state_authority() {
    let mut expected = synthetic_statement(2, 2, 16);
    expected.input_nullifiers[1] = expected.input_nullifiers[0];
    expected.outputs[1] = expected.outputs[0].clone();
    let wire = expected.canonical_bytes().unwrap();
    assert_eq!(PaymentStatement::from_bytes(&wire).unwrap(), expected);
}
