use thorum_crypto_lab::{
    seal_for_relation, verify_encryption_witness, Context, Error, RecipientKey, SealedNote,
    MAX_NOTE_BYTES, RECIPIENT_KEY_BYTES,
};

fn context() -> Context {
    Context {
        chain_id: [0x14; 32],
        protocol_version: 1,
        output_tag: [0x36; 32],
    }
}

#[test]
fn sender_witness_matches_exact_envelope_and_recipient_recovers_bytes() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    let plaintext = (0..=255).cycle().take(769).collect::<Vec<u8>>();
    let (sealed, witness) = seal_for_relation(&public_key, &context(), &plaintext).unwrap();
    let decoded = SealedNote::from_bytes(&sealed.to_bytes().unwrap()).unwrap();
    verify_encryption_witness(&public_key, &context(), &plaintext, &witness, &decoded).unwrap();
    assert_eq!(
        recipient.open(&context(), &decoded).unwrap().as_slice(),
        plaintext
    );
}

#[test]
fn sender_check_needs_only_the_public_recipient_key() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    drop(recipient);
    let (sealed, witness) = seal_for_relation(&public_key, &context(), b"synthetic note").unwrap();
    verify_encryption_witness(
        &public_key,
        &context(),
        b"synthetic note",
        &witness,
        &sealed,
    )
    .unwrap();
}

#[test]
fn another_fresh_witness_and_changed_plaintext_are_rejected() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    let (sealed, witness) = seal_for_relation(&public_key, &context(), b"synthetic note").unwrap();
    let (_, other_witness) = seal_for_relation(&public_key, &context(), b"synthetic note").unwrap();
    assert_eq!(
        verify_encryption_witness(
            &public_key,
            &context(),
            b"synthetic note",
            &other_witness,
            &sealed
        ),
        Err(Error::AuthenticationFailed)
    );
    for plaintext in [
        b"different note".as_slice(),
        b"synthetic notE".as_slice(),
        b"".as_slice(),
    ] {
        assert_eq!(
            verify_encryption_witness(&public_key, &context(), plaintext, &witness, &sealed),
            Err(Error::AuthenticationFailed)
        );
    }
}

#[test]
fn recipient_substitution_and_every_context_field_are_rejected() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    let wrong_key = RecipientKey::generate().unwrap().public_key();
    let plaintext = b"synthetic note";
    let (sealed, witness) = seal_for_relation(&public_key, &context(), plaintext).unwrap();
    assert_eq!(
        verify_encryption_witness(&wrong_key, &context(), plaintext, &witness, &sealed),
        Err(Error::AuthenticationFailed)
    );
    let mut contexts = [context(); 3];
    contexts[0].chain_id[1] ^= 1;
    contexts[1].protocol_version += 1;
    contexts[2].output_tag[1] ^= 1;
    for changed in contexts {
        assert_eq!(
            verify_encryption_witness(&public_key, &changed, plaintext, &witness, &sealed),
            Err(Error::AuthenticationFailed)
        );
    }
}

#[test]
fn nonce_encapsulation_and_every_ciphertext_region_are_bound() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    let plaintext = b"synthetic note";
    let (sealed, witness) = seal_for_relation(&public_key, &context(), plaintext).unwrap();
    let mut changed = sealed.clone();
    changed.nonce[5] ^= 1;
    assert_eq!(
        verify_encryption_witness(&public_key, &context(), plaintext, &witness, &changed),
        Err(Error::AuthenticationFailed)
    );
    for index in [
        0,
        sealed.kem_ciphertext.len() / 2,
        sealed.kem_ciphertext.len() - 1,
    ] {
        let mut changed = sealed.clone();
        changed.kem_ciphertext[index] ^= 1;
        assert_eq!(
            verify_encryption_witness(&public_key, &context(), plaintext, &witness, &changed),
            Err(Error::AuthenticationFailed)
        );
    }
    for index in [
        0,
        plaintext.len() - 1,
        plaintext.len(),
        sealed.ciphertext.len() - 1,
    ] {
        let mut changed = sealed.clone();
        changed.ciphertext[index] ^= 1;
        assert_eq!(
            verify_encryption_witness(&public_key, &context(), plaintext, &witness, &changed),
            Err(Error::AuthenticationFailed)
        );
    }
}

#[test]
fn sender_check_enforces_payload_and_structural_bounds() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    let (sealed, witness) = seal_for_relation(&public_key, &context(), b"note").unwrap();
    assert!(matches!(
        seal_for_relation(&public_key, &context(), &vec![0; MAX_NOTE_BYTES + 1]),
        Err(Error::LimitExceeded)
    ));
    assert!(matches!(
        seal_for_relation(&[0xFF; RECIPIENT_KEY_BYTES], &context(), b"note"),
        Err(Error::InvalidKey)
    ));
    assert_eq!(
        verify_encryption_witness(
            &public_key,
            &context(),
            &vec![0; MAX_NOTE_BYTES + 1],
            &witness,
            &sealed
        ),
        Err(Error::LimitExceeded)
    );
    let mut truncated = sealed;
    truncated.kem_ciphertext.pop();
    assert_eq!(
        verify_encryption_witness(&public_key, &context(), b"note", &witness, &truncated),
        Err(Error::InvalidEncoding)
    );
}
