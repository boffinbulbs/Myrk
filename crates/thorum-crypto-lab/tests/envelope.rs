use thorum_crypto_lab::{
    seal, verify_authorization, AuthorizationKey, Context, Error, RecipientKey, SealedNote,
    AUTHORIZATION_KEY_BYTES, AUTHORIZATION_SIGNATURE_BYTES, KEM_CIPHERTEXT_BYTES,
    MAX_AUTHORIZATION_BYTES, MAX_NOTE_BYTES, RECIPIENT_KEY_BYTES, TAG_BYTES,
};

fn context() -> Context {
    Context {
        chain_id: [0x31; 32],
        protocol_version: 1,
        output_tag: [0x72; 32],
    }
}

#[test]
fn independent_keys_have_fixed_encodings_and_exact_binary_recovery() {
    let recipient = RecipientKey::generate().unwrap();
    assert_eq!(recipient.public_key().len(), RECIPIENT_KEY_BYTES);
    let plaintext = (0..=255).cycle().take(1024).collect::<Vec<u8>>();
    let sealed = seal(&recipient.public_key(), &context(), &plaintext).unwrap();
    assert_eq!(sealed.kem_ciphertext.len(), KEM_CIPHERTEXT_BYTES);
    assert_eq!(sealed.ciphertext.len(), plaintext.len() + TAG_BYTES);
    let bytes = sealed.to_bytes().unwrap();
    let decoded = SealedNote::from_bytes(&bytes).unwrap();
    assert_eq!(decoded, sealed);
    assert_eq!(
        recipient.open(&context(), &decoded).unwrap().as_slice(),
        plaintext
    );
}

#[test]
fn same_message_uses_fresh_encapsulation_and_nonce() {
    let recipient = RecipientKey::generate().unwrap();
    let first = seal(&recipient.public_key(), &context(), b"synthetic note").unwrap();
    let second = seal(&recipient.public_key(), &context(), b"synthetic note").unwrap();
    // A failure would be an entropy or state reuse alarm, not a proof about RNG quality.
    assert_ne!(first.kem_ciphertext, second.kem_ciphertext);
    assert_ne!(first.nonce, second.nonce);
    assert_ne!(first.ciphertext, second.ciphertext);
}

#[test]
fn valid_length_kem_tampering_fails_at_aead_authentication() {
    let recipient = RecipientKey::generate().unwrap();
    let mut sealed = seal(&recipient.public_key(), &context(), b"synthetic note").unwrap();
    sealed.kem_ciphertext[731] ^= 1;
    assert_eq!(
        recipient.open(&context(), &sealed).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn nonce_ciphertext_and_tag_mutations_return_no_plaintext() {
    let recipient = RecipientKey::generate().unwrap();
    let sealed = seal(&recipient.public_key(), &context(), b"synthetic note").unwrap();
    let mut mutated = sealed.clone();
    mutated.nonce[0] ^= 1;
    assert_eq!(
        recipient.open(&context(), &mutated).unwrap_err(),
        Error::AuthenticationFailed
    );
    for index in [0, sealed.ciphertext.len() - 1] {
        let mut mutated = sealed.clone();
        mutated.ciphertext[index] ^= 1;
        assert_eq!(
            recipient.open(&context(), &mutated).unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}

#[test]
fn wrong_recipient_and_each_context_field_fail_authentication() {
    let recipient = RecipientKey::generate().unwrap();
    let wrong_recipient = RecipientKey::generate().unwrap();
    let sealed = seal(&recipient.public_key(), &context(), b"synthetic note").unwrap();
    assert_eq!(
        wrong_recipient.open(&context(), &sealed).unwrap_err(),
        Error::AuthenticationFailed
    );
    let mut contexts = [context(); 3];
    contexts[0].chain_id[0] ^= 1;
    contexts[1].protocol_version += 1;
    contexts[2].output_tag[0] ^= 1;
    for changed in contexts {
        assert_eq!(
            recipient.open(&changed, &sealed).unwrap_err(),
            Error::AuthenticationFailed
        );
    }
}

#[test]
fn identical_reopen_is_allowed_but_another_output_context_is_rejected() {
    let recipient = RecipientKey::generate().unwrap();
    let sealed = seal(&recipient.public_key(), &context(), b"synthetic note").unwrap();
    assert_eq!(
        recipient.open(&context(), &sealed).unwrap().as_slice(),
        b"synthetic note"
    );
    assert_eq!(
        recipient.open(&context(), &sealed).unwrap().as_slice(),
        b"synthetic note"
    );
    let mut other_output = context();
    other_output.output_tag[31] ^= 1;
    assert_eq!(
        recipient.open(&other_output, &sealed).unwrap_err(),
        Error::AuthenticationFailed
    );
}

#[test]
fn empty_and_maximum_payloads_recover_and_oversized_payloads_fail() {
    let recipient = RecipientKey::generate().unwrap();
    for plaintext in [Vec::new(), vec![0xA5; MAX_NOTE_BYTES]] {
        let sealed = seal(&recipient.public_key(), &context(), &plaintext).unwrap();
        let decoded = SealedNote::from_bytes(&sealed.to_bytes().unwrap()).unwrap();
        assert_eq!(
            recipient.open(&context(), &decoded).unwrap().as_slice(),
            plaintext
        );
    }
    assert_eq!(
        seal(
            &recipient.public_key(),
            &context(),
            &vec![0; MAX_NOTE_BYTES + 1]
        )
        .unwrap_err(),
        Error::LimitExceeded
    );
}

#[test]
fn malformed_key_and_ciphertext_lengths_are_structural_errors() {
    let recipient = RecipientKey::generate().unwrap();
    assert_eq!(
        seal(&[0; 32], &context(), b"note").unwrap_err(),
        Error::InvalidKey
    );
    // Packed ML-KEM coefficients of 4095 exceed q and fail public key validation.
    assert_eq!(
        seal(&[0xFF; RECIPIENT_KEY_BYTES], &context(), b"note").unwrap_err(),
        Error::InvalidKey
    );
    let mut sealed = seal(&recipient.public_key(), &context(), b"note").unwrap();
    sealed.kem_ciphertext.pop();
    assert_eq!(
        recipient.open(&context(), &sealed).unwrap_err(),
        Error::InvalidEncoding
    );
    assert_eq!(sealed.to_bytes().unwrap_err(), Error::InvalidEncoding);
}

#[test]
fn envelope_parser_rejects_truncation_trailing_bytes_versions_and_length_overflow() {
    let recipient = RecipientKey::generate().unwrap();
    let bytes = seal(&recipient.public_key(), &context(), b"note")
        .unwrap()
        .to_bytes()
        .unwrap();
    for cut in [0, 8, 10, 13, 100, bytes.len() - 1] {
        assert_eq!(
            SealedNote::from_bytes(&bytes[..cut]).unwrap_err(),
            Error::InvalidEncoding
        );
    }
    let mut trailing = bytes.clone();
    trailing.push(0);
    assert_eq!(
        SealedNote::from_bytes(&trailing).unwrap_err(),
        Error::InvalidEncoding
    );
    let mut version = bytes.clone();
    version[9] ^= 1;
    assert_eq!(
        SealedNote::from_bytes(&version).unwrap_err(),
        Error::UnsupportedSuite
    );
    let mut wrong_magic = bytes.clone();
    wrong_magic[0] ^= 1;
    assert_eq!(
        SealedNote::from_bytes(&wrong_magic).unwrap_err(),
        Error::InvalidEncoding
    );
    let mut huge = bytes;
    huge[10..14].copy_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        SealedNote::from_bytes(&huge).unwrap_err(),
        Error::InvalidEncoding
    );
    assert_eq!(
        SealedNote::from_bytes(&vec![0; MAX_NOTE_BYTES + 2048]).unwrap_err(),
        Error::LimitExceeded
    );
}

#[test]
fn authorization_binds_public_key_message_chain_version_and_output() {
    let key = AuthorizationKey::generate().unwrap();
    let public = key.public_key();
    let message = b"synthetic transition bytes";
    let signature = key.sign(&context(), message).unwrap();
    assert_eq!(public.len(), AUTHORIZATION_KEY_BYTES);
    assert_eq!(signature.len(), AUTHORIZATION_SIGNATURE_BYTES);
    verify_authorization(&public, &context(), message, &signature).unwrap();
    assert_eq!(
        verify_authorization(&public, &context(), b"changed", &signature).unwrap_err(),
        Error::SignatureFailed
    );
    let other_key = AuthorizationKey::generate().unwrap();
    assert_eq!(
        verify_authorization(&other_key.public_key(), &context(), message, &signature).unwrap_err(),
        Error::SignatureFailed
    );
    let mut contexts = [context(); 3];
    contexts[0].chain_id[5] ^= 1;
    contexts[1].protocol_version += 1;
    contexts[2].output_tag[5] ^= 1;
    for changed in contexts {
        assert_eq!(
            verify_authorization(&public, &changed, message, &signature).unwrap_err(),
            Error::SignatureFailed
        );
    }
}

#[test]
fn authorization_rejects_mutations_lengths_and_resource_overruns() {
    let key = AuthorizationKey::generate().unwrap();
    let public = key.public_key();
    let mut signature = key.sign(&context(), b"transition").unwrap();
    signature[0] ^= 1;
    assert_eq!(
        verify_authorization(&public, &context(), b"transition", &signature).unwrap_err(),
        Error::SignatureFailed
    );
    signature.pop();
    assert_eq!(
        verify_authorization(&public, &context(), b"transition", &signature).unwrap_err(),
        Error::InvalidEncoding
    );
    let too_large = vec![0; MAX_AUTHORIZATION_BYTES + 1];
    assert_eq!(
        key.sign(&context(), &too_large).unwrap_err(),
        Error::LimitExceeded
    );
    assert_eq!(
        verify_authorization(&public[..100], &context(), b"transition", &[]).unwrap_err(),
        Error::InvalidKey
    );
}

#[test]
fn authorization_cannot_be_substituted_for_encryption_or_wrong_domains() {
    let authorization = AuthorizationKey::generate().unwrap();
    let recipient = RecipientKey::generate().unwrap();
    let signature = authorization.sign(&context(), b"transition").unwrap();
    assert_eq!(
        seal(&authorization.public_key(), &context(), b"note").unwrap_err(),
        Error::InvalidKey
    );
    assert_eq!(
        verify_authorization(
            &recipient.public_key(),
            &context(),
            b"transition",
            &signature
        )
        .unwrap_err(),
        Error::InvalidKey
    );
}

#[test]
fn authorization_can_bind_the_completed_envelope_without_a_circular_dependency() {
    let authorization = AuthorizationKey::generate().unwrap();
    let recipient = RecipientKey::generate().unwrap();
    let sealed = seal(
        &recipient.public_key(),
        &context(),
        b"synthetic private state",
    )
    .unwrap();
    let bytes = sealed.to_bytes().unwrap();
    let signature = authorization.sign(&context(), &bytes).unwrap();
    verify_authorization(&authorization.public_key(), &context(), &bytes, &signature).unwrap();
    assert_eq!(
        recipient.open(&context(), &sealed).unwrap().as_slice(),
        b"synthetic private state"
    );
    let mut changed = sealed;
    changed.ciphertext[0] ^= 1;
    assert_eq!(
        verify_authorization(
            &authorization.public_key(),
            &context(),
            &changed.to_bytes().unwrap(),
            &signature
        )
        .unwrap_err(),
        Error::SignatureFailed
    );
}

#[test]
fn context_encoding_has_explicit_lengths_and_big_endian_integers() {
    let mut expected = Vec::new();
    expected.extend_from_slice(&32_u32.to_be_bytes());
    expected.extend_from_slice(&[0x31; 32]);
    expected.extend_from_slice(&4_u32.to_be_bytes());
    expected.extend_from_slice(&1_u32.to_be_bytes());
    expected.extend_from_slice(&32_u32.to_be_bytes());
    expected.extend_from_slice(&[0x72; 32]);
    assert_eq!(context().encode(), expected);
    assert_eq!(expected.len(), 80);
}
