use thorum_crypto_lab::{validate_recipient_key, Error, RecipientKey, RECIPIENT_KEY_BYTES};

#[test]
fn recipient_key_validation_matches_exact_backend_encoding_rules() {
    let recipient = RecipientKey::generate().unwrap();
    let public_key = recipient.public_key();
    validate_recipient_key(&public_key).unwrap();
    for length in [0, 1, RECIPIENT_KEY_BYTES - 1, RECIPIENT_KEY_BYTES + 1] {
        assert_eq!(
            validate_recipient_key(&vec![0; length]),
            Err(Error::InvalidKey)
        );
    }
    // The packed polynomial coefficients exceed the modulus in this encoding.
    assert_eq!(
        validate_recipient_key(&[0xFF; RECIPIENT_KEY_BYTES]),
        Err(Error::InvalidKey)
    );
    // Canonical decoding is not proof that a secret key is known or a key was generated honestly.
    validate_recipient_key(&[0; RECIPIENT_KEY_BYTES]).unwrap();
}
