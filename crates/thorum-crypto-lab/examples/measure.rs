//! Raw local measurements. Run a release build and preserve environment metadata.
//! No synthetic seed is used for measured key generation or encapsulation.

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ml_kem::{Decapsulate, DecapsulationKey1024};
use sha3::{Digest, Sha3_512};
use std::{error::Error, hint::black_box, io, time::Instant};
use thorum_crypto_lab::{
    seal, verify_authorization, AuthorizationKey, Context, RecipientKey, AUTHORIZATION_KEY_BYTES,
    AUTHORIZATION_SIGNATURE_BYTES, KEM_CIPHERTEXT_BYTES, RECIPIENT_KEY_BYTES, TAG_BYTES,
};
use zeroize::Zeroizing;

type Result<T> = std::result::Result<T, Box<dyn Error>>;

fn record<T>(
    operation: &str,
    input_bytes: usize,
    output_bytes: usize,
    sample: usize,
    operation_fn: impl FnOnce() -> Result<T>,
) -> Result<T> {
    let start = Instant::now();
    let value = operation_fn()?;
    black_box(&value);
    let elapsed = start.elapsed().as_nanos();
    println!("{operation},{input_bytes},{output_bytes},{sample},{elapsed}");
    Ok(value)
}

fn main() -> Result<()> {
    let args: Vec<_> = std::env::args().skip(1).collect();
    if args.len() > 1 {
        return Err(io::Error::other("usage: measure [samples between 1 and 10000]").into());
    }
    let samples = args
        .first()
        .map(|s| s.parse::<usize>())
        .transpose()?
        .unwrap_or(30);
    if !(1..=10000).contains(&samples) {
        return Err(io::Error::other("sample count must be between 1 and 10000").into());
    }
    let context = Context {
        chain_id: [0x31; 32],
        protocol_version: 1,
        output_tag: [0x72; 32],
    };
    let message = vec![0x53; 1024];
    let authorization = AuthorizationKey::generate()?;
    let authorization_public = authorization.public_key();
    let signature = authorization.sign(&context, &message)?;
    let recipient = RecipientKey::generate()?;
    let recipient_public = recipient.public_key();
    let mut seed = Zeroizing::new(ml_kem::Seed::default());
    getrandom::fill(seed.as_mut_slice())?;
    let kem_key = DecapsulationKey1024::from_seed(*seed);
    let kem_public = kem_key.encapsulation_key();

    // Warm the same implementations before recording samples. This does not
    // cover every cache state, cold startup, or sustained thermal condition.
    for _ in 0..3 {
        let signed = authorization.sign(&context, &message)?;
        verify_authorization(&authorization_public, &context, &message, &signed)?;
        let sealed = seal(&recipient_public, &context, &message)?;
        black_box(recipient.open(&context, &sealed)?);
    }

    println!("operation,input_bytes,output_bytes,sample,elapsed_ns");
    for sample in 0..samples {
        record(
            "mldsa87_keygen_os",
            0,
            AUTHORIZATION_KEY_BYTES,
            sample,
            || Ok(AuthorizationKey::generate()?),
        )?;
        record(
            "mldsa87_sign_os",
            message.len(),
            AUTHORIZATION_SIGNATURE_BYTES,
            sample,
            || Ok(authorization.sign(&context, black_box(&message))?),
        )?;
        record(
            "mldsa87_verify",
            message.len() + signature.len(),
            0,
            sample,
            || {
                Ok(verify_authorization(
                    &authorization_public,
                    &context,
                    black_box(&message),
                    &signature,
                )?)
            },
        )?;
        record(
            "mlkem1024_keygen_os",
            0,
            RECIPIENT_KEY_BYTES,
            sample,
            || Ok(RecipientKey::generate()?),
        )?;
        let (kem_ciphertext, _) = record(
            "mlkem1024_encaps_os",
            RECIPIENT_KEY_BYTES,
            KEM_CIPHERTEXT_BYTES,
            sample,
            || {
                let mut randomness = Zeroizing::new(ml_kem::B32::default());
                getrandom::fill(randomness.as_mut_slice())?;
                let (ciphertext, shared) = kem_public.encapsulate_deterministic(&randomness);
                Ok((ciphertext, Zeroizing::new(shared)))
            },
        )?;
        record("mlkem1024_decaps", KEM_CIPHERTEXT_BYTES, 32, sample, || {
            Ok(Zeroizing::new(
                kem_key.decapsulate(black_box(&kem_ciphertext)),
            ))
        })?;
        record("sha3_512_digest", message.len(), 64, sample, || {
            Ok(Sha3_512::digest(black_box(&message)))
        })?;
    }

    for payload_bytes in [0, 256, 1024, 16384] {
        let plaintext = vec![0xA5; payload_bytes];
        let mut aead_key = Zeroizing::new([0_u8; 32]);
        getrandom::fill(aead_key.as_mut_slice())?;
        let cipher = Aes256Gcm::new_from_slice(aead_key.as_ref())?;
        let aad = context.encode();
        let zero_nonce = Nonce::from([0_u8; 12]);
        let ciphertext = cipher.encrypt(
            &zero_nonce,
            Payload {
                msg: &plaintext,
                aad: &aad,
            },
        )?;
        let sealed = seal(&recipient_public, &context, &plaintext)?;
        let envelope_bytes = sealed.to_bytes()?.len();
        for sample in 0..samples {
            let mut nonce = [0_u8; 12];
            nonce[4..].copy_from_slice(&((sample as u64) + 1).to_be_bytes());
            record(
                "aes256gcm_encrypt",
                payload_bytes,
                payload_bytes + TAG_BYTES,
                sample,
                || {
                    Ok(cipher.encrypt(
                        &Nonce::from(nonce),
                        Payload {
                            msg: black_box(&plaintext),
                            aad: &aad,
                        },
                    )?)
                },
            )?;
            record(
                "aes256gcm_decrypt",
                ciphertext.len(),
                payload_bytes,
                sample,
                || {
                    Ok(Zeroizing::new(cipher.decrypt(
                        &zero_nonce,
                        Payload {
                            msg: black_box(&ciphertext),
                            aad: &aad,
                        },
                    )?))
                },
            )?;
            record(
                "envelope_seal_os",
                payload_bytes,
                envelope_bytes,
                sample,
                || Ok(seal(&recipient_public, &context, black_box(&plaintext))?),
            )?;
            record(
                "envelope_open",
                envelope_bytes,
                payload_bytes,
                sample,
                || Ok(recipient.open(&context, black_box(&sealed))?),
            )?;
        }
    }
    Ok(())
}
