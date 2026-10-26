//! Isolated primitive integration for synthetic local research.
//!
//! This crate does not implement a private ledger, proofs, recipient discovery,
//! consensus authorization, or production wallet key management. Its signatures
//! expose public authorization keys. Its encryption suite is experimental.

#![forbid(unsafe_code)]

mod envelope;

pub use envelope::SealedNote;

use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use ml_dsa::{Keypair, MlDsa87, Signature, SigningKey, VerifyingKey};
use ml_kem::{Decapsulate, DecapsulationKey1024, EncapsulationKey1024, KeyExport, TryKeyInit};
use sha3::{Digest, Sha3_512};
use std::fmt;
use zeroize::{Zeroize, Zeroizing};

/// Laboratory suite version. This is not a consensus or address format version.
pub const SUITE_VERSION: u16 = 1;
/// Maximum plaintext payload accepted by the envelope laboratory.
pub const MAX_NOTE_BYTES: usize = 16 * 1024;
/// Maximum synthetic authorization payload.
pub const MAX_AUTHORIZATION_BYTES: usize = 64 * 1024;
/// Encoded ML-KEM-1024 encapsulation key size.
pub const RECIPIENT_KEY_BYTES: usize = 1568;
/// Encoded ML-KEM-1024 ciphertext size.
pub const KEM_CIPHERTEXT_BYTES: usize = 1568;
/// Encoded ML-DSA-87 verification key size.
pub const AUTHORIZATION_KEY_BYTES: usize = 2592;
/// Encoded ML-DSA-87 signature size.
pub const AUTHORIZATION_SIGNATURE_BYTES: usize = 4627;
/// AES GCM authentication tag size for this suite.
pub const TAG_BYTES: usize = 16;

const SIGNATURE_CONTEXT: &[u8] = b"Thorum crypto laboratory authorization v1";
const AUTHORIZATION_DOMAIN: &[u8] = b"thorum.crypto-lab.authorization.v1";
const ENCRYPTION_DOMAIN: &[u8] = b"thorum.crypto-lab.recipient-envelope.v1";
const RECIPIENT_DOMAIN: &[u8] = b"thorum.crypto-lab.recipient-key.v1";
const KDF_DOMAIN: &[u8] = b"thorum.crypto-lab.experimental-sha3-kdf.v1";

/// An externally supplied synthetic validation context.
///
/// The caller must authenticate this context independently. The output tag is
/// opaque research input. It is not a commitment construction or a transaction ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Context {
    pub chain_id: [u8; 32],
    pub protocol_version: u32,
    pub output_tag: [u8; 32],
}

impl Context {
    /// Canonical bytes use fixed width integers in network byte order and an
    /// unsigned 32 bit length before every field, including fixed width fields.
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(80);
        frame(&mut bytes, &self.chain_id);
        frame(&mut bytes, &self.protocol_version.to_be_bytes());
        frame(&mut bytes, &self.output_tag);
        bytes
    }
}

/// Errors identify public structural failures and one opaque authentication
/// failure. They must not be exposed as a remote decryption oracle.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Error {
    EntropyUnavailable,
    InvalidEncoding,
    InvalidKey,
    UnsupportedSuite,
    LimitExceeded,
    AuthenticationFailed,
    SignatureFailed,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let message = match self {
            Self::EntropyUnavailable => "operating system entropy unavailable",
            Self::InvalidEncoding => "invalid canonical laboratory encoding",
            Self::InvalidKey => "invalid public key encoding",
            Self::UnsupportedSuite => "unsupported laboratory suite version",
            Self::LimitExceeded => "laboratory input limit exceeded",
            Self::AuthenticationFailed => "envelope authentication failed",
            Self::SignatureFailed => "authorization verification failed",
        };
        f.write_str(message)
    }
}

impl std::error::Error for Error {}

/// Secret authorization key with no serialization or Debug interface in this
/// laboratory. Upstream zeroize support is enabled for owned secret key values.
pub struct AuthorizationKey(SigningKey<MlDsa87>);

impl AuthorizationKey {
    /// Generate an independent key from fallible operating system entropy.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new(ml_dsa::Seed::default());
        getrandom::fill(seed.as_mut_slice()).map_err(|_| Error::EntropyUnavailable)?;
        Ok(Self(SigningKey::from_seed(&seed)))
    }

    /// Return the public key. Public signatures do not provide private ownership.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.verifying_key().encode().to_vec()
    }

    /// Sign bounded framed bytes using hedged ML-DSA and a nonempty FIPS context.
    pub fn sign(&self, context: &Context, message: &[u8]) -> Result<Vec<u8>, Error> {
        let bytes = authorization_bytes(context, message)?;
        let signature = self
            .0
            .expanded_key()
            .sign_randomized(&bytes, SIGNATURE_CONTEXT, &mut getrandom::SysRng)
            .map_err(|_| Error::EntropyUnavailable)?;
        Ok(signature.encode().to_vec())
    }
}

/// Verify the same context, bytes, parameter set and nonempty FIPS context.
pub fn verify_authorization(
    public_key: &[u8],
    context: &Context,
    message: &[u8],
    signature: &[u8],
) -> Result<(), Error> {
    if public_key.len() != AUTHORIZATION_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    if signature.len() != AUTHORIZATION_SIGNATURE_BYTES {
        return Err(Error::InvalidEncoding);
    }
    let bytes = authorization_bytes(context, message)?;
    let encoded_key = ml_dsa::EncodedVerifyingKey::<MlDsa87>::try_from(public_key)
        .map_err(|_| Error::InvalidKey)?;
    let key = VerifyingKey::<MlDsa87>::decode(&encoded_key);
    let signature =
        Signature::<MlDsa87>::try_from(signature).map_err(|_| Error::SignatureFailed)?;
    if key.verify_with_context(&bytes, SIGNATURE_CONTEXT, &signature) {
        Ok(())
    } else {
        Err(Error::SignatureFailed)
    }
}

/// Independent recipient secret key. A recipient key does not authorize spending.
pub struct RecipientKey(DecapsulationKey1024);

/// Local sender witness for reproducing one recipient envelope.
///
/// The encapsulation randomness can reveal the envelope's shared secret and
/// payload. Keep this value inside the trusted local prover boundary. It has
/// no Debug, cloning, serialization, or secret export interface. It is not a
/// proof, a public validation input, or recipient spending authority.
pub struct EncryptionWitness(Zeroizing<ml_kem::B32>);

impl RecipientKey {
    /// Generate a recipient key from a fresh uniformly random 64 byte seed.
    pub fn generate() -> Result<Self, Error> {
        let mut seed = Zeroizing::new(ml_kem::Seed::default());
        getrandom::fill(seed.as_mut_slice()).map_err(|_| Error::EntropyUnavailable)?;
        Ok(Self(DecapsulationKey1024::from_seed(*seed)))
    }

    /// Return the public recipient key for this laboratory parameter set.
    pub fn public_key(&self) -> Vec<u8> {
        self.0.encapsulation_key().to_bytes().to_vec()
    }

    /// Recover exact payload bytes only after authenticated decryption succeeds.
    /// Reopening an identical envelope succeeds again. Ledger replay prevention
    /// requires a separate state transition and is not supplied by this function.
    pub fn open(
        &self,
        context: &Context,
        sealed: &SealedNote,
    ) -> Result<Zeroizing<Vec<u8>>, Error> {
        sealed.validate()?;
        let kem_ciphertext =
            ml_kem::Ciphertext::<ml_kem::MlKem1024>::try_from(sealed.kem_ciphertext.as_slice())
                .map_err(|_| Error::InvalidEncoding)?;
        let shared = Zeroizing::new(self.0.decapsulate(&kem_ciphertext));
        let recipient_key = self.public_key();
        let aad = envelope_aad(
            context,
            &recipient_key,
            &sealed.kem_ciphertext,
            &sealed.nonce,
        );
        let key = derive_key(shared.as_slice(), &aad);
        let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::InvalidKey)?;
        let plaintext = cipher
            .decrypt(
                &Nonce::from(sealed.nonce),
                Payload {
                    msg: &sealed.ciphertext,
                    aad: &aad,
                },
            )
            .map_err(|_| Error::AuthenticationFailed)?;
        Ok(Zeroizing::new(plaintext))
    }
}

/// Check the exact ML-KEM-1024 public key encoding without using randomness.
///
/// This checks length and the backend's canonical coefficient decoding. It
/// does not establish possession of a corresponding secret, intended recipient
/// identity, key generation provenance or a secure delivery channel.
pub fn validate_recipient_key(public_key: &[u8]) -> Result<(), Error> {
    if public_key.len() != RECIPIENT_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    EncapsulationKey1024::new_from_slice(public_key).map_err(|_| Error::InvalidKey)?;
    Ok(())
}

/// Seal one bounded payload with fresh OS encapsulation randomness and nonce.
///
/// The experimental KDF hashes framed domain, KEM secret and public associated
/// data with SHA3-512, then takes its first 32 bytes. It is not a selected ledger
/// KDF or a claim about the security of the composed protocol. The associated
/// data excludes the final ciphertext, signatures, proofs and transaction IDs.
pub fn seal(
    recipient_key: &[u8],
    context: &Context,
    plaintext: &[u8],
) -> Result<SealedNote, Error> {
    if plaintext.len() > MAX_NOTE_BYTES {
        return Err(Error::LimitExceeded);
    }
    if recipient_key.len() != RECIPIENT_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    let recipient =
        EncapsulationKey1024::new_from_slice(recipient_key).map_err(|_| Error::InvalidKey)?;
    let mut randomness = Zeroizing::new(ml_kem::B32::default());
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| Error::EntropyUnavailable)?;
    // FIPS 203 internal encapsulation consumes exactly these 32 fresh uniform
    // bytes. Deterministic constants must never enter this path.
    let (kem_ciphertext, shared) = recipient.encapsulate_deterministic(&randomness);
    let shared = Zeroizing::new(shared);
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| Error::EntropyUnavailable)?;
    encrypt_encapsulation(
        recipient_key,
        context,
        plaintext,
        kem_ciphertext.as_slice(),
        shared.as_slice(),
        nonce,
    )
}

/// Seal a payload and retain its secret sender witness for local relation work.
///
/// This uses the same envelope profile as [`seal`]. Fresh operating system
/// randomness is required for each invocation. The returned witness must not
/// be placed in a transaction, proof transport, log, or benchmark output.
pub fn seal_for_relation(
    recipient_key: &[u8],
    context: &Context,
    plaintext: &[u8],
) -> Result<(SealedNote, EncryptionWitness), Error> {
    if plaintext.len() > MAX_NOTE_BYTES {
        return Err(Error::LimitExceeded);
    }
    if recipient_key.len() != RECIPIENT_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    let recipient =
        EncapsulationKey1024::new_from_slice(recipient_key).map_err(|_| Error::InvalidKey)?;
    let mut randomness = Zeroizing::new(ml_kem::B32::default());
    getrandom::fill(randomness.as_mut_slice()).map_err(|_| Error::EntropyUnavailable)?;
    let (kem_ciphertext, shared) = recipient.encapsulate_deterministic(&randomness);
    let shared = Zeroizing::new(shared);
    let mut nonce = [0_u8; 12];
    getrandom::fill(&mut nonce).map_err(|_| Error::EntropyUnavailable)?;
    let sealed = encrypt_encapsulation(
        recipient_key,
        context,
        plaintext,
        kem_ciphertext.as_slice(),
        shared.as_slice(),
        nonce,
    )?;
    Ok((sealed, EncryptionWitness(randomness)))
}

/// Check exact sender encryption semantics without a recipient secret key.
///
/// This local reference check receives the private plaintext and randomness.
/// It recomputes encapsulation, context binding, key derivation and AEAD, then
/// compares every encapsulation and note ciphertext byte. It returns no
/// plaintext or intermediate secret. It is not a zero knowledge proof check
/// and must not be exposed as a remote witness or decryption service.
pub fn verify_encryption_witness(
    recipient_key: &[u8],
    context: &Context,
    plaintext: &[u8],
    witness: &EncryptionWitness,
    sealed: &SealedNote,
) -> Result<(), Error> {
    if plaintext.len() > MAX_NOTE_BYTES {
        return Err(Error::LimitExceeded);
    }
    sealed.validate()?;
    if recipient_key.len() != RECIPIENT_KEY_BYTES {
        return Err(Error::InvalidKey);
    }
    let recipient =
        EncapsulationKey1024::new_from_slice(recipient_key).map_err(|_| Error::InvalidKey)?;
    let (kem_ciphertext, shared) = recipient.encapsulate_deterministic(&witness.0);
    let shared = Zeroizing::new(shared);
    let reproduced = encrypt_encapsulation(
        recipient_key,
        context,
        plaintext,
        kem_ciphertext.as_slice(),
        shared.as_slice(),
        sealed.nonce,
    )?;
    if reproduced.kem_ciphertext == sealed.kem_ciphertext
        && reproduced.ciphertext == sealed.ciphertext
    {
        Ok(())
    } else {
        Err(Error::AuthenticationFailed)
    }
}

fn encrypt_encapsulation(
    recipient_key: &[u8],
    context: &Context,
    plaintext: &[u8],
    kem_ciphertext: &[u8],
    shared: &[u8],
    nonce: [u8; 12],
) -> Result<SealedNote, Error> {
    let aad = envelope_aad(context, recipient_key, kem_ciphertext, &nonce);
    let key = derive_key(shared, &aad);
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|_| Error::InvalidKey)?;
    let ciphertext = cipher
        .encrypt(
            &Nonce::from(nonce),
            Payload {
                msg: plaintext,
                aad: &aad,
            },
        )
        .map_err(|_| Error::AuthenticationFailed)?;
    Ok(SealedNote {
        kem_ciphertext: kem_ciphertext.to_vec(),
        nonce,
        ciphertext,
    })
}

fn authorization_bytes(context: &Context, message: &[u8]) -> Result<Vec<u8>, Error> {
    if message.len() > MAX_AUTHORIZATION_BYTES {
        return Err(Error::LimitExceeded);
    }
    let mut bytes = Vec::with_capacity(message.len() + 160);
    frame(&mut bytes, AUTHORIZATION_DOMAIN);
    frame(&mut bytes, &SUITE_VERSION.to_be_bytes());
    frame(&mut bytes, &context.encode());
    frame(&mut bytes, message);
    Ok(bytes)
}

fn envelope_aad(
    context: &Context,
    recipient_key: &[u8],
    kem_ciphertext: &[u8],
    nonce: &[u8],
) -> Vec<u8> {
    let mut recipient = Sha3_512::new();
    hash_frame(&mut recipient, RECIPIENT_DOMAIN);
    hash_frame(&mut recipient, recipient_key);
    let binding = recipient.finalize();
    let mut bytes = Vec::with_capacity(kem_ciphertext.len() + 256);
    frame(&mut bytes, ENCRYPTION_DOMAIN);
    frame(&mut bytes, &SUITE_VERSION.to_be_bytes());
    frame(&mut bytes, &context.encode());
    frame(&mut bytes, &binding);
    frame(&mut bytes, kem_ciphertext);
    frame(&mut bytes, nonce);
    bytes
}

fn derive_key(shared: &[u8], aad: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut hash = Sha3_512::new();
    hash_frame(&mut hash, KDF_DOMAIN);
    hash_frame(&mut hash, shared);
    hash_frame(&mut hash, aad);
    let mut digest = hash.finalize();
    let mut key = Zeroizing::new([0_u8; 32]);
    key.copy_from_slice(&digest[..32]);
    digest.as_mut_slice().zeroize();
    key
}

fn hash_frame(hash: &mut Sha3_512, field: &[u8]) {
    // All callers use fixed or explicitly bounded fields well below u32::MAX.
    hash.update((field.len() as u32).to_be_bytes());
    hash.update(field);
}

pub(crate) fn frame(bytes: &mut Vec<u8>, field: &[u8]) {
    bytes.extend_from_slice(&(field.len() as u32).to_be_bytes());
    bytes.extend_from_slice(field);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn authorization_requires_the_nonempty_fips_context() {
        let key = AuthorizationKey::generate().unwrap();
        let context = Context {
            chain_id: [1; 32],
            protocol_version: 1,
            output_tag: [2; 32],
        };
        let message = b"synthetic transition";
        let signature = key.sign(&context, message).unwrap();
        let signature = Signature::<MlDsa87>::try_from(signature.as_slice()).unwrap();
        let bytes = authorization_bytes(&context, message).unwrap();
        let public = key.0.verifying_key();
        assert!(public.verify_with_context(&bytes, SIGNATURE_CONTEXT, &signature));
        assert!(!public.verify_with_context(&bytes, b"", &signature));
        assert!(!public.verify_with_context(&bytes, ENCRYPTION_DOMAIN, &signature));
    }
}
