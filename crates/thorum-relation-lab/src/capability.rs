use thorum_crypto_lab::{validate_recipient_key, RECIPIENT_KEY_BYTES};

use crate::{
    codec::Reader, frame, hash_fields, key_binding, ChainId, Digest64, NullifierSecret,
    RelationError,
};

pub const RECIPIENT_CAPABILITY_VERSION: u16 = 2;
pub const MAX_CAPABILITY_BYTES: usize = 2048;
const CAPABILITY_DOMAIN: &[u8] = b"thorum.relation-lab.recipient-capability.v2";
const RECIPIENT_KEY_DOMAIN: &[u8] = b"thorum.relation-lab.recipient-key-binding.v2";

/// Public receiver capability. It contains a secret binding, never the secret.
/// Authenticating its intended recipient remains an application obligation.
#[derive(Clone, Eq, PartialEq)]
pub struct RecipientCapability {
    pub(crate) chain_id: ChainId,
    pub(crate) owner_key_binding: Digest64,
    pub(crate) nullifier_secret_binding: Digest64,
    recipient_public_key: Vec<u8>,
}

impl RecipientCapability {
    /// Receiver construction. The sender receives only the resulting public value.
    pub fn new(
        chain_id: ChainId,
        owner_public_key: &[u8],
        recipient_public_key: &[u8],
        secret: &NullifierSecret,
    ) -> Result<Self, RelationError> {
        validate_recipient_key(recipient_public_key)?;
        Ok(Self {
            chain_id,
            owner_key_binding: key_binding(owner_public_key)?,
            nullifier_secret_binding: secret.recipient_binding(&chain_id),
            recipient_public_key: recipient_public_key.to_vec(),
        })
    }

    pub const fn chain_id(&self) -> ChainId {
        self.chain_id
    }
    pub const fn owner_key_binding(&self) -> Digest64 {
        self.owner_key_binding
    }
    pub const fn nullifier_secret_binding(&self) -> Digest64 {
        self.nullifier_secret_binding
    }
    pub fn recipient_public_key(&self) -> &[u8] {
        &self.recipient_public_key
    }

    pub fn encryption_key_binding(&self) -> Digest64 {
        // Construction and decoding validate the exact canonical KEM public key.
        recipient_key_binding(&self.chain_id, &self.recipient_public_key)
    }

    /// Public local codec. This is not a production address format.
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut bytes = Vec::with_capacity(MAX_CAPABILITY_BYTES);
        frame(&mut bytes, CAPABILITY_DOMAIN);
        frame(&mut bytes, &RECIPIENT_CAPABILITY_VERSION.to_be_bytes());
        frame(&mut bytes, &self.chain_id);
        frame(&mut bytes, &self.owner_key_binding);
        frame(&mut bytes, &self.nullifier_secret_binding);
        frame(&mut bytes, &self.recipient_public_key);
        bytes
    }

    pub fn from_bytes(bytes: &[u8], expected_chain: ChainId) -> Result<Self, RelationError> {
        if bytes.len() > MAX_CAPABILITY_BYTES {
            return Err(RelationError::LimitExceeded);
        }
        let mut reader = Reader::new(bytes);
        if reader.field()? != CAPABILITY_DOMAIN {
            return Err(RelationError::UnsupportedEncoding);
        }
        if u16::from_be_bytes(reader.fixed()?) != RECIPIENT_CAPABILITY_VERSION {
            return Err(RelationError::UnsupportedEncoding);
        }
        let chain_id = reader.fixed()?;
        if chain_id != expected_chain {
            return Err(RelationError::ChainMismatch);
        }
        let owner_key_binding = reader.fixed()?;
        let nullifier_secret_binding = reader.fixed()?;
        let public_key = reader.field()?;
        if public_key.len() != RECIPIENT_KEY_BYTES {
            return Err(RelationError::InvalidEncoding);
        }
        validate_recipient_key(public_key)?;
        reader.finish()?;
        let capability = Self {
            chain_id,
            owner_key_binding,
            nullifier_secret_binding,
            recipient_public_key: public_key.to_vec(),
        };
        if capability.to_bytes() != bytes {
            return Err(RelationError::InvalidEncoding);
        }
        Ok(capability)
    }
}

pub(crate) fn recipient_key_binding(chain: &ChainId, public_key: &[u8]) -> Digest64 {
    hash_fields(RECIPIENT_KEY_DOMAIN, &[chain, public_key])
}
