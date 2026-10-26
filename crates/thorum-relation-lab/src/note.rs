use sha3::{Digest, Sha3_512};
use thorum_core::Amount;
use zeroize::Zeroizing;

use crate::{
    capability::recipient_key_binding, codec::Reader, frame, hash_fields, AssetId, ChainId,
    Digest64, RecipientCapability, RelationError, FORMAT_VERSION,
};

const OPENING_DOMAIN: &[u8] = b"thorum.relation-lab.note-opening.v1";
const COMMITMENT_DOMAIN: &[u8] = b"thorum.relation-lab.note-commitment.v1";
const SECRET_BINDING_DOMAIN: &[u8] = b"thorum.relation-lab.nullifier-secret-binding.v1";
const NULLIFIER_DOMAIN: &[u8] = b"thorum.relation-lab.note-nullifier.v1";
const VOTE_NULLIFIER_DOMAIN: &[u8] = b"thorum.relation-lab.vote-nullifier.v1";
const RECIPIENT_OPENING_DOMAIN: &[u8] = b"thorum.relation-lab.note-opening.v2";
const RECIPIENT_COMMITMENT_DOMAIN: &[u8] = b"thorum.relation-lab.note-commitment.v2";
const RECIPIENT_SECRET_DOMAIN: &[u8] = b"thorum.relation-lab.nullifier-secret-binding.v2";
const RECIPIENT_NULLIFIER_DOMAIN: &[u8] = b"thorum.relation-lab.note-nullifier.v2";
const RECIPIENT_VOTE_DOMAIN: &[u8] = b"thorum.relation-lab.vote-nullifier.v2";

pub const RECIPIENT_NOTE_VERSION: u16 = 2;
pub const MAX_RECIPIENT_OPENING_BYTES: usize = 1024;

/// Private nullifier authority. It has no Debug, Clone or general serialization.
pub struct NullifierSecret(Zeroizing<[u8; 32]>);

impl NullifierSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }

    pub fn generate() -> Result<Self, RelationError> {
        let mut bytes = Zeroizing::new([0; 32]);
        getrandom::fill(bytes.as_mut())
            .map_err(|_| thorum_crypto_lab::Error::EntropyUnavailable)?;
        Ok(Self(bytes))
    }

    /// Deliberate secret authority export for a separately protected backup.
    pub fn export_backup(&self) -> Zeroizing<[u8; 32]> {
        Zeroizing::new(*self.0)
    }

    pub(crate) fn recipient_binding(&self, chain: &ChainId) -> Digest64 {
        hash_fields(RECIPIENT_SECRET_DOMAIN, &[chain, self.0.as_ref()])
    }
}

/// Authenticated creation context required in addition to successful decryption.
pub struct RecoveryContext {
    pub chain_id: ChainId,
    pub creation_version: u32,
    pub expected_commitment: Digest64,
}

/// Immutable bond policy inside a note commitment.
///
/// Unlock epoch is exclusive. Registration and delegation authorization must
/// already have been validated by the ledger supplying the snapshot.
#[derive(Clone, Copy, Eq, PartialEq)]
pub struct BondPolicy {
    pub(crate) voting_key_binding: Digest64,
    pub(crate) activation_epoch: u64,
    pub(crate) maturity_epoch: u64,
    pub(crate) unlock_epoch: u64,
}

impl BondPolicy {
    pub fn new(
        voting_public_key: &[u8],
        activation_epoch: u64,
        maturity_epoch: u64,
        unlock_epoch: u64,
    ) -> Result<Self, RelationError> {
        if activation_epoch > maturity_epoch || maturity_epoch >= unlock_epoch {
            return Err(RelationError::InvalidBondPolicy);
        }
        Ok(Self {
            voting_key_binding: key_binding(voting_public_key)?,
            activation_epoch,
            maturity_epoch,
            unlock_epoch,
        })
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
pub enum NotePolicy {
    Payment,
    Bond(BondPolicy),
}

/// Local note fields. This type deliberately has no Debug or serialization trait.
pub struct NoteParameters {
    pub chain_id: ChainId,
    pub creation_version: u32,
    pub asset_id: AssetId,
    pub amount: Amount,
    pub serial: [u8; 32],
    pub policy: NotePolicy,
}

/// Private opening consumed directly by the transparent local checker.
pub struct NoteOpening {
    pub(crate) chain_id: ChainId,
    pub(crate) creation_version: u32,
    pub(crate) asset_id: AssetId,
    pub(crate) amount: Amount,
    pub(crate) owner_key_binding: Digest64,
    nullifier_secret_binding: Digest64,
    encoding: NoteEncoding,
    serial: [u8; 32],
    blinding: Zeroizing<[u8; 32]>,
    pub(crate) policy: NotePolicy,
}

enum NoteEncoding {
    LegacyV1(Zeroizing<[u8; 32]>),
    RecipientV2 { recipient_key_binding: Digest64 },
}

impl NoteOpening {
    /// Entropy quality and uniqueness of serial, secret and blinding are caller obligations.
    pub fn new(
        parameters: NoteParameters,
        owner_public_key: &[u8],
        nullifier_secret: &NullifierSecret,
        blinding: [u8; 32],
    ) -> Result<Self, RelationError> {
        let owner_key_binding = key_binding(owner_public_key)?;
        if let NotePolicy::Bond(policy) = parameters.policy {
            if policy.voting_key_binding == owner_key_binding {
                return Err(RelationError::RestrictedKeyNotDistinct);
            }
        }
        let nullifier_secret_binding = secret_binding(&parameters.chain_id, nullifier_secret);
        Ok(Self {
            chain_id: parameters.chain_id,
            creation_version: parameters.creation_version,
            asset_id: parameters.asset_id,
            amount: parameters.amount,
            owner_key_binding,
            nullifier_secret_binding,
            encoding: NoteEncoding::LegacyV1(Zeroizing::new(*nullifier_secret.0)),
            serial: parameters.serial,
            blinding: Zeroizing::new(blinding),
            policy: parameters.policy,
        })
    }

    /// Sender construction uses only a public capability and no recipient secret.
    pub fn new_recipient(
        parameters: NoteParameters,
        capability: &RecipientCapability,
        blinding: [u8; 32],
    ) -> Result<Self, RelationError> {
        if parameters.chain_id != capability.chain_id {
            return Err(RelationError::ChainMismatch);
        }
        check_policy(parameters.policy, &capability.owner_key_binding)?;
        Ok(Self {
            chain_id: parameters.chain_id,
            creation_version: parameters.creation_version,
            asset_id: parameters.asset_id,
            amount: parameters.amount,
            owner_key_binding: capability.owner_key_binding,
            nullifier_secret_binding: capability.nullifier_secret_binding,
            encoding: NoteEncoding::RecipientV2 {
                recipient_key_binding: capability.encryption_key_binding(),
            },
            serial: parameters.serial,
            blinding: Zeroizing::new(blinding),
            policy: parameters.policy,
        })
    }

    pub const fn encoding_version(&self) -> u16 {
        match self.encoding {
            NoteEncoding::LegacyV1(_) => FORMAT_VERSION,
            NoteEncoding::RecipientV2 { .. } => RECIPIENT_NOTE_VERSION,
        }
    }

    /// Bounded v2 recovery with independent expected commitment and receiver authority.
    /// The payload never contains the receiver nullifier secret.
    pub fn recover_recipient(
        bytes: &[u8],
        context: &RecoveryContext,
        capability: &RecipientCapability,
        secret: &NullifierSecret,
    ) -> Result<Self, RelationError> {
        if bytes.len() > MAX_RECIPIENT_OPENING_BYTES {
            return Err(RelationError::LimitExceeded);
        }
        let mut reader = Reader::new(bytes);
        if reader.field()? != RECIPIENT_OPENING_DOMAIN
            || u16::from_be_bytes(reader.fixed()?) != RECIPIENT_NOTE_VERSION
        {
            return Err(RelationError::UnsupportedEncoding);
        }
        let chain_id = reader.fixed()?;
        let creation_version = u32::from_be_bytes(reader.fixed()?);
        let asset_id = reader.fixed()?;
        let amount = Amount::from_atomic(u64::from_be_bytes(reader.fixed()?));
        let owner_key_binding = reader.fixed()?;
        let nullifier_secret_binding = reader.fixed()?;
        let encryption_key_binding = reader.fixed()?;
        let serial = reader.fixed()?;
        let blinding = Zeroizing::new(reader.fixed()?);
        let policy = match reader.fixed::<1>()? {
            [0] => NotePolicy::Payment,
            [1] => NotePolicy::Bond(BondPolicy {
                voting_key_binding: reader.fixed()?,
                activation_epoch: u64::from_be_bytes(reader.fixed()?),
                maturity_epoch: u64::from_be_bytes(reader.fixed()?),
                unlock_epoch: u64::from_be_bytes(reader.fixed()?),
            }),
            _ => return Err(RelationError::UnsupportedEncoding),
        };
        reader.finish()?;
        if chain_id != context.chain_id || chain_id != capability.chain_id {
            return Err(RelationError::ChainMismatch);
        }
        if creation_version != context.creation_version {
            return Err(RelationError::VersionMismatch);
        }
        check_policy(policy, &owner_key_binding)?;
        if owner_key_binding != capability.owner_key_binding
            || nullifier_secret_binding != capability.nullifier_secret_binding
            || encryption_key_binding != capability.encryption_key_binding()
        {
            return Err(RelationError::CapabilityMismatch);
        }
        if secret.recipient_binding(&chain_id) != nullifier_secret_binding {
            return Err(RelationError::NullifierSecretMismatch);
        }
        let opening = Self {
            chain_id,
            creation_version,
            asset_id,
            amount,
            owner_key_binding,
            nullifier_secret_binding,
            encoding: NoteEncoding::RecipientV2 {
                recipient_key_binding: encryption_key_binding,
            },
            serial,
            blinding,
            policy,
        };
        if opening.private_opening_bytes().as_slice() != bytes {
            return Err(RelationError::InvalidEncoding);
        }
        if opening.commitment() != context.expected_commitment {
            return Err(RelationError::CommitmentMismatch);
        }
        Ok(opening)
    }

    pub fn commitment(&self) -> Digest64 {
        let bytes = self.private_opening_bytes();
        let domain = match self.encoding {
            NoteEncoding::LegacyV1(_) => COMMITMENT_DOMAIN,
            NoteEncoding::RecipientV2 { .. } => RECIPIENT_COMMITMENT_DOMAIN,
        };
        hash_fields(domain, &[&bytes])
    }

    /// Explicit private export for local encryption. Never publish or log these bytes.
    pub fn private_opening_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Both supported policies fit without reallocating the secret payload.
        let mut bytes = Zeroizing::new(Vec::with_capacity(768));
        let domain = match self.encoding {
            NoteEncoding::LegacyV1(_) => OPENING_DOMAIN,
            NoteEncoding::RecipientV2 { .. } => RECIPIENT_OPENING_DOMAIN,
        };
        frame(&mut bytes, domain);
        frame(&mut bytes, &self.encoding_version().to_be_bytes());
        frame(&mut bytes, &self.chain_id);
        frame(&mut bytes, &self.creation_version.to_be_bytes());
        frame(&mut bytes, &self.asset_id);
        frame(&mut bytes, &self.amount.atomic().to_be_bytes());
        frame(&mut bytes, &self.owner_key_binding);
        frame(&mut bytes, &self.nullifier_secret_binding);
        match &self.encoding {
            NoteEncoding::LegacyV1(secret) => frame(&mut bytes, secret.as_ref()),
            NoteEncoding::RecipientV2 {
                recipient_key_binding,
            } => {
                frame(&mut bytes, recipient_key_binding);
            }
        }
        frame(&mut bytes, &self.serial);
        frame(&mut bytes, self.blinding.as_ref());
        match self.policy {
            NotePolicy::Payment => frame(&mut bytes, &[0]),
            NotePolicy::Bond(policy) => {
                frame(&mut bytes, &[1]);
                frame(&mut bytes, &policy.voting_key_binding);
                frame(&mut bytes, &policy.activation_epoch.to_be_bytes());
                frame(&mut bytes, &policy.maturity_epoch.to_be_bytes());
                frame(&mut bytes, &policy.unlock_epoch.to_be_bytes());
            }
        }
        bytes
    }

    /// Stable for an existing note across anchors, epochs, paths and current protocol versions.
    pub fn nullifier(&self, secret: &NullifierSecret) -> Result<Digest64, RelationError> {
        self.check_secret(secret)?;
        let domain = match self.encoding {
            NoteEncoding::LegacyV1(_) => NULLIFIER_DOMAIN,
            NoteEncoding::RecipientV2 { .. } => RECIPIENT_NULLIFIER_DOMAIN,
        };
        Ok(hash_fields(
            domain,
            &[&self.chain_id, secret.0.as_ref(), &self.commitment()],
        ))
    }

    /// One canonical nullifier per existing bond, epoch and authenticated duty.
    /// Owner, delegate, current protocol and snapshot anchor do not enter this derivation.
    pub fn vote_nullifier(
        &self,
        secret: &NullifierSecret,
        epoch: u64,
        duty_id: &[u8; 32],
    ) -> Result<Digest64, RelationError> {
        self.check_secret(secret)?;
        let domain = match self.encoding {
            NoteEncoding::LegacyV1(_) => VOTE_NULLIFIER_DOMAIN,
            NoteEncoding::RecipientV2 { .. } => RECIPIENT_VOTE_DOMAIN,
        };
        Ok(hash_fields(
            domain,
            &[
                &self.chain_id,
                secret.0.as_ref(),
                &self.commitment(),
                &epoch.to_be_bytes(),
                duty_id,
            ],
        ))
    }

    fn check_secret(&self, secret: &NullifierSecret) -> Result<(), RelationError> {
        let binding = match self.encoding {
            NoteEncoding::LegacyV1(_) => secret_binding(&self.chain_id, secret),
            NoteEncoding::RecipientV2 { .. } => secret.recipient_binding(&self.chain_id),
        };
        if self.nullifier_secret_binding != binding {
            return Err(RelationError::NullifierSecretMismatch);
        }
        Ok(())
    }

    pub(crate) fn check_recipient_key(&self, public_key: &[u8]) -> Result<(), RelationError> {
        if let NoteEncoding::RecipientV2 {
            recipient_key_binding: expected,
        } = self.encoding
        {
            thorum_crypto_lab::validate_recipient_key(public_key)?;
            if recipient_key_binding(&self.chain_id, public_key) != expected {
                return Err(RelationError::RecipientKeyMismatch);
            }
        }
        Ok(())
    }
}

fn check_policy(policy: NotePolicy, owner: &Digest64) -> Result<(), RelationError> {
    if let NotePolicy::Bond(bond) = policy {
        if bond.activation_epoch > bond.maturity_epoch || bond.maturity_epoch >= bond.unlock_epoch {
            return Err(RelationError::InvalidBondPolicy);
        }
        if bond.voting_key_binding == *owner {
            return Err(RelationError::RestrictedKeyNotDistinct);
        }
    }
    Ok(())
}

fn secret_binding(chain: &ChainId, secret: &NullifierSecret) -> Digest64 {
    hash_fields(SECRET_BINDING_DOMAIN, &[chain, secret.0.as_ref()])
}

/// Exact SHA3-512 of the full ML-DSA-87 public key bytes.
pub fn key_binding(public_key: &[u8]) -> Result<Digest64, RelationError> {
    if public_key.len() != thorum_crypto_lab::AUTHORIZATION_KEY_BYTES {
        return Err(thorum_crypto_lab::Error::InvalidKey.into());
    }
    Ok(Sha3_512::digest(public_key).into())
}
