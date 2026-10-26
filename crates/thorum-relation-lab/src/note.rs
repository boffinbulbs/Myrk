use sha3::{Digest, Sha3_512};
use thorum_core::Amount;
use zeroize::Zeroizing;

use crate::{frame, hash_fields, AssetId, ChainId, Digest64, RelationError, FORMAT_VERSION};

const OPENING_DOMAIN: &[u8] = b"thorum.relation-lab.note-opening.v1";
const COMMITMENT_DOMAIN: &[u8] = b"thorum.relation-lab.note-commitment.v1";
const SECRET_BINDING_DOMAIN: &[u8] = b"thorum.relation-lab.nullifier-secret-binding.v1";
const NULLIFIER_DOMAIN: &[u8] = b"thorum.relation-lab.note-nullifier.v1";
const VOTE_NULLIFIER_DOMAIN: &[u8] = b"thorum.relation-lab.vote-nullifier.v1";

/// Caller supplied local secret. No randomness generation or secret export is provided.
pub struct NullifierSecret(Zeroizing<[u8; 32]>);

impl NullifierSecret {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(Zeroizing::new(bytes))
    }
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
    nullifier_secret: Zeroizing<[u8; 32]>,
    serial: [u8; 32],
    blinding: Zeroizing<[u8; 32]>,
    pub(crate) policy: NotePolicy,
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
            nullifier_secret: Zeroizing::new(*nullifier_secret.0),
            serial: parameters.serial,
            blinding: Zeroizing::new(blinding),
            policy: parameters.policy,
        })
    }

    pub fn commitment(&self) -> Digest64 {
        let bytes = self.private_opening_bytes();
        hash_fields(COMMITMENT_DOMAIN, &[&bytes])
    }

    /// Explicit private export for local encryption. Never publish or log these bytes.
    pub fn private_opening_bytes(&self) -> Zeroizing<Vec<u8>> {
        // Both supported policies fit without reallocating the secret payload.
        let mut bytes = Zeroizing::new(Vec::with_capacity(768));
        frame(&mut bytes, OPENING_DOMAIN);
        frame(&mut bytes, &FORMAT_VERSION.to_be_bytes());
        frame(&mut bytes, &self.chain_id);
        frame(&mut bytes, &self.creation_version.to_be_bytes());
        frame(&mut bytes, &self.asset_id);
        frame(&mut bytes, &self.amount.atomic().to_be_bytes());
        frame(&mut bytes, &self.owner_key_binding);
        frame(&mut bytes, &self.nullifier_secret_binding);
        frame(&mut bytes, self.nullifier_secret.as_ref());
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
        Ok(hash_fields(
            NULLIFIER_DOMAIN,
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
        Ok(hash_fields(
            VOTE_NULLIFIER_DOMAIN,
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
        if self.nullifier_secret_binding != secret_binding(&self.chain_id, secret) {
            return Err(RelationError::NullifierSecretMismatch);
        }
        Ok(())
    }
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
