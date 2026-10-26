use std::collections::BTreeSet;

use thorum_core::Amount;
use thorum_crypto_lab::{verify_authorization, Context};

use crate::{
    hash_fields, key_binding, short_tag, statement_frame, ChainId, Digest64, MerklePath,
    NoteOpening, NotePolicy, NullifierSecret, RelationError, FORMAT_VERSION, NATIVE_ASSET_ID,
};

pub const MAX_STAKE_BONDS: usize = 8;

/// Authenticated registration, snapshot origin and set freshness remain caller obligations.
pub struct StakeContext<'a> {
    pub chain_id: ChainId,
    pub protocol_version: u32,
    pub validation_tag: [u8; 32],
    pub snapshot_anchor: Digest64,
    pub snapshot_epoch: u64,
    pub epoch: u64,
    pub duty_id: [u8; 32],
    pub required_lock_through_epoch: u64,
    pub spent_bond_nullifiers: &'a BTreeSet<Digest64>,
    pub used_vote_nullifiers: &'a BTreeSet<Digest64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakeClaim {
    pub vote_nullifier: Digest64,
    pub voting_key_binding: Digest64,
    pub weight: Amount,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct StakeStatement {
    pub chain_id: ChainId,
    pub protocol_version: u32,
    pub validation_tag: [u8; 32],
    pub snapshot_anchor: Digest64,
    pub snapshot_epoch: u64,
    pub epoch: u64,
    pub duty_id: [u8; 32],
    /// Opaque decision binding. The caller validates the meaning and admissibility.
    pub decision_digest: Digest64,
    pub required_lock_through_epoch: u64,
    pub claims: Vec<StakeClaim>,
}

impl StakeStatement {
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelationError> {
        if !(1..=MAX_STAKE_BONDS).contains(&self.claims.len()) {
            return Err(RelationError::LimitExceeded);
        }
        let mut bytes = Vec::new();
        statement_frame(&mut bytes, b"thorum.relation-lab.stake-statement.v1")?;
        statement_frame(&mut bytes, &FORMAT_VERSION.to_be_bytes())?;
        statement_frame(&mut bytes, &self.chain_id)?;
        statement_frame(&mut bytes, &self.protocol_version.to_be_bytes())?;
        statement_frame(&mut bytes, &self.validation_tag)?;
        statement_frame(&mut bytes, &self.snapshot_anchor)?;
        statement_frame(&mut bytes, &self.snapshot_epoch.to_be_bytes())?;
        statement_frame(&mut bytes, &self.epoch.to_be_bytes())?;
        statement_frame(&mut bytes, &self.duty_id)?;
        statement_frame(&mut bytes, &self.decision_digest)?;
        statement_frame(&mut bytes, &self.required_lock_through_epoch.to_be_bytes())?;
        statement_frame(&mut bytes, &(self.claims.len() as u32).to_be_bytes())?;
        for claim in &self.claims {
            statement_frame(&mut bytes, &claim.vote_nullifier)?;
            statement_frame(&mut bytes, &claim.voting_key_binding)?;
            statement_frame(&mut bytes, &claim.weight.atomic().to_be_bytes())?;
        }
        Ok(bytes)
    }

    pub fn authorization_message(&self) -> Result<Digest64, RelationError> {
        Ok(hash_fields(
            b"thorum.relation-lab.restricted-vote-authorization.v1",
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn authorization_context(&self) -> Result<Context, RelationError> {
        let digest = self.authorization_message()?;
        Ok(Context {
            chain_id: self.chain_id,
            protocol_version: self.protocol_version,
            output_tag: short_tag(&hash_fields(
                b"thorum.relation-lab.stake-auth-context.v1",
                &[&digest],
            )),
        })
    }
}

/// Local bond witness. No owner signing key or owner signature is required for voting.
pub struct BondWitness {
    pub opening: NoteOpening,
    pub nullifier_secret: NullifierSecret,
    pub membership: MerklePath,
    pub voting_public_key: Vec<u8>,
    pub authorization: Vec<u8>,
}

/// Check snapshot eligibility and return linear atomic weight without changing any set.
pub fn check_stake_eligibility(
    statement: &StakeStatement,
    witnesses: &[BondWitness],
    context: &StakeContext<'_>,
) -> Result<Amount, RelationError> {
    if context.snapshot_epoch > context.epoch || context.required_lock_through_epoch < context.epoch
    {
        return Err(RelationError::InvalidSnapshot);
    }
    if statement.chain_id != context.chain_id {
        return Err(RelationError::ChainMismatch);
    }
    if statement.protocol_version != context.protocol_version {
        return Err(RelationError::VersionMismatch);
    }
    if statement.epoch != context.epoch || statement.duty_id != context.duty_id {
        return Err(RelationError::WrongEpoch);
    }
    if statement.validation_tag != context.validation_tag
        || statement.snapshot_epoch != context.snapshot_epoch
        || statement.required_lock_through_epoch != context.required_lock_through_epoch
    {
        return Err(RelationError::ContextMismatch);
    }
    if statement.snapshot_anchor != context.snapshot_anchor {
        return Err(RelationError::UntrustedAnchor);
    }
    if witnesses.len() != statement.claims.len() {
        return Err(RelationError::LimitExceeded);
    }
    let message = statement.authorization_message()?;
    let authorization_context = statement.authorization_context()?;
    let mut bonds = BTreeSet::new();
    let mut votes = BTreeSet::new();
    let mut total = Amount::ZERO;
    for (witness, claim) in witnesses.iter().zip(&statement.claims) {
        let note = &witness.opening;
        if note.chain_id != statement.chain_id {
            return Err(RelationError::ChainMismatch);
        }
        if note.creation_version > statement.protocol_version {
            return Err(RelationError::VersionMismatch);
        }
        let policy = match note.policy {
            NotePolicy::Bond(policy) => policy,
            NotePolicy::Payment => return Err(RelationError::NotBond),
        };
        if note.asset_id != NATIVE_ASSET_ID || note.amount == Amount::ZERO {
            return Err(RelationError::NonNativeBond);
        }
        if policy.activation_epoch > context.snapshot_epoch
            || policy.maturity_epoch > context.snapshot_epoch
        {
            return Err(RelationError::ImmatureBond);
        }
        if policy.unlock_epoch <= context.required_lock_through_epoch {
            return Err(RelationError::ExpiredBondLock);
        }
        let bond_nullifier = note.nullifier(&witness.nullifier_secret)?;
        if !bonds.insert(bond_nullifier) {
            return Err(RelationError::DuplicateBond);
        }
        if context.spent_bond_nullifiers.contains(&bond_nullifier) {
            return Err(RelationError::AlreadySpent);
        }
        if witness
            .membership
            .root(&statement.chain_id, &note.commitment())
            != context.snapshot_anchor
        {
            return Err(RelationError::MembershipFailed);
        }
        let voting_binding = key_binding(&witness.voting_public_key)?;
        if voting_binding == note.owner_key_binding {
            return Err(RelationError::RestrictedKeyNotDistinct);
        }
        if voting_binding != policy.voting_key_binding || claim.voting_key_binding != voting_binding
        {
            return Err(RelationError::VotingKeyMismatch);
        }
        let vote_nullifier =
            note.vote_nullifier(&witness.nullifier_secret, context.epoch, &context.duty_id)?;
        if claim.vote_nullifier != vote_nullifier || !votes.insert(vote_nullifier) {
            return Err(RelationError::VoteNullifierMismatch);
        }
        if context.used_vote_nullifiers.contains(&vote_nullifier) {
            return Err(RelationError::VoteAlreadyUsed);
        }
        if claim.weight != note.amount {
            return Err(RelationError::WeightMismatch);
        }
        verify_authorization(
            &witness.voting_public_key,
            &authorization_context,
            &message,
            &witness.authorization,
        )?;
        total = total
            .checked_add(note.amount)
            .map_err(|_| RelationError::AmountOverflow)?;
    }
    Ok(total)
}
