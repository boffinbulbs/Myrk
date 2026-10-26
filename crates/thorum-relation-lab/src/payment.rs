use std::collections::{BTreeMap, BTreeSet};

use thorum_core::Amount;
use thorum_crypto_lab::{
    verify_authorization, verify_encryption_witness, Context, EncryptionWitness, SealedNote,
};

use crate::{
    hash_fields, key_binding, short_tag, statement_frame, AssetId, ChainId, Digest64, MerklePath,
    NoteOpening, NotePolicy, NullifierSecret, RelationError, FORMAT_VERSION, NATIVE_ASSET_ID,
};

pub const MAX_PAYMENT_ITEMS: usize = 8;

/// Explicit external state view. The caller authenticates its contents.
pub struct PaymentContext<'a> {
    pub chain_id: ChainId,
    pub protocol_version: u32,
    pub validation_tag: [u8; 32],
    pub accepted_anchors: &'a BTreeSet<Digest64>,
    pub spent_nullifiers: &'a BTreeSet<Digest64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentOutput {
    pub commitment: Digest64,
    pub envelope: SealedNote,
}

/// Public relation statement. It contains no authorization evidence or private witness.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PaymentStatement {
    pub chain_id: ChainId,
    pub protocol_version: u32,
    pub validation_tag: [u8; 32],
    pub anchor: Digest64,
    pub input_nullifiers: Vec<Digest64>,
    pub outputs: Vec<PaymentOutput>,
    pub native_fee: Amount,
}

impl PaymentStatement {
    /// Canonical bounded bytes bind every output commitment and every envelope byte.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, RelationError> {
        if !(1..=MAX_PAYMENT_ITEMS).contains(&self.input_nullifiers.len())
            || !(1..=MAX_PAYMENT_ITEMS).contains(&self.outputs.len())
        {
            return Err(RelationError::LimitExceeded);
        }
        let mut bytes = Vec::new();
        statement_frame(&mut bytes, b"thorum.relation-lab.payment-statement.v1")?;
        statement_frame(&mut bytes, &FORMAT_VERSION.to_be_bytes())?;
        statement_frame(&mut bytes, &self.chain_id)?;
        statement_frame(&mut bytes, &self.protocol_version.to_be_bytes())?;
        statement_frame(&mut bytes, &self.validation_tag)?;
        statement_frame(&mut bytes, &self.anchor)?;
        statement_frame(
            &mut bytes,
            &(self.input_nullifiers.len() as u32).to_be_bytes(),
        )?;
        for nullifier in &self.input_nullifiers {
            statement_frame(&mut bytes, nullifier)?;
        }
        statement_frame(&mut bytes, &(self.outputs.len() as u32).to_be_bytes())?;
        for output in &self.outputs {
            statement_frame(&mut bytes, &output.commitment)?;
            statement_frame(&mut bytes, &output.envelope.to_bytes()?)?;
        }
        statement_frame(&mut bytes, &self.native_fee.atomic().to_be_bytes())?;
        Ok(bytes)
    }

    /// The full statement is hashed before signing. The 64 byte digest is not a proof.
    pub fn authorization_message(&self) -> Result<Digest64, RelationError> {
        Ok(hash_fields(
            b"thorum.relation-lab.payment-authorization.v1",
            &[&self.canonical_bytes()?],
        ))
    }

    pub fn authorization_context(&self) -> Result<Context, RelationError> {
        let digest = self.authorization_message()?;
        Ok(Context {
            chain_id: self.chain_id,
            protocol_version: self.protocol_version,
            output_tag: short_tag(&hash_fields(
                b"thorum.relation-lab.payment-auth-context.v1",
                &[&digest],
            )),
        })
    }
}

pub struct InputWitness {
    pub opening: NoteOpening,
    pub nullifier_secret: NullifierSecret,
    pub membership: MerklePath,
    pub owner_public_key: Vec<u8>,
    pub authorization: Vec<u8>,
}

pub struct OutputWitness {
    pub opening: NoteOpening,
    pub recipient_public_key: Vec<u8>,
    pub encryption: EncryptionWitness,
}

/// Local secret witness. It has no Debug, cloning or serialization implementation.
pub struct PaymentWitness {
    pub inputs: Vec<InputWitness>,
    pub outputs: Vec<OutputWitness>,
}

/// A 32 byte crypto laboratory context tag derived from a full output commitment.
/// It is separate from the full 64 byte commitment checked by the relation.
pub fn output_encryption_context(
    chain_id: ChainId,
    protocol_version: u32,
    validation_tag: [u8; 32],
    output_index: u32,
    commitment: &Digest64,
) -> Result<Context, RelationError> {
    if output_index as usize >= MAX_PAYMENT_ITEMS {
        return Err(RelationError::LimitExceeded);
    }
    let binding = hash_fields(
        b"thorum.relation-lab.output-encryption-context.v1",
        &[
            &chain_id,
            &protocol_version.to_be_bytes(),
            &validation_tag,
            &output_index.to_be_bytes(),
            commitment,
        ],
    );
    Ok(Context {
        chain_id,
        protocol_version,
        output_tag: short_tag(&binding),
    })
}

/// Check one ordinary payment against explicit external state without changing it.
pub fn check_payment(
    statement: &PaymentStatement,
    witness: &PaymentWitness,
    context: &PaymentContext<'_>,
) -> Result<(), RelationError> {
    if statement.chain_id != context.chain_id {
        return Err(RelationError::ChainMismatch);
    }
    if statement.protocol_version != context.protocol_version {
        return Err(RelationError::VersionMismatch);
    }
    if statement.validation_tag != context.validation_tag {
        return Err(RelationError::ContextMismatch);
    }
    if !context.accepted_anchors.contains(&statement.anchor) {
        return Err(RelationError::UntrustedAnchor);
    }
    if witness.inputs.len() != statement.input_nullifiers.len()
        || witness.outputs.len() != statement.outputs.len()
    {
        return Err(RelationError::LimitExceeded);
    }
    let message = statement.authorization_message()?;
    let authorization_context = statement.authorization_context()?;
    let mut seen = BTreeSet::new();
    for nullifier in &statement.input_nullifiers {
        if !seen.insert(*nullifier) {
            return Err(RelationError::DuplicateNullifier);
        }
        if context.spent_nullifiers.contains(nullifier) {
            return Err(RelationError::AlreadySpent);
        }
    }
    let mut input_totals = BTreeMap::new();
    let mut output_totals = BTreeMap::new();
    for (input, nullifier) in witness.inputs.iter().zip(&statement.input_nullifiers) {
        let note = &input.opening;
        if note.chain_id != statement.chain_id {
            return Err(RelationError::ChainMismatch);
        }
        if note.creation_version > statement.protocol_version {
            return Err(RelationError::VersionMismatch);
        }
        if note.policy != NotePolicy::Payment {
            return Err(RelationError::BondSpendUnsupported);
        }
        if note.nullifier(&input.nullifier_secret)? != *nullifier {
            return Err(RelationError::NullifierMismatch);
        }
        if input
            .membership
            .root(&statement.chain_id, &note.commitment())
            != statement.anchor
        {
            return Err(RelationError::MembershipFailed);
        }
        if key_binding(&input.owner_public_key)? != note.owner_key_binding {
            return Err(RelationError::OwnerKeyMismatch);
        }
        verify_authorization(
            &input.owner_public_key,
            &authorization_context,
            &message,
            &input.authorization,
        )?;
        add_amount(&mut input_totals, note.asset_id, note.amount)?;
    }
    let mut output_commitments = BTreeSet::new();
    for (index, (output, private)) in statement.outputs.iter().zip(&witness.outputs).enumerate() {
        let note = &private.opening;
        if note.chain_id != statement.chain_id {
            return Err(RelationError::ChainMismatch);
        }
        if note.creation_version != statement.protocol_version {
            return Err(RelationError::VersionMismatch);
        }
        if note.commitment() != output.commitment || !output_commitments.insert(output.commitment) {
            return Err(RelationError::CommitmentMismatch);
        }
        note.check_recipient_key(&private.recipient_public_key)?;
        let encryption_context = output_encryption_context(
            statement.chain_id,
            statement.protocol_version,
            statement.validation_tag,
            index as u32,
            &output.commitment,
        )?;
        verify_encryption_witness(
            &private.recipient_public_key,
            &encryption_context,
            &note.private_opening_bytes(),
            &private.encryption,
            &output.envelope,
        )?;
        add_amount(&mut output_totals, note.asset_id, note.amount)?;
    }
    add_amount(&mut output_totals, NATIVE_ASSET_ID, statement.native_fee)?;
    if input_totals != output_totals {
        return Err(RelationError::ConservationFailed);
    }
    Ok(())
}

pub(crate) fn add_amount(
    totals: &mut BTreeMap<AssetId, Amount>,
    asset: AssetId,
    amount: Amount,
) -> Result<(), RelationError> {
    if amount != Amount::ZERO {
        let total = totals.entry(asset).or_default();
        *total = total
            .checked_add(amount)
            .map_err(|_| RelationError::AmountOverflow)?;
    }
    Ok(())
}
