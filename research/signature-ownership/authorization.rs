//! Verifier owned public authorization preprocessing for the retained laboratory.
//! This helper receives no private witness and does not verify a payment proof.

#![forbid(unsafe_code)]

use thorum_crypto_lab::{Context, SUITE_VERSION};
use thorum_relation_lab::{PaymentStatement, RelationError};

pub const PURE_CONTEXT: &[u8; 41] = b"Thorum crypto laboratory authorization v1";
pub const AUTHORIZATION_INPUT_BYTES: usize = 196;
pub const PURE_MESSAGE_BYTES: usize = 239;
const DOMAIN: &[u8] = b"thorum.crypto-lab.authorization.v1";

/// All fields derive from the same bounded public statement. No setter or
/// deserializer accepts a prover supplied digest, context or authority input.
pub struct ExpectedAuthorization {
    public_bytes: Vec<u8>,
    message: [u8; 64],
    context: Context,
    input: [u8; AUTHORIZATION_INPUT_BYTES],
    pure_message: [u8; PURE_MESSAGE_BYTES],
}

impl ExpectedAuthorization {
    /// Public deterministic preprocessing. Eligibility, consumption, private
    /// ownership and proof verification remain separate required operations.
    pub fn from_transaction(transaction: &PaymentStatement) -> Result<Self, RelationError> {
        if SUITE_VERSION != 1 {
            return Err(RelationError::UnsupportedEncoding);
        }
        let public_bytes = transaction.canonical_bytes()?;
        let message = transaction.authorization_message()?;
        let context = transaction.authorization_context()?;
        if context.encode().len() != 80 {
            return Err(RelationError::UnsupportedEncoding);
        }
        let mut input = Vec::with_capacity(AUTHORIZATION_INPUT_BYTES);
        frame(&mut input, DOMAIN);
        frame(&mut input, &SUITE_VERSION.to_be_bytes());
        frame(&mut input, &context.encode());
        frame(&mut input, &message);
        let input: [u8; AUTHORIZATION_INPUT_BYTES] = input
            .try_into()
            .map_err(|_| RelationError::UnsupportedEncoding)?;
        let mut pure_message = [0; PURE_MESSAGE_BYTES];
        pure_message[1] = PURE_CONTEXT.len() as u8;
        pure_message[2..43].copy_from_slice(PURE_CONTEXT);
        pure_message[43..].copy_from_slice(&input);
        Ok(Self {
            public_bytes,
            message,
            context,
            input,
            pure_message,
        })
    }

    pub fn canonical_public_bytes(&self) -> &[u8] {
        &self.public_bytes
    }
    pub fn message(&self) -> &[u8; 64] {
        &self.message
    }
    pub fn context(&self) -> &Context {
        &self.context
    }
    pub fn authorization_input(&self) -> &[u8; AUTHORIZATION_INPUT_BYTES] {
        &self.input
    }
    /// A later private relation must concatenate its actual private tr with
    /// these exact public bytes before constraining SHAKE256 mu.
    pub fn pure_message(&self) -> &[u8; PURE_MESSAGE_BYTES] {
        &self.pure_message
    }
}

fn frame(output: &mut Vec<u8>, value: &[u8]) {
    // Only fixed bounded fields are framed here. Transaction framing uses the
    // original relation serializer and its independent total resource bound.
    output.extend_from_slice(&(value.len() as u32).to_be_bytes());
    output.extend_from_slice(value);
}
