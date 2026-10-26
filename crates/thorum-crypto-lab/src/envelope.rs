use crate::{frame, Error, KEM_CIPHERTEXT_BYTES, MAX_NOTE_BYTES, SUITE_VERSION, TAG_BYTES};

const MAGIC: &[u8; 8] = b"THMLAB01";
const OVERHEAD: usize = 8 + 2 + 4 + KEM_CIPHERTEXT_BYTES + 4 + 12 + 4 + TAG_BYTES;

/// A research envelope containing public ciphertext and nonce values.
/// Parsing does not establish authenticity or recipient recoverability.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SealedNote {
    pub kem_ciphertext: Vec<u8>,
    pub nonce: [u8; 12],
    pub ciphertext: Vec<u8>,
}

impl SealedNote {
    /// Return one canonical encoding. There are no optional fields or padding.
    pub fn to_bytes(&self) -> Result<Vec<u8>, Error> {
        self.validate()?;
        let mut bytes = Vec::with_capacity(self.ciphertext.len() + OVERHEAD - TAG_BYTES);
        bytes.extend_from_slice(MAGIC);
        bytes.extend_from_slice(&SUITE_VERSION.to_be_bytes());
        frame(&mut bytes, &self.kem_ciphertext);
        frame(&mut bytes, &self.nonce);
        frame(&mut bytes, &self.ciphertext);
        Ok(bytes)
    }

    /// Reject malformed lengths and trailing data before cryptographic work.
    /// No allocation uses a length supplied by the envelope before bounding it.
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() > MAX_NOTE_BYTES + OVERHEAD {
            return Err(Error::LimitExceeded);
        }
        if bytes.len() < OVERHEAD || bytes.get(..8) != Some(MAGIC.as_slice()) {
            return Err(Error::InvalidEncoding);
        }
        if bytes[8..10] != SUITE_VERSION.to_be_bytes() {
            return Err(Error::UnsupportedSuite);
        }
        let mut input = &bytes[10..];
        let kem = take_field(&mut input)?;
        if kem.len() != KEM_CIPHERTEXT_BYTES {
            return Err(Error::InvalidEncoding);
        }
        let nonce = take_field(&mut input)?;
        let nonce: [u8; 12] = nonce.try_into().map_err(|_| Error::InvalidEncoding)?;
        let ciphertext = take_field(&mut input)?;
        if !input.is_empty() || ciphertext.len() < TAG_BYTES {
            return Err(Error::InvalidEncoding);
        }
        if ciphertext.len() > MAX_NOTE_BYTES + TAG_BYTES {
            return Err(Error::LimitExceeded);
        }
        Ok(Self {
            kem_ciphertext: kem.to_vec(),
            nonce,
            ciphertext: ciphertext.to_vec(),
        })
    }

    pub(crate) fn validate(&self) -> Result<(), Error> {
        if self.kem_ciphertext.len() != KEM_CIPHERTEXT_BYTES || self.ciphertext.len() < TAG_BYTES {
            return Err(Error::InvalidEncoding);
        }
        if self.ciphertext.len() > MAX_NOTE_BYTES + TAG_BYTES {
            return Err(Error::LimitExceeded);
        }
        Ok(())
    }
}

fn take_field<'a>(input: &mut &'a [u8]) -> Result<&'a [u8], Error> {
    let prefix: [u8; 4] = input
        .get(..4)
        .ok_or(Error::InvalidEncoding)?
        .try_into()
        .map_err(|_| Error::InvalidEncoding)?;
    let len = u32::from_be_bytes(prefix) as usize;
    let remaining = &input[4..];
    let field = remaining.get(..len).ok_or(Error::InvalidEncoding)?;
    *input = &remaining[len..];
    Ok(field)
}
