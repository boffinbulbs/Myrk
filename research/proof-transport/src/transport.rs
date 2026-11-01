//! Borrowed resource admission. This does not verify a proof.
//! Mechanisms follow the MIT licensed conservation laboratory byte preflight.
use std::io::{self, Write};

const BYTE_CAP: usize = 2 * 1024 * 1024;
const DEPTH_CAP: usize = 24;
const TOKEN_CAP: usize = 200_000;
const ITEM_CAP: usize = 16_384;
const MAGIC: &[u8; 4] = b"KPV1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Error {
    Frame,
    Bytes,
    Depth,
    Tokens,
    Items,
    String,
    Number,
    Delimiter,
    Lexical,
}

/// Budget admission only. Owned typed decoding and verification remain separate.
pub(crate) struct Admitted<'a> {
    bytes: &'a [u8],
}

impl<'a> Admitted<'a> {
    pub(crate) fn bytes(&self) -> &'a [u8] {
        self.bytes
    }
}

/// This borrowed path does not bound an upstream network allocation.
pub(crate) fn admit_frame(frame: &[u8]) -> Result<Admitted<'_>, Error> {
    let header = frame.get(..8).ok_or(Error::Frame)?;
    if &header[..4] != MAGIC {
        return Err(Error::Frame);
    }
    let declared = u32::from_be_bytes(header[4..8].try_into().map_err(|_| Error::Frame)?);
    let declared = usize::try_from(declared).map_err(|_| Error::Frame)?;
    if declared > BYTE_CAP {
        return Err(Error::Bytes);
    }
    let payload = &frame[8..];
    if payload.len() != declared {
        return Err(Error::Frame);
    }
    admit_json(payload)
}

/// Fixed stack counters precede all owned proof collections.
/// This is lexical budgeting, not JSON grammar, schema or canonical validation.
pub(crate) fn admit_json(bytes: &[u8]) -> Result<Admitted<'_>, Error> {
    if bytes.len() > BYTE_CAP {
        return Err(Error::Bytes);
    }
    let mut closing = [0u8; DEPTH_CAP];
    let mut commas = [0usize; DEPTH_CAP];
    let mut depth = 0usize;
    let mut tokens = 0usize;
    let mut index = 0usize;
    while index < bytes.len() {
        match bytes[index] {
            b'[' | b'{' => {
                if depth == DEPTH_CAP {
                    return Err(Error::Depth);
                }
                closing[depth] = if bytes[index] == b'[' { b']' } else { b'}' };
                commas[depth] = 0;
                depth += 1;
                tokens += 1;
                index += 1;
            }
            b']' | b'}' => {
                depth = depth.checked_sub(1).ok_or(Error::Delimiter)?;
                if closing[depth] != bytes[index] {
                    return Err(Error::Delimiter);
                }
                index += 1;
            }
            b',' => {
                let slot = depth.checked_sub(1).ok_or(Error::Delimiter)?;
                commas[slot] += 1;
                if commas[slot] >= ITEM_CAP {
                    return Err(Error::Items);
                }
                index += 1;
            }
            b'"' => {
                index += 1;
                let start = index;
                while bytes.get(index).is_some_and(|byte| *byte != b'"') {
                    if bytes[index] == b'\\'
                        || !bytes[index].is_ascii()
                        || bytes[index] < 0x20
                        || index - start >= 64
                    {
                        return Err(Error::String);
                    }
                    index += 1;
                }
                if bytes.get(index) != Some(&b'"') {
                    return Err(Error::String);
                }
                tokens += 1;
                index += 1;
            }
            b'0'..=b'9' => {
                let start = index;
                while bytes.get(index).is_some_and(u8::is_ascii_digit) {
                    index += 1;
                }
                if index - start > 20 {
                    return Err(Error::Number);
                }
                tokens += 1;
            }
            b'n' => {
                if bytes.get(index..index + 4) != Some(b"null") {
                    return Err(Error::Lexical);
                }
                index += 4;
                tokens += 1;
            }
            b':' | b' ' | b'\n' | b'\r' | b'\t' => index += 1,
            _ => return Err(Error::Lexical),
        }
        if tokens > TOKEN_CAP {
            return Err(Error::Tokens);
        }
    }
    if depth != 0 {
        return Err(Error::Delimiter);
    }
    Ok(Admitted { bytes })
}

/// Compare actual serializer output to the admitted input without an encoded Vec.
/// Only the typed decoder integration may decide which proof is serialized here.
pub(crate) struct CanonicalWriter<'a> {
    remaining: &'a [u8],
    failed: bool,
}

impl<'a> CanonicalWriter<'a> {
    pub(crate) fn new(admitted: &Admitted<'a>) -> Self {
        Self {
            remaining: admitted.bytes,
            failed: false,
        }
    }

    pub(crate) fn finish(self) -> io::Result<()> {
        if self.failed || !self.remaining.is_empty() {
            Err(io::Error::other("noncanonical proof encoding"))
        } else {
            Ok(())
        }
    }
}

impl Write for CanonicalWriter<'_> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        if self.failed || self.remaining.get(..bytes.len()) != Some(bytes) {
            self.failed = true;
            return Err(io::Error::other("noncanonical proof encoding"));
        }
        self.remaining = &self.remaining[bytes.len()..];
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        if self.failed {
            Err(io::Error::other("noncanonical proof encoding"))
        } else {
            Ok(())
        }
    }
}
