use crate::codec::{self, Counts, Decoded};
use std::{
    collections::TryReserveError,
    io::{self, Read},
};

pub(crate) const PAYLOAD_CAP: usize = 2 * 1024 * 1024;
const WIRE_CAP: usize = PAYLOAD_CAP + 9;
const READ_CAP: usize = WIRE_CAP;

#[derive(Debug)]
pub(crate) enum Error {
    Spent,
    Header,
    Length,
    Truncated,
    Trailing,
    ReadBudget,
    ReadContract,
    Io(io::Error),
    Reservation(TryReserveError),
    Decode(codec::Error),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Io(source) => write!(f, "reader I/O: {source}"),
            Self::Reservation(source) => write!(f, "payload reservation: {source}"),
            Self::Decode(source) => write!(f, "proof decoding: {source:?}"),
            other => write!(f, "frame admission: {other:?}"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Io(source) => Some(source),
            Self::Reservation(source) => Some(source),
            _ => None,
        }
    }
}

#[derive(Default, serde::Serialize)]
pub(crate) struct Attempt {
    spent: bool,
    read_calls: usize,
    bytes_read: usize,
    wire_credit_spent: usize,
    payload_reservations: usize,
    requested_payload_bytes: usize,
    payload_capacity: usize,
    decode: Counts,
}

impl Attempt {
    pub(crate) fn snapshot(&self) -> [usize; 11] {
        [
            usize::from(self.spent),
            self.read_calls,
            self.bytes_read,
            self.wire_credit_spent,
            self.payload_reservations,
            self.requested_payload_bytes,
            self.payload_capacity,
            self.decode.admissions,
            self.decode.typed_decodes,
            self.decode.decoded_shapes,
            self.decode.canonical_encodings,
        ]
    }

    /// Consumes reader ownership. Borrowed readers retain their underlying owner.
    /// A Read call can block; this finite-input component supplies no network deadline.
    pub(crate) fn decode<R: Read>(&mut self, mut reader: R) -> Result<Decoded, Error> {
        if self.spent {
            return Err(Error::Spent);
        }
        self.spent = true;
        let mut header = [0u8; 8];
        self.fill(&mut reader, &mut header)?;
        if &header[..4] != b"KPV1" {
            return Err(Error::Header);
        }
        let length = u32::from_be_bytes(header[4..].try_into().map_err(|_| Error::Header)?);
        let length = usize::try_from(length).map_err(|_| Error::Length)?;
        if length > PAYLOAD_CAP {
            return Err(Error::Length);
        }
        // Charge the complete single request and EOF probe before allocation.
        self.wire_credit_spent = 9 + length;
        self.requested_payload_bytes = length;
        self.payload_reservations += 1;
        let mut payload = Vec::new();
        payload
            .try_reserve_exact(length)
            .map_err(Error::Reservation)?;
        self.payload_capacity = payload.capacity();
        payload.resize(length, 0);
        self.fill(&mut reader, &mut payload)?;
        let mut probe = [0u8; 1];
        if self.read(&mut reader, &mut probe)? != 0 {
            return Err(Error::Trailing);
        }
        codec::decode_json(&payload, &mut self.decode).map_err(Error::Decode)
    }

    fn fill<R: Read>(&mut self, reader: &mut R, mut bytes: &mut [u8]) -> Result<(), Error> {
        while !bytes.is_empty() {
            let read = self.read(reader, bytes)?;
            if read == 0 {
                return Err(Error::Truncated);
            }
            bytes = &mut bytes[read..];
        }
        Ok(())
    }

    fn read<R: Read>(&mut self, reader: &mut R, bytes: &mut [u8]) -> Result<usize, Error> {
        if self.read_calls >= READ_CAP {
            return Err(Error::ReadBudget);
        }
        let credit = if self.wire_credit_spent == 0 {
            8
        } else {
            self.wire_credit_spent
        };
        if bytes.len()
            > credit
                .checked_sub(self.bytes_read)
                .ok_or(Error::ReadBudget)?
        {
            return Err(Error::ReadBudget);
        }
        self.read_calls += 1;
        // Every original I/O error, including Interrupted, terminates this request.
        let read = reader.read(bytes).map_err(Error::Io)?;
        if read > bytes.len() {
            return Err(Error::ReadContract);
        }
        self.bytes_read = self.bytes_read.checked_add(read).ok_or(Error::ReadBudget)?;
        if self.bytes_read > WIRE_CAP {
            return Err(Error::ReadBudget);
        }
        Ok(read)
    }
}
