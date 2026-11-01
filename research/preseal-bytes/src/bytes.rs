//! Bounded public synthetic job syntax. No proof or state validity is established.
use sha3::{Digest, Sha3_512};

pub const MAX_TOTAL: usize = 65536;
pub const MAX_RECORDS: usize = 4;
pub const MAX_POLICY: usize = 1024;
pub const MAX_PAYLOAD: usize = 4096;
const MAGIC: &[u8; 8] = b"KOVAJOB\0";

#[derive(Debug)]
pub enum Error {
    Total,
    Overflow,
    Truncated,
    Magic,
    Width,
    Version,
    ZeroTarget,
    FieldLimit,
    Count,
    Kind,
    Trailing,
    NonCanonical,
    Allocation(std::collections::TryReserveError),
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "unverified job byte error: {self:?}")
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Allocation(error) => Some(error),
            _ => None,
        }
    }
}

// All identifiers here are unverified labels supplied with public test bytes.
#[derive(Clone, Copy, Debug)]
pub struct PublicContext<'a> {
    pub chain: &'a [u8; 32],
    pub rules: &'a [u8; 64],
    pub consensus: &'a [u8; 64],
    pub crypto_registry: &'a [u8; 64],
    pub resources: &'a [u8; 64],
    pub predecessor: &'a [u8; 64],
    pub height: u64,
    pub timestamp: u64,
    pub epoch: u64,
    pub finality: &'a [u8; 64],
    pub target_le: &'a [u8; 32],
    pub parent_profile: &'a [u8; 64],
    pub treasury_policy: &'a [u8],
}

#[derive(Clone, Copy, Debug)]
pub struct PublicRecord<'a> {
    pub kind: u16,
    pub class: &'a [u8; 64],
    pub effect: &'a [u8],
    pub authorization: &'a [u8],
    pub recovery: &'a [u8],
}

const EMPTY_RECORD: PublicRecord<'static> = PublicRecord {
    kind: 1,
    class: &[0; 64],
    effect: &[],
    authorization: &[],
    recovery: &[],
};

pub struct UnverifiedJob<'a> {
    bytes: &'a [u8],
    context: PublicContext<'a>,
    records: [PublicRecord<'a>; MAX_RECORDS],
    count: usize,
}

#[derive(Debug, PartialEq, Eq)]
pub struct UnverifiedRecordIds {
    pub effect: [u8; 64],
    pub authorization: [u8; 64],
}

pub struct UnverifiedBytes {
    bytes: Vec<u8>,
    requested_capacity: usize,
    observed_capacity: usize,
}

impl UnverifiedBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.bytes
    }

    pub fn requested_capacity(&self) -> usize {
        self.requested_capacity
    }

    pub fn observed_capacity(&self) -> usize {
        self.observed_capacity
    }
}

fn add(total: usize, additional: usize) -> Result<usize, Error> {
    total.checked_add(additional).ok_or(Error::Overflow)
}

fn admitted_size(context: PublicContext<'_>, records: &[PublicRecord<'_>]) -> Result<usize, Error> {
    if records.len() > MAX_RECORDS {
        return Err(Error::Count);
    }
    if context.target_le.iter().all(|&x| x == 0) {
        return Err(Error::ZeroTarget);
    }
    if context.treasury_policy.len() > MAX_POLICY {
        return Err(Error::FieldLimit);
    }
    let mut total = add(610, context.treasury_policy.len())?;
    for record in records {
        if !(1..=4).contains(&record.kind) {
            return Err(Error::Kind);
        }
        total = add(total, 86)?;
        for field in [record.effect, record.authorization, record.recovery] {
            if field.len() > MAX_PAYLOAD {
                return Err(Error::FieldLimit);
            }
            total = add(total, field.len())?;
        }
    }
    if total > MAX_TOTAL || u32::try_from(total).is_err() {
        return Err(Error::Total);
    }
    Ok(total)
}

// Private sinks cannot be replaced by caller callbacks or verdicts.
trait Sink {
    fn write(&mut self, bytes: &[u8]);
}

impl Sink for Vec<u8> {
    fn write(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

struct Compare<'a> {
    source: &'a [u8],
    offset: usize,
    equal: bool,
}

impl Sink for Compare<'_> {
    fn write(&mut self, bytes: &[u8]) {
        if !self.equal {
            return;
        }
        match self.offset.checked_add(bytes.len()) {
            Some(end) if self.source.get(self.offset..end) == Some(bytes) => self.offset = end,
            _ => self.equal = false,
        }
    }
}

fn frame(sink: &mut impl Sink, bytes: &[u8]) {
    // Every caller has admitted a complete bounded job or a fixed hash domain.
    let length = u32::try_from(bytes.len()).expect("admitted frame length");
    sink.write(&length.to_be_bytes());
    sink.write(bytes);
}

fn emit(sink: &mut impl Sink, c: PublicContext<'_>, records: &[PublicRecord<'_>]) {
    sink.write(MAGIC);
    for field in [
        1_u16.to_be_bytes().as_slice(),
        c.chain,
        c.rules,
        c.consensus,
        c.crypto_registry,
        c.resources,
        c.predecessor,
        &c.height.to_be_bytes(),
        &c.timestamp.to_be_bytes(),
        &c.epoch.to_be_bytes(),
        c.finality,
        c.target_le,
        c.parent_profile,
        c.treasury_policy,
        &u32::try_from(records.len())
            .expect("admitted count")
            .to_be_bytes(),
    ] {
        frame(sink, field);
    }
    for r in records {
        for field in [
            r.kind.to_be_bytes().as_slice(),
            r.class,
            r.effect,
            r.authorization,
            r.recovery,
        ] {
            frame(sink, field);
        }
    }
}

pub fn encode(
    context: PublicContext<'_>,
    records: &[PublicRecord<'_>],
) -> Result<UnverifiedBytes, Error> {
    let total = admitted_size(context, records)?;
    let mut bytes = Vec::new();
    bytes.try_reserve_exact(total).map_err(Error::Allocation)?;
    let observed_capacity = bytes.capacity();
    emit(&mut bytes, context, records);
    assert_eq!(bytes.len(), total);
    assert_eq!(bytes.capacity(), observed_capacity);
    Ok(UnverifiedBytes {
        bytes,
        requested_capacity: total,
        observed_capacity,
    })
}

struct Cursor<'a> {
    source: &'a [u8],
    offset: usize,
}

impl<'a> Cursor<'a> {
    fn take(&mut self, length: usize) -> Result<&'a [u8], Error> {
        let end = add(self.offset, length)?;
        let bytes = self.source.get(self.offset..end).ok_or(Error::Truncated)?;
        self.offset = end;
        Ok(bytes)
    }

    fn field(&mut self, cap: usize, exact: Option<usize>) -> Result<&'a [u8], Error> {
        let length = u32::from_be_bytes(self.take(4)?.try_into().map_err(|_| Error::Width)?);
        let length = usize::try_from(length).map_err(|_| Error::Overflow)?;
        if exact.is_some_and(|n| n != length) {
            return Err(Error::Width);
        }
        if length > cap {
            return Err(Error::FieldLimit);
        }
        self.take(length)
    }

    fn fixed<const N: usize>(&mut self) -> Result<&'a [u8; N], Error> {
        self.field(N, Some(N))?.try_into().map_err(|_| Error::Width)
    }
}

pub fn parse(bytes: &[u8]) -> Result<UnverifiedJob<'_>, Error> {
    if bytes.len() > MAX_TOTAL {
        return Err(Error::Total);
    }
    let mut reader = Cursor {
        source: bytes,
        offset: 0,
    };
    if reader.take(8)? != MAGIC {
        return Err(Error::Magic);
    }
    if u16::from_be_bytes(*reader.fixed()?) != 1 {
        return Err(Error::Version);
    }
    let context = PublicContext {
        chain: reader.fixed()?,
        rules: reader.fixed()?,
        consensus: reader.fixed()?,
        crypto_registry: reader.fixed()?,
        resources: reader.fixed()?,
        predecessor: reader.fixed()?,
        height: u64::from_be_bytes(*reader.fixed()?),
        timestamp: u64::from_be_bytes(*reader.fixed()?),
        epoch: u64::from_be_bytes(*reader.fixed()?),
        finality: reader.fixed()?,
        target_le: reader.fixed()?,
        parent_profile: reader.fixed()?,
        treasury_policy: reader.field(MAX_POLICY, None)?,
    };
    if context.target_le.iter().all(|&x| x == 0) {
        return Err(Error::ZeroTarget);
    }
    let count =
        usize::try_from(u32::from_be_bytes(*reader.fixed()?)).map_err(|_| Error::Overflow)?;
    if count > MAX_RECORDS {
        return Err(Error::Count);
    }
    let mut records = [EMPTY_RECORD; MAX_RECORDS];
    for record in &mut records[..count] {
        let kind = u16::from_be_bytes(*reader.fixed()?);
        if !(1..=4).contains(&kind) {
            return Err(Error::Kind);
        }
        *record = PublicRecord {
            kind,
            class: reader.fixed()?,
            effect: reader.field(MAX_PAYLOAD, None)?,
            authorization: reader.field(MAX_PAYLOAD, None)?,
            recovery: reader.field(MAX_PAYLOAD, None)?,
        };
    }
    if reader.offset != bytes.len() {
        return Err(Error::Trailing);
    }
    if admitted_size(context, &records[..count])? != bytes.len() {
        return Err(Error::NonCanonical);
    }
    let mut comparison = Compare {
        source: bytes,
        offset: 0,
        equal: true,
    };
    emit(&mut comparison, context, &records[..count]);
    if !comparison.equal || comparison.offset != bytes.len() {
        return Err(Error::NonCanonical);
    }
    Ok(UnverifiedJob {
        bytes,
        context,
        records,
        count,
    })
}

fn hash_fields(fields: &[&[u8]]) -> [u8; 64] {
    let mut hash = Sha3_512::new();
    for field in fields {
        hash.update(
            u32::try_from(field.len())
                .expect("admitted hash field")
                .to_be_bytes(),
        );
        hash.update(field);
    }
    hash.finalize().into()
}

impl<'a> UnverifiedJob<'a> {
    pub fn as_bytes(&self) -> &'a [u8] {
        self.bytes
    }
    pub fn context(&self) -> PublicContext<'a> {
        self.context
    }
    pub fn records(&self) -> &[PublicRecord<'a>] {
        &self.records[..self.count]
    }
    pub fn job_id(&self) -> [u8; 64] {
        hash_fields(&[b"kova.preseal-job.commitment.v1", self.bytes])
    }
    pub fn record_ids(&self, index: usize) -> Option<UnverifiedRecordIds> {
        let record = self.records().get(index)?;
        let effect = hash_fields(&[
            b"kova.effect-id.v1",
            self.context.chain,
            self.context.rules,
            &record.kind.to_be_bytes(),
            record.class,
            record.effect,
            record.recovery,
        ]);
        let authorization =
            hash_fields(&[b"kova.authorization-id.v1", &effect, record.authorization]);
        Some(UnverifiedRecordIds {
            effect,
            authorization,
        })
    }
}

#[cfg(test)]
pub(crate) fn internal_controls() {
    assert!(matches!(add(usize::MAX, 1), Err(Error::Overflow)));
    let mut c = Compare {
        source: b"ab",
        offset: 0,
        equal: true,
    };
    c.write(b"x");
    c.write(b"ab");
    assert!(!c.equal);
    assert_eq!(c.offset, 0);
    let mut c = Compare {
        source: b"a",
        offset: 0,
        equal: true,
    };
    c.write(b"ab");
    assert!(!c.equal);
    let mut c = Compare {
        source: b"ab",
        offset: 0,
        equal: true,
    };
    c.write(b"a");
    assert!(c.equal && c.offset != c.source.len());
}
