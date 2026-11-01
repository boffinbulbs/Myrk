use crate::{
    codec,
    reader::{Attempt, Error, PAYLOAD_CAP},
};
use serde_json::json;
use std::{
    cell::Cell,
    fs::{File, OpenOptions},
    io::{self, Cursor, Read, Write},
    path::PathBuf,
    rc::Rc,
    sync::Arc,
};

const FIXTURE: &[u8] = include_bytes!("../../proof-transport/fixtures/proof.json");

#[derive(Default)]
struct Monitor {
    calls: Cell<usize>,
    drops: Cell<usize>,
}
struct Tracked<R> {
    inner: R,
    monitor: Rc<Monitor>,
}
impl<R: Read> Read for Tracked<R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        self.monitor.calls.set(self.monitor.calls.get() + 1);
        self.inner.read(bytes)
    }
}
impl<R> Drop for Tracked<R> {
    fn drop(&mut self) {
        self.monitor.drops.set(self.monitor.drops.get() + 1);
    }
}
fn tracked<R>(inner: R) -> (Tracked<R>, Rc<Monitor>) {
    let monitor = Rc::new(Monitor::default());
    (
        Tracked {
            inner,
            monitor: monitor.clone(),
        },
        monitor,
    )
}
fn framed(bytes: &[u8]) -> Vec<u8> {
    let mut output = Vec::with_capacity(bytes.len() + 8);
    output.extend_from_slice(b"KPV1");
    output.extend_from_slice(&u32::try_from(bytes.len()).unwrap().to_be_bytes());
    output.extend_from_slice(bytes);
    output
}
fn reentry(attempt: &mut Attempt) {
    let before = attempt.snapshot();
    let (source, monitor) = tracked(Cursor::new(b"unused"));
    assert!(matches!(attempt.decode(source), Err(Error::Spent)));
    assert_eq!(before, attempt.snapshot());
    assert_eq!(monitor.calls.get(), 0);
    assert_eq!(monitor.drops.get(), 1);
}
fn failed<R: Read>(source: R, expected: &str) -> (Attempt, Error) {
    let (source, monitor) = tracked(source);
    let mut attempt = Attempt::default();
    let error = attempt
        .decode(source)
        .err()
        .expect("selected reader failure");
    let actual = match &error {
        Error::Header => "header",
        Error::Length => "length",
        Error::Truncated => "truncated",
        Error::Trailing => "trailing",
        Error::ReadContract => "contract",
        Error::Io(_) => "io",
        Error::Decode(codec::Error::Encoding) => "encoding",
        Error::Decode(codec::Error::Shape) => "shape",
        other => panic!("unexpected reader cause: {other}"),
    };
    assert_eq!(actual, expected);
    assert_eq!(monitor.drops.get(), 1);
    assert_eq!(monitor.calls.get(), attempt.snapshot()[1]);
    reentry(&mut attempt);
    (attempt, error)
}

struct Chunks {
    inner: Cursor<Vec<u8>>,
}
impl Read for Chunks {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = bytes.len().min(7);
        self.inner.read(&mut bytes[..count])
    }
}
#[derive(Debug)]
struct Sentinel(Arc<()>);
impl std::fmt::Display for Sentinel {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("synthetic reader cause")
    }
}
impl std::error::Error for Sentinel {}
struct Fault {
    inner: Cursor<Vec<u8>>,
    after: u64,
    kind: io::ErrorKind,
    identity: Arc<()>,
}
impl Read for Fault {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        if self.inner.position() == self.after {
            return Err(io::Error::new(self.kind, Sentinel(self.identity.clone())));
        }
        self.inner.read(bytes)
    }
}
struct ContractViolation;
impl Read for ContractViolation {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        Ok(bytes.len() + 1)
    }
}

#[allow(
    clippy::assertions_on_constants,
    reason = "Only the admitted release diagnostic may run"
)]
pub fn fixed_reader_diagnostic() {
    assert!(!cfg!(debug_assertions), "release diagnostic required");
    const { assert!(FIXTURE.len() == 596650) };
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    std::fs::create_dir_all(&directory).unwrap();
    let path = directory.join("input.frame");
    {
        let mut file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&path)
            .unwrap();
        file.write_all(b"KPV1").unwrap();
        file.write_all(&u32::try_from(FIXTURE.len()).unwrap().to_be_bytes())
            .unwrap();
        file.write_all(FIXTURE).unwrap();
        file.sync_all().unwrap();
    }
    let mut actual = Attempt::default();
    let (file, monitor) = tracked(File::open(&path).unwrap());
    let mut decoded = actual.decode(file).unwrap();
    assert_eq!(decoded.degree_bits, 9);
    assert_eq!(actual.snapshot()[2], FIXTURE.len() + 8);
    assert_eq!(actual.snapshot()[3], FIXTURE.len() + 9);
    assert_eq!(actual.snapshot()[4..6], [1, FIXTURE.len()]);
    assert!(actual.snapshot()[6] >= FIXTURE.len());
    assert_eq!(actual.snapshot()[7..], [1, 1, 1, 1]);
    assert_eq!(monitor.drops.get(), 1);
    reentry(&mut actual);

    let mut fragmented = Attempt::default();
    let (source, monitor) = tracked(Chunks {
        inner: Cursor::new(framed(FIXTURE)),
    });
    let proof = fragmented.decode(source).unwrap();
    assert_eq!(proof.degree_bits, 9);
    drop(proof);
    assert_eq!(fragmented.snapshot()[2], FIXTURE.len() + 8);
    assert!(fragmented.snapshot()[1] > actual.snapshot()[1]);
    assert!(fragmented.snapshot()[1] <= FIXTURE.len() + 9);
    assert_eq!(monitor.drops.get(), 1);
    reentry(&mut fragmented);

    let mut refusals = Vec::new();
    for (bytes, cause) in [
        (b"KPV".as_slice(), "truncated"),
        (b"BAD1\0\0\0\0".as_slice(), "header"),
        (b"KPV1\0\x20\0\x01".as_slice(), "length"),
        (b"KPV1\xff\xff\xff\xff".as_slice(), "length"),
    ] {
        let (attempt, _) = failed(Cursor::new(bytes), cause);
        assert_eq!(attempt.snapshot()[4], 0);
        assert_eq!(attempt.snapshot()[7], 0);
        refusals.push(attempt.snapshot());
    }
    let writer = OpenOptions::new().write(true).open(&path).unwrap();
    writer.set_len(12).unwrap();
    let (attempt, error) = failed(writer, "io");
    if let Error::Io(source) = error {
        assert!(source.raw_os_error().is_some())
    } else {
        unreachable!()
    }
    assert_eq!(attempt.snapshot()[4], 0);
    refusals.push(attempt.snapshot());
    let (attempt, _) = failed(File::open(&path).unwrap(), "truncated");
    assert_eq!(attempt.snapshot()[2], 12);
    assert_eq!(attempt.snapshot()[4], 1);
    assert_eq!(attempt.snapshot()[7], 0);
    refusals.push(attempt.snapshot());
    std::fs::remove_file(&path).unwrap();

    let mut trailing = framed(FIXTURE);
    trailing.push(b'x');
    let (attempt, _) = failed(Cursor::new(trailing), "trailing");
    assert_eq!(attempt.snapshot()[2], FIXTURE.len() + 9);
    assert_eq!(attempt.snapshot()[7], 0);
    refusals.push(attempt.snapshot());
    let (attempt, _) = failed(Cursor::new(framed(b"{}")), "encoding");
    assert_eq!(attempt.snapshot()[8], 1);
    refusals.push(attempt.snapshot());
    decoded.degree_bits = 10;
    let wrong_shape = serde_json::to_vec(&decoded).unwrap();
    drop(decoded);
    let (attempt, _) = failed(Cursor::new(framed(&wrong_shape)), "shape");
    assert_eq!(attempt.snapshot()[8], 1);
    refusals.push(attempt.snapshot());
    drop(wrong_shape);

    for (after, kind) in [
        (0, io::ErrorKind::Interrupted),
        (
            u64::try_from(FIXTURE.len() + 8).unwrap(),
            io::ErrorKind::TimedOut,
        ),
    ] {
        let identity = Arc::new(());
        let (attempt, error) = failed(
            Fault {
                inner: Cursor::new(framed(FIXTURE)),
                after,
                kind,
                identity: identity.clone(),
            },
            "io",
        );
        if let Error::Io(source) = error {
            assert_eq!(source.kind(), kind);
            let sentinel = source
                .get_ref()
                .unwrap()
                .downcast_ref::<Sentinel>()
                .unwrap();
            assert!(Arc::ptr_eq(&sentinel.0, &identity));
        } else {
            unreachable!()
        }
        assert_eq!(attempt.snapshot()[7], 0);
        if after == 0 {
            assert_eq!(attempt.snapshot()[1], 1);
            assert_eq!(attempt.snapshot()[4], 0)
        }
        refusals.push(attempt.snapshot());
    }
    let (attempt, _) = failed(ContractViolation, "contract");
    assert_eq!(attempt.snapshot()[4], 0);
    refusals.push(attempt.snapshot());
    let (attempt, _) = failed(Cursor::new(framed(&vec![b' '; PAYLOAD_CAP])), "encoding");
    assert_eq!(attempt.snapshot()[5], PAYLOAD_CAP);
    assert_eq!(attempt.snapshot()[2], PAYLOAD_CAP + 8);
    assert_eq!(attempt.snapshot()[8], 1);
    refusals.push(attempt.snapshot());
    let (attempt, _) = failed(Cursor::new(framed(b"")), "encoding");
    assert_eq!(attempt.snapshot()[5], 0);
    assert_eq!(attempt.snapshot()[8], 1);
    refusals.push(attempt.snapshot());
    assert_eq!(refusals.len(), 14);

    let report = json!({"format":"kova.frame-reader.native.v1","fixture_bytes":FIXTURE.len(),
        "owned_file_positive":actual,"fragmented_positive":fragmented,"failure_snapshots":refusals,
        "failed_reentries":14,"successful_reentries":2,"owned_reader_drops":32,
        "real_os_read_errors":1,"preserved_synthetic_io_causes":2,"scratch_removed":!path.exists(),
        "proofs_produced":0,"verifier_calls":0,"pcs_instances":0,"network_reads":0});
    let bytes = serde_json::to_vec_pretty(&report).unwrap();
    assert!(bytes.len() <= 16384);
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("native.json"))
        .unwrap();
    file.write_all(&bytes).unwrap();
    file.sync_all().unwrap();
}
