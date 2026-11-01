#![forbid(unsafe_code)]
use kova_state_journal::{Error, Journal};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
    process::{Child, Command, Stdio},
};

fn fresh(base: &Path, name: &str) -> (PathBuf, Journal) {
    let path = base.join(name);
    let journal = Journal::initialize(&path, b"A").expect("initialize actual files");
    (path, journal)
}
fn commit(j: &mut Journal, payload: &[u8]) {
    let mut a = j.begin(j.head().generation, payload).expect("begin");
    a.write().expect("write");
    a.sync().expect("sync");
    a.publish().expect("publish");
    a.finish().expect("finish");
}
fn io_kind(error: &Error, kind: std::io::ErrorKind) -> bool {
    matches!(error, Error::Io { source, .. } if source.kind() == kind)
}
fn worker(mode: &str, path: &Path) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_journal-worker"));
    command.arg(mode).arg(path);
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        // CREATE_NO_WINDOW only. No job breakaway flag is requested.
        command.creation_flags(0x08000000);
    }
    command
}
struct OwnedChild(Child);
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if matches!(self.0.try_wait(), Ok(None)) {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}
fn read_process(path: &Path, generation: u64, payload: &[u8]) {
    let output = worker("read", path).output().expect("owned reader process");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let mut expected = generation.to_be_bytes().to_vec();
    expected.extend_from_slice(payload);
    assert_eq!(output.stdout, expected);
    assert!(output.stderr.is_empty());
}

#[test]
#[ignore = "Requires frozen executables and original external resource admission"]
fn actual_journal_controls() {
    assert_eq!(
        std::env::var("KOVA_JOURNAL_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results/cases/primary-v3");
    fs::create_dir_all(root.parent().expect("case parent")).expect("case parent creation");
    fs::create_dir(&root).expect("exclusive native attempt directory");
    let root = root.canonicalize().expect("canonical attempt");
    assert!(
        root.starts_with(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .expect("manifest")
        )
    );
    let mut groups = 0;
    // Independently saved complete record bytes, including checksum literals.
    let literals: Vec<Vec<u8>> = include_str!("../fixtures/frames.hex")
        .lines()
        .map(|line| {
            line.as_bytes()
                .chunks_exact(2)
                .map(|b| {
                    u8::from_str_radix(std::str::from_utf8(b).expect("hex"), 16).expect("hex byte")
                })
                .collect()
        })
        .collect();
    let (p, mut j) = fresh(&root, "literals");
    assert_eq!(fs::read(p.join("frame-0")).expect("read zero"), literals[0]);
    commit(&mut j, b"B");
    assert_eq!(fs::read(p.join("frame-1")).expect("read one"), literals[1]);
    commit(&mut j, b"A");
    assert_eq!(fs::read(p.join("frame-2")).expect("read two"), literals[2]);
    assert!(matches!(j.begin(0, b"C"), Err(Error::Stale)));
    assert!(matches!(j.begin(2, b"C"), Err(Error::Failed)));
    assert!(matches!(j.failure(), Some(Error::Stale)));
    drop(j);
    let j = Journal::open(&p).expect("reopen generation two");
    assert_eq!(j.head().generation, 2);
    assert_eq!(j.head().payload, b"A");
    drop(j);
    groups += 1;

    let (p, mut j) = fresh(&root, "limit");
    assert!(matches!(j.begin(0, &[0; 65]), Err(Error::Limit)));
    assert!(!p.join("pending-0").exists());
    drop(j);
    groups += 1;
    let (_, mut j) = fresh(&root, "generation");
    commit(&mut j, b"B");
    commit(&mut j, b"C");
    commit(&mut j, b"D");
    assert!(matches!(j.begin(3, b"E"), Err(Error::Limit)));
    drop(j);
    groups += 1;
    let (p, j) = fresh(&root, "lease");
    assert!(matches!(Journal::open(&p), Err(Error::Busy)));
    drop(j);
    drop(Journal::open(&p).expect("actual OS lease release"));
    groups += 1;

    let (p, mut j) = fresh(&root, "pending-collision");
    for slot in 0u8..4 {
        fs::write(p.join(format!("pending-{slot}")), [slot]).expect("unowned slot sentinel");
    }
    let e = match j.begin(0, b"B") {
        Err(e) => e,
        Ok(_) => panic!("collision accepted"),
    };
    assert!(matches!(e, Error::NoFreeSlot));
    assert!(matches!(j.begin(0, b"B"), Err(Error::Failed)));
    assert!(matches!(j.failure(), Some(Error::NoFreeSlot)));
    for slot in 0u8..4 {
        assert_eq!(
            fs::read(p.join(format!("pending-{slot}"))).expect("preserved sentinel"),
            [slot]
        );
    }
    drop(j);
    groups += 1;
    let (p, mut j) = fresh(&root, "published-collision");
    let mut a = j.begin(0, b"B").expect("begin");
    a.write().expect("write");
    a.sync().expect("sync");
    fs::write(p.join("frame-1"), b"sentinel").expect("unowned publication sentinel");
    let e = a.publish().expect_err("observed destination collision");
    assert!(matches!(e, Error::DestinationExists));
    assert!(!a.published());
    drop(a);
    assert_eq!(fs::read(p.join("frame-1")).expect("sentinel"), b"sentinel");
    drop(j);
    groups += 1;

    let (p, j) = fresh(&root, "truncation");
    drop(j);
    fs::OpenOptions::new()
        .write(true)
        .open(p.join("frame-0"))
        .expect("owned file")
        .set_len(27)
        .expect("actual truncation");
    assert!(matches!(Journal::open(&p), Err(Error::Length)));
    groups += 1;
    let (p, j) = fresh(&root, "checksum");
    drop(j);
    let mut bytes = literals[0].clone();
    bytes[24] = b'Z';
    fs::write(p.join("frame-0"), &bytes).expect("actual mutation");
    assert!(matches!(Journal::open(&p), Err(Error::Checksum)));
    groups += 1;
    let (p, j) = fresh(&root, "not-authenticated");
    drop(j);
    let mut bytes = literals[0].clone();
    bytes[24] = b'Z';
    let end = bytes.len() - 4;
    let sum: u32 = bytes[..end].iter().map(|b| u32::from(*b)).sum();
    bytes[end..].copy_from_slice(&sum.to_be_bytes());
    fs::write(p.join("frame-0"), bytes).expect("rewritten record");
    let j = Journal::open(&p).expect("checksum is not authentication");
    assert_eq!(j.head().payload, b"Z");
    drop(j);
    groups += 1;
    let (p, mut j) = fresh(&root, "gap");
    commit(&mut j, b"B");
    commit(&mut j, b"A");
    drop(j);
    fs::remove_file(p.join("frame-1")).expect("owned gap control");
    assert!(matches!(Journal::open(&p), Err(Error::Gap)));
    groups += 1;
    let (p, j) = fresh(&root, "format");
    drop(j);
    let mut bytes = literals[0].clone();
    bytes[0] ^= 1;
    fs::write(p.join("frame-0"), bytes).expect("actual format mutation");
    assert!(matches!(Journal::open(&p), Err(Error::Format)));
    groups += 1;
    let (p, mut j) = fresh(&root, "parent");
    commit(&mut j, b"B");
    drop(j);
    let mut bytes = literals[1].clone();
    bytes[19] = 1;
    fs::write(p.join("frame-1"), bytes).expect("actual parent mutation");
    assert!(matches!(Journal::open(&p), Err(Error::Format)));
    groups += 1;
    let (p, mut j) = fresh(&root, "abandon");
    let a = j.begin(0, b"B").expect("begin");
    drop(a);
    assert!(matches!(j.failure(), Some(Error::Aborted)));
    assert!(!p.join("pending-0").exists());
    drop(j);
    groups += 1;
    let (p, mut j) = fresh(&root, "cleanup");
    let mut a = j.begin(0, b"B").expect("begin");
    a.write().expect("write");
    a.sync().expect("sync");
    fs::rename(p.join("pending-0"), p.join("held")).expect("explicit namespace intervention");
    fs::create_dir(p.join("pending-0")).expect("cleanup obstruction");
    // A second sync is a real phase error. Its cleanup meets an actual directory.
    assert!(matches!(a.sync(), Err(Error::Phase)));
    drop(a);
    assert!(matches!(j.failure(), Some(Error::Phase)));
    assert!(matches!(j.cleanup_failure(), Some(Error::Io { .. })));
    assert_eq!(fs::read(p.join("held")).expect("held bytes"), literals[1]);
    drop(j);
    fs::remove_dir(p.join("pending-0")).expect("remove only owned empty obstruction");
    fs::remove_file(p.join("held")).expect("remove only owned held file");
    let mut j = Journal::open(&p).expect("fresh owner after failed attempt");
    let mut a = j.begin(0, b"B").expect("new attempt");
    a.write().expect("write");
    a.sync().expect("sync");
    a.publish().expect("actual publication");
    fs::rename(p.join("frame-1"), p.join("held")).expect("published validation intervention");
    let e = a.finish().expect_err("actual read error after publication");
    assert!(io_kind(&e, std::io::ErrorKind::NotFound));
    assert!(io_kind(
        j.failure().expect("first cause"),
        std::io::ErrorKind::NotFound
    ));
    assert!(j.cleanup_failure().is_none());
    assert_eq!(j.head().generation, 1);
    drop(j);
    fs::rename(p.join("held"), p.join("frame-1")).expect("restore actual published file");
    let j = Journal::open(&p).expect("published snapshot survives validation failure");
    assert_eq!(j.head().generation, 1);
    assert_eq!(j.head().payload, b"B");
    drop(j);
    groups += 1;
    let (p, j) = fresh(&root, "unknown");
    drop(j);
    fs::write(p.join("unknown"), b"x").expect("unknown path");
    assert!(matches!(Journal::open(&p), Err(Error::Format)));
    groups += 1;
    let (p, mut j) = fresh(&root, "payload-bounds");
    commit(&mut j, &[]);
    commit(&mut j, &[0xaa; 64]);
    drop(j);
    let j = Journal::open(&p).expect("maximum bounded payload");
    assert_eq!(j.head().payload, [0xaa; 64]);
    assert_eq!(
        fs::metadata(p.join("frame-2")).expect("file size").len(),
        92
    );
    drop(j);
    groups += 1;
    assert_eq!(groups, 16);
}

#[test]
#[ignore = "Requires frozen executables and original external resource admission"]
fn remaining_recovery_controls() {
    assert_eq!(
        std::env::var("KOVA_JOURNAL_GATE").as_deref(),
        Ok("reviewed-external-resource-admission")
    );
    let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results/cases/recovery-v3");
    fs::create_dir_all(root.parent().expect("case parent")).expect("case parent creation");
    fs::create_dir(&root).expect("exclusive recovery attempt directory");
    let root = root.canonicalize().expect("canonical attempt");
    assert!(
        root.starts_with(
            Path::new(env!("CARGO_MANIFEST_DIR"))
                .canonicalize()
                .expect("manifest")
        )
    );
    let literals: Vec<Vec<u8>> = include_str!("../fixtures/frames.hex")
        .lines()
        .map(|line| {
            line.as_bytes()
                .chunks_exact(2)
                .map(|b| {
                    u8::from_str_radix(std::str::from_utf8(b).expect("hex"), 16).expect("hex byte")
                })
                .collect()
        })
        .collect();
    // A real absent path fails before constructing an owner. This is distinct
    // from the earlier same-owner postpublication read failure.
    let e = match Journal::open(&root.join("missing-owner")) {
        Err(e) => e,
        Ok(_) => panic!("missing owner accepted"),
    };
    assert!(io_kind(&e, std::io::ErrorKind::NotFound));
    let groups = 1;

    let mut terminated = 0;
    let mut readers = 0;
    let mut resumed_writers = 0;
    let mut preserved_orphans = 0;
    for cut in 0..5 {
        let (p, j) = fresh(&root, &format!("cut-{cut}"));
        drop(j);
        let mut child = OwnedChild(
            worker("write", &p)
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .spawn()
                .expect("owned writer process"),
        );
        for (stage, expected) in b"CWSPF".iter().enumerate().take(cut + 1) {
            let mut b = [0];
            child
                .0
                .stdout
                .as_mut()
                .expect("output")
                .read_exact(&mut b)
                .expect("actual operation barrier");
            assert_eq!(b, [*expected]);
            if stage < cut {
                child
                    .0
                    .stdin
                    .as_mut()
                    .expect("input")
                    .write_all(b"+")
                    .expect("ack");
            }
        }
        child.0.kill().expect("terminate only owned writer");
        let status = child.0.wait().expect("wait owned writer");
        assert!(!status.success());
        terminated += 1;
        drop(child);
        let (generation, payload): (u64, &[u8]) = if cut >= 3 { (1, b"B") } else { (0, b"A") };
        read_process(&p, generation, payload);
        readers += 1;
        let pending = p.join("pending-0");
        let before = if pending.exists() {
            Some(fs::read(&pending).expect("retained orphan bytes"))
        } else {
            None
        };
        let original_frame =
            fs::read(p.join(format!("frame-{generation}"))).expect("original committed bytes");
        let status = worker("append", &p)
            .status()
            .expect("fresh postrestart writer");
        assert!(status.success());
        resumed_writers += 1;
        read_process(&p, generation + 1, b"C");
        readers += 1;
        assert_eq!(
            fs::read(p.join(format!("frame-{}", generation + 1))).expect("new committed literal"),
            literals[if generation == 0 { 3 } else { 4 }]
        );
        assert_eq!(
            fs::read(p.join(format!("frame-{generation}"))).expect("old committed bytes"),
            original_frame
        );
        if let Some(before) = before {
            assert_eq!(
                fs::read(&pending).expect("orphan retained after new write"),
                before
            );
            preserved_orphans += 1;
        }
    }
    let (p, j) = fresh(&root, "normal-child");
    drop(j);
    let mut child = OwnedChild(
        worker("write", &p)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()
            .expect("writer"),
    );
    for expected in b"CWSPF" {
        let mut b = [0];
        child
            .0
            .stdout
            .as_mut()
            .expect("output")
            .read_exact(&mut b)
            .expect("barrier");
        assert_eq!(b, [*expected]);
        child
            .0
            .stdin
            .as_mut()
            .expect("input")
            .write_all(b"+")
            .expect("ack");
    }
    assert!(child.0.wait().expect("normal exit").success());
    drop(child);
    read_process(&p, 1, b"B");
    readers += 1;
    assert_eq!(
        (
            groups,
            terminated,
            readers,
            resumed_writers,
            preserved_orphans
        ),
        (1, 5, 11, 5, 3)
    );
    let result = format!(
        "{{\"format\":\"kova.state-journal.native.v3\",\"new_primary_groups\":{groups},\"owned_terminations\":{terminated},\"fresh_reader_processes\":{readers},\"fresh_postrestart_writers\":{resumed_writers},\"preserved_orphans\":{preserved_orphans},\"total_child_processes\":22,\"maximum_payload_bytes\":64,\"power_failure_tests\":0,\"cryptographic_proof_calls\":0}}\n"
    );
    fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(
            root.parent()
                .expect("parent")
                .parent()
                .expect("results")
                .join("native-v3.json"),
        )
        .expect("exclusive result")
        .write_all(result.as_bytes())
        .expect("write result");
}
