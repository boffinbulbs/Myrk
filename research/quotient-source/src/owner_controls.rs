// Module-private storage fault fixtures. These do not fabricate commitment data.
// Only this child module can place an isolated empty owner at a writer phase.
use super::*;
use crate::diagnostics_setup::Anchor;
use p3_field::PrimeCharacteristicRing;
use serde_json::{Value, json};

fn fixture(anchor: &Anchor) -> CompositeStore {
    let store = CompositeStore::new(anchor).unwrap();
    store
        .transition(Phase::Ready, Phase::MainCommitted)
        .unwrap();
    store
}

fn assert_failed(store: &CompositeStore, cause: Error, state: FileState) {
    let snapshot = store.snapshot().unwrap();
    assert_eq!(snapshot.phase, Phase::Failed);
    assert_eq!(snapshot.failure, Some(cause));
    assert_eq!(snapshot.entries[12].state, state);
    assert_eq!(
        (snapshot.reserved_files, snapshot.reserved_bytes),
        (13, 1_325_056)
    );
    assert!(store.begin_quotient_evaluations().is_err());
}

pub(crate) fn fixed_controls(anchor: &Anchor) -> Value {
    let mut completed = Vec::new();
    {
        let store = fixture(anchor);
        let mut writer = store.begin_quotient_evaluations().unwrap();
        assert!(matches!(
            store.begin_quotient_evaluations(),
            Err(Error::Busy)
        ));
        writer.abort(Error::Incomplete);
        assert_failed(&store, Error::Incomplete, FileState::Removed);
        completed.push("exclusive_writer");
    }
    for (name, row, width) in [("out_of_order", 1, 4), ("short_row", 0, 3)] {
        let store = fixture(anchor);
        let mut writer = store.begin_quotient_evaluations().unwrap();
        assert_eq!(
            writer.write_row(row, &vec![BabyBear::ONE; width]),
            Err(Error::Shape)
        );
        assert_failed(&store, Error::Shape, FileState::Removed);
        completed.push(name);
    }
    {
        let store = fixture(anchor);
        let writer = store.begin_quotient_evaluations().unwrap();
        assert!(matches!(writer.finish(), Err(Error::Incomplete)));
        assert_failed(&store, Error::Incomplete, FileState::Removed);
        completed.push("incomplete_finish");
    }
    {
        let store = fixture(anchor);
        let path = store.path(12);
        fs::write(&path, b"unowned sentinel").unwrap();
        assert!(matches!(
            store.begin_quotient_evaluations(),
            Err(Error::Io(std::io::ErrorKind::AlreadyExists))
        ));
        assert_failed(
            &store,
            Error::Io(std::io::ErrorKind::AlreadyExists),
            FileState::Uncreated,
        );
        assert_eq!(fs::read(&path).unwrap(), b"unowned sentinel");
        drop(store);
        assert_eq!(fs::read(&path).unwrap(), b"unowned sentinel");
        // This fixture created the sentinel, independently of the failed writer.
        fs::remove_file(&path).unwrap();
        fs::remove_dir(path.parent().unwrap()).unwrap();
        completed.push("unowned_sentinel_preserved");
    }
    {
        let store = fixture(anchor);
        let writer = store.begin_quotient_evaluations().unwrap();
        drop(writer);
        assert_failed(&store, Error::Unwind, FileState::Removed);
        completed.push("unfinished_drop_closes_owner");
    }
    {
        let store = fixture(anchor);
        let mut writer = store.begin_quotient_evaluations().unwrap();
        drop(writer.file.take());
        assert_eq!(
            writer.write_row(0, &[BabyBear::ONE; 4]),
            Err(Error::Incomplete)
        );
        assert_failed(&store, Error::Incomplete, FileState::Removed);
        completed.push("closed_writer_descriptor");
    }
    {
        let store = fixture(anchor);
        let mut writer = store.begin_quotient_evaluations().unwrap();
        for row in 0..2048 {
            writer.write_row(row, &[BabyBear::ONE; 4]).unwrap();
        }
        OpenOptions::new()
            .write(true)
            .open(store.path(12))
            .unwrap()
            .set_len(1)
            .unwrap();
        let error = match writer.finish() {
            Ok(_) => panic!("short file sealed"),
            Err(error) => error,
        };
        assert_eq!(error, Error::Access(StorageError::Length));
        assert_failed(&store, error, FileState::Removed);
        completed.push("reopen_rejects_short_file");
    }
    {
        let store = fixture(anchor);
        let other = fixture(anchor);
        let mut writer = store.begin_quotient_evaluations().unwrap();
        for row in 0..2048 {
            writer.write_row(row, &[BabyBear::ONE; 4]).unwrap();
        }
        let input = writer.finish().unwrap();
        assert_eq!(input.dimensions().unwrap(), [2048, 4]);
        assert_eq!(input.try_window(0, 0, 4).unwrap(), [BabyBear::ONE; 4]);
        assert_eq!(input.try_window(2047, 0, 4).unwrap(), [BabyBear::ONE; 4]);
        assert_eq!(other.check_quotient_input(&input), Err(Error::Owner));
        // A real post-seal descriptor read must reject a noncanonical word.
        let mut file = OpenOptions::new().write(true).open(store.path(12)).unwrap();
        file.write_all(&BabyBear::ORDER_U32.to_le_bytes()).unwrap();
        file.sync_all().unwrap();
        drop(file);
        assert!(matches!(
            input.try_window(0, 0, 4),
            Err(Error::Access(StorageError::NonCanonicalField))
        ));
        assert!(input.try_window(2047, 0, 4).is_err());
        assert_eq!(store.snapshot().unwrap().phase, Phase::Failed);
        completed.push("sealed_foreign_owner_and_noncanonical_read");
    }
    json!({"completed":completed,"isolated_owner_fixtures":10,"actual_main_commitments":0,
        "meaning":"storage lifecycle controls only, not committed-data provenance"})
}
