use kova_signature_packed::{
    layout::*,
    packed::{self, Bank},
};
use serde_json::{json, Value};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

fn number(value: &Value) -> usize {
    value.as_u64().unwrap().try_into().unwrap()
}
fn bank(name: &str) -> (Bank, usize) {
    match name {
        "key" => (Bank::Key, 0),
        "signature" => (Bank::Signature, 864),
        "note" => (Bank::Note, 2407),
        _ => panic!("unknown frozen bank"),
    }
}
fn add(mask: &mut [bool; 2547], name: &str, index: usize) {
    let (kind, offset) = bank(name);
    assert!(index < kind.len());
    mask[offset + index / 3] = true;
}

#[test]
fn complete_fixed_routes_match_frozen_inventory() {
    // This only builds fixed route metadata. No AIR, field row or constructor runs.
    let c: Value = serde_json::from_slice(include_bytes!(
        "../../source-certificate/fixtures-certificate.json"
    ))
    .unwrap();
    assert_eq!(c["format"], "kova.source-certificate.v1");
    assert_eq!(
        (HEIGHT, WIDTH, packed::WORDS, packed::PORTS),
        (8192, 43176, 2547, 125)
    );
    let mut covered = [false; 2547];
    let mut first = [usize::MAX; 2547];
    let mut last = [0usize; 2547];
    let mut max = 0;
    let mut peak = 0;
    let mut total = 0;
    for pc in 0..HEIGHT {
        let mut expected = [false; 2547];
        let mut bytes = vec![];
        if pc < 414 {
            let block = &c["initial_blocks"][pc / 6];
            for segment in block["message"].as_array().unwrap() {
                let name = segment["source"].as_str().unwrap();
                if matches!(name, "key" | "signature" | "note") {
                    let start = number(&segment["first_byte"]);
                    for index in start..start + number(&segment["length"]) {
                        bytes.push((name, index));
                    }
                }
            }
        }
        for family in c["direct_families"].as_array().unwrap() {
            let from = number(&family["rows"][0]);
            if from <= pc && pc < number(&family["rows"][1]) {
                let start = number(&family["first"]) + (pc - from) * number(&family["stride"]);
                for index in start..start + number(&family["count"]) {
                    bytes.push((family["bank"].as_str().unwrap(), index));
                }
            }
        }
        for fixed in c["fixed_note"].as_array().unwrap() {
            bytes.push(("note", number(&fixed[0])));
        }
        for &(name, index) in &bytes {
            add(&mut expected, name, index);
        }
        let wanted: Vec<u16> = expected
            .into_iter()
            .enumerate()
            .filter_map(|(id, used)| used.then_some(id as u16))
            .collect();
        let actual = packed::word_ids_at(pc);
        assert_eq!(actual, wanted, "physical row {pc}");
        assert!(actual.len() <= 125);
        let runs = c["metric_runs"].as_array().unwrap();
        let counts = runs
            .iter()
            .find(|run| number(&run[0]) <= pc && pc < number(&run[1]))
            .unwrap();
        assert_eq!(actual.len(), number(&counts[2][2]));
        for (name, index) in bytes {
            let (kind, offset) = bank(name);
            let (port, byte) = packed::port_at(pc, kind, index);
            assert_eq!(usize::from(actual[port]), offset + index / 3);
            assert_eq!(byte, index % 3);
        }
        for &id in actual {
            let id = usize::from(id);
            covered[id] = true;
            first[id] = first[id].min(pc);
            last[id] = pc;
        }
        if actual.len() > max {
            max = actual.len();
            peak = pc;
        }
        total += actual.len();
    }
    assert!(covered.into_iter().all(|used| used));
    assert_eq!((max, peak, total), (125, 234, 423569));
    for name in ["key", "signature", "note"] {
        let (kind, offset) = bank(name);
        for (field, observed) in [("word_first_rows", &first), ("word_last_rows", &last)] {
            let mut next = 0;
            for run in c["coverage"][name][field].as_array().unwrap() {
                assert_eq!(number(&run[0]), next);
                for word in number(&run[0])..number(&run[1]) {
                    assert_eq!(observed[offset + word], number(&run[2]));
                }
                next = number(&run[1]);
            }
            assert_eq!(next, kind.len().div_ceil(3));
        }
    }
    let (early, a) = packed::port_at(0, Bank::Signature, 0);
    let (later, b) = packed::port_at(1, Bank::Signature, 0);
    assert_ne!(early, later);
    assert_eq!((a, b), (0, 0));
    assert_eq!(packed::word_ids_at(0)[early], packed::word_ids_at(1)[later]);
    for (pc, kind, indices) in [
        (0, Bank::Key, [30, 31, 32]),
        (0, Bank::Signature, [63, 64, 65]),
        (8191, Bank::Note, [48, 49, 50]),
    ] {
        let routes = indices.map(|index| packed::port_at(pc, kind, index));
        assert_eq!(routes[0].0, routes[1].0);
        assert_eq!(routes[1].0, routes[2].0);
        assert_eq!([routes[0].1, routes[1].1, routes[2].1], [0, 1, 2]);
    }
    let invalid = [
        (HEIGHT, Bank::Key, 0),
        (0, Bank::Key, 2592),
        (0, Bank::Signature, 4627),
        (0, Bank::Note, 418),
        (8191, Bank::Key, 0),
        (600, Bank::Signature, 0),
        (600, Bank::Note, 141),
    ];
    for (pc, kind, index) in invalid {
        assert!(std::panic::catch_unwind(|| packed::port_at(pc, kind, index)).is_err());
    }
    assert!(std::panic::catch_unwind(|| packed::word_ids_at(HEIGHT)).is_err());
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    fs::create_dir_all(&directory).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join("routes.json"))
        .unwrap();
    file.write_all(serde_json::to_string(&json!({"physical_rows":8192,"held_words":2547,"peak_words":125,"peak_row":234,"literal_word_selections":423569,"invalid_metadata_refusals":8,"same_block_rank_change":true,"word_lifetimes_match":true,"native_traces":0,"symbolic_collections":0,"backend_proofs":0})).unwrap().as_bytes()).unwrap();
    file.sync_all().unwrap();
}
