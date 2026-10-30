use kova_source_packing::{
    BITS, CLOCK, CONSUMERS, HEIGHT, OUTPUT, PORTS, PackedSourceAir, Sources, WIDTH,
    routes::{self, WINDOWS, WORD_COUNT},
};
use p3_air::{
    check_all_constraints,
    symbolic::{AirLayout, get_symbolic_constraints},
};
use p3_baby_bear::BabyBear as F;
use p3_field::{PrimeCharacteristicRing, PrimeField32};
use p3_matrix::{Matrix, dense::RowMajorMatrix};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    fs::{self, OpenOptions},
    io::Write,
    path::PathBuf,
};

#[derive(Deserialize)]
struct Reference {
    key: Vec<u8>,
    signature: Vec<u8>,
    note: Vec<u8>,
    words: Vec<u32>,
    ports: Vec<Vec<u32>>,
    consumers: Vec<Vec<u32>>,
}
fn write(name: &str, value: &Value) {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("results");
    fs::create_dir_all(&directory).unwrap();
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(directory.join(name))
        .unwrap();
    file.write_all(serde_json::to_string(value).unwrap().as_bytes())
        .unwrap();
    file.sync_all().unwrap();
}

#[test]
fn a_symbolic_shape_without_trace() {
    let layout = AirLayout::from_air::<F>(&PackedSourceAir);
    assert_eq!(
        (
            layout.main_width,
            layout.num_public_values,
            layout.preprocessed_width,
            layout.num_periodic_columns
        ),
        (1364, 0, 0, 0)
    );
    let constraints = get_symbolic_constraints::<F, _>(&PackedSourceAir, layout);
    let count = constraints.len();
    let degree = constraints
        .iter()
        .map(|v| v.degree_multiple())
        .max()
        .unwrap();
    write(
        "symbolic.json",
        &json!({"collections":1,"constraints":count,"degree":degree,"native_traces":0,"backend_proofs":0}),
    );
    assert_eq!((count, degree), (1451, 2));
}

struct Changes(Vec<(usize, F)>);
impl Changes {
    fn set(&mut self, trace: &mut RowMajorMatrix<F>, row: usize, column: usize, value: F) {
        let index = row * WIDTH + column;
        if !self.0.iter().any(|(at, _)| *at == index) {
            self.0.push((index, trace.values[index]));
        }
        trace.values[index] = value;
    }
    fn restore(self, trace: &mut RowMajorMatrix<F>) {
        for (index, value) in self.0 {
            trace.values[index] = value;
        }
    }
    fn port(&mut self, trace: &mut RowMajorMatrix<F>, row: usize, port: usize, value: u32) {
        assert!(value < (1 << 24));
        for bit in 0..24 {
            self.set(
                trace,
                row,
                BITS + port * 24 + bit,
                F::from_bool((value >> bit) & 1 != 0),
            );
        }
    }
    fn outputs(&mut self, trace: &mut RowMajorMatrix<F>, row: usize) {
        for index in 0..CONSUMERS {
            let value = routes::consumer(WINDOWS[row], index)
                .map_or(F::ZERO, |(p, offset)| port_byte(trace, row, p, offset));
            self.set(trace, row, OUTPUT + index, value);
        }
    }
    fn clock(&mut self, trace: &mut RowMajorMatrix<F>, row: usize, tick: usize) {
        for index in 0..HEIGHT {
            self.set(trace, row, CLOCK + index, F::from_bool(index == tick));
        }
    }
}
fn port_byte(trace: &RowMajorMatrix<F>, row: usize, port: usize, offset: usize) -> F {
    (0..8)
        .map(|bit| {
            trace.values[row * WIDTH + BITS + port * 24 + offset * 8 + bit] * F::from_u32(1 << bit)
        })
        .sum()
}
fn port_value(trace: &RowMajorMatrix<F>, row: usize, port: usize) -> F {
    port_byte(trace, row, port, 0)
        + port_byte(trace, row, port, 1) * F::from_u32(256)
        + port_byte(trace, row, port, 2) * F::from_u32(65536)
}
fn accept(trace: &RowMajorMatrix<F>, positives: &mut usize) {
    let report = check_all_constraints(&PackedSourceAir, trace, &[], Some(1));
    assert!(report.is_ok(), "{report:?}");
    assert_eq!(
        (report.total_rows, report.total_constraints_per_row),
        (16, 1451)
    );
    *positives += 1;
}

#[test]
fn b_native_reads_and_eighteen_rejections() {
    let expected: Reference =
        serde_json::from_str(include_str!("../fixtures/reference.json")).unwrap();
    let sources = Sources::new(
        expected.key.try_into().unwrap(),
        expected.signature.try_into().unwrap(),
        expected.note.try_into().unwrap(),
    );
    let mut trace = sources.trace();
    assert_eq!((trace.height(), trace.width), (HEIGHT, WIDTH));
    assert_eq!(expected.words.len(), WORD_COUNT);
    assert_eq!(
        (expected.ports.len(), expected.consumers.len()),
        (HEIGHT, HEIGHT)
    );
    for row in 0..HEIGHT {
        assert_eq!(
            (expected.ports[row].len(), expected.consumers[row].len()),
            (PORTS, CONSUMERS)
        );
        for slot in 0..WORD_COUNT {
            assert_eq!(
                trace.values[row * WIDTH + slot].as_canonical_u32(),
                expected.words[slot]
            );
        }
        for tick in 0..HEIGHT {
            assert_eq!(
                trace.values[row * WIDTH + CLOCK + tick],
                F::from_bool(row == tick)
            );
        }
        for port in 0..PORTS {
            assert_eq!(
                port_value(&trace, row, port).as_canonical_u32(),
                expected.ports[row][port]
            );
            for bit in 0..24 {
                assert_eq!(
                    trace.values[row * WIDTH + BITS + port * 24 + bit],
                    F::from_bool((expected.ports[row][port] >> bit) & 1 != 0)
                );
            }
        }
        for index in 0..CONSUMERS {
            assert_eq!(
                trace.values[row * WIDTH + OUTPUT + index].as_canonical_u32(),
                expected.consumers[row][index]
            );
        }
    }
    let mut positives = 0;
    accept(&trace, &mut positives);
    let names = [
        "wrong_source",
        "wrong_word",
        "stale_repeat",
        "active_hold",
        "inactive_hold",
        "first_anchor",
        "clock_restart",
        "last_anchor",
        "key_alignment",
        "note_alignment",
        "signature_padding",
        "note_padding",
        "note417",
        "non_boolean",
        "carry_alias",
        "unused_active_port",
        "inactive_port",
        "inactive_consumer",
    ];
    let mut records = vec![];
    for (case, name) in names.into_iter().enumerate() {
        let mut alternative = Changes(vec![]);
        if case == 2 {
            let word = expected.words[46] ^ 1;
            for row in 0..HEIGHT {
                alternative.set(&mut trace, row, 46, F::from_u32(word));
            }
            for row in [2, 7] {
                alternative.port(&mut trace, row, 0, word);
                alternative.outputs(&mut trace, row);
            }
            accept(&trace, &mut positives);
        }
        let mut changes = Changes(vec![]);
        match case {
            0 | 1 => {
                let wrong = if case == 0 {
                    expected.words[46]
                } else {
                    expected.words[11]
                };
                assert_ne!(wrong, expected.ports[0][0]);
                changes.port(&mut trace, 0, 0, wrong);
                changes.outputs(&mut trace, 0);
            }
            2 => {
                changes.port(&mut trace, 7, 0, expected.words[46]);
                changes.outputs(&mut trace, 7);
            }
            3 | 4 => {
                let row = if case == 3 { 5 } else { 13 };
                changes.set(&mut trace, row, 0, F::from_u32(expected.words[0] + 1));
            }
            5 => changes.clock(&mut trace, 0, 1),
            6 => changes.clock(&mut trace, 10, 0),
            7 => changes.clock(&mut trace, 15, 14),
            8 | 9 => {
                let row = if case == 8 { 0 } else { 3 };
                let wrong = port_byte(&trace, row, 0, 0);
                assert_ne!(wrong, trace.values[row * WIDTH + OUTPUT]);
                changes.set(&mut trace, row, OUTPUT, wrong);
            }
            10..=12 => {
                let (row, slot, addition) = match case {
                    10 => (5, 50, 256),
                    11 => (6, 59, 65536),
                    _ => (6, 59, 1),
                };
                let word = expected.words[slot] + addition;
                for r in 0..HEIGHT {
                    changes.set(&mut trace, r, slot, F::from_u32(word));
                }
                changes.port(&mut trace, row, 0, word);
                changes.outputs(&mut trace, row);
                assert_eq!(port_value(&trace, row, 0), trace.values[row * WIDTH + slot]);
            }
            13 => changes.set(&mut trace, 0, BITS, F::TWO),
            14 => {
                let original = port_value(&trace, 2, 0);
                assert_eq!(trace.values[2 * WIDTH + BITS + 8], F::ONE);
                let low = trace.values[2 * WIDTH + BITS + 7];
                changes.set(&mut trace, 2, BITS + 7, low + F::TWO);
                changes.set(&mut trace, 2, BITS + 8, F::ZERO);
                changes.outputs(&mut trace, 2);
                assert_eq!(port_value(&trace, 2, 0), original);
            }
            15 => changes.set(&mut trace, 2, BITS + 47 * 24, F::ONE),
            16 => changes.set(&mut trace, 8, BITS, F::ONE),
            17 => changes.set(&mut trace, 9, OUTPUT, F::ONE),
            _ => unreachable!(),
        }
        let report = check_all_constraints(&PackedSourceAir, &trace, &[], Some(1));
        let observed = json!({"name":name,"rejected":!report.is_ok(),"failures":report.failures.len(),"row":report.failures.first().map(|v|v.row),"constraint":report.failures.first().map(|v|v.constraint)});
        write(&format!("{case:02}-{name}.json"), &observed);
        assert!(!report.is_ok(), "{name}");
        // The retained threshold stops between rows, after collecting a row.
        assert!(report.failures.len() <= 1451);
        assert!(
            report
                .failures
                .iter()
                .all(|v| v.row == report.failures[0].row)
        );
        if let Some(expected) = match case {
            10 => Some(1263),
            11 => Some(1266),
            12 => Some(1450),
            14 => Some(117),
            _ => None,
        } {
            assert_eq!(report.failures.len(), 1);
            assert_eq!(report.failures[0].constraint, expected);
        }
        records.push(observed);
        changes.restore(&mut trace);
        accept(&trace, &mut positives);
        if case == 2 {
            alternative.restore(&mut trace);
            accept(&trace, &mut positives);
        }
    }
    assert_eq!((positives, records.len()), (21, 18));
    write(
        "native.json",
        &json!({"native_traces":1,"max_live_traces":1,"rows":16,"width":1364,"failure_threshold":1,"row_granular_threshold":true,"failure_bound_per_row":1451,"positive_checks":positives,"restoration_checks":18,"backend_proofs":0,"rejections":records}),
    );
}
