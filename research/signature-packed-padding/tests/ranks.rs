//! Fixed tail ranks from source-family unions and the retained scalar certificate.
use kova_signature_packed::{
    layout::HEIGHT,
    packed::{self, Bank},
};
use serde::Deserialize;

pub const PADDING_PORTS: [usize; 33] = [
    3, 7, 10, 11, 12, 25, 31, 32, 33, 34, 35, 36, 43, 49, 53, 55, 56, 57, 58, 62, 71, 74, 76, 77,
    78, 79, 80, 81, 82, 89, 99, 103, 124,
];

#[derive(Deserialize)]
struct Certificate {
    format: String,
    rows: usize,
    metric_names: Vec<String>,
    metric_runs: Vec<(usize, usize, [usize; 8])>,
}

pub struct Ranks {
    pub signature: Vec<u8>,
    pub note: Vec<u8>,
}

fn mark<const N: usize>(words: &mut [bool; N], from: usize, to: usize) {
    assert!(from <= to);
    if from == to {
        return;
    }
    words[from / 3..to.div_ceil(3)].fill(true);
}

fn signature_rank(row: usize) -> usize {
    let mut key = [false; 864];
    let mut signature = [false; 1543];
    if row == 0 {
        mark(&mut key, 0, 32);
    }
    if row < 256 {
        mark(&mut key, 32 + 10 * row, 42 + 10 * row);
    }
    if (12..228).contains(&row) {
        let block = row / 6 - 2;
        mark(&mut key, 72 * block, 72 * block + 72);
    }
    if (234..354).contains(&row) {
        let block = row / 6 - 39;
        mark(&mut key, 136 * block, (136 * block + 136).min(2592));
    }
    mark(&mut signature, 4619, 4627);
    if row < 448 {
        mark(&mut signature, 64 + 10 * row, 74 + 10 * row);
    }
    if row < 75 {
        mark(&mut signature, 4544 + row, 4545 + row);
    }
    if row < 6 || row == 5369 {
        mark(&mut signature, 0, 64);
    }
    key.into_iter().filter(|used| *used).count()
        + signature.into_iter().filter(|used| *used).count()
        - 1
}

pub fn expected_constraint(port: usize, offset: usize) -> usize {
    assert!(PADDING_PORTS.contains(&port) && matches!(offset, 1 | 2));
    6127 + port + 2 * PADDING_PORTS.iter().filter(|&&p| p < port).count() + offset
}

pub fn projection() -> Ranks {
    let c: Certificate = serde_json::from_slice(include_bytes!(
        "../../source-certificate/fixtures-certificate.json"
    ))
    .unwrap();
    assert_eq!(c.format, "kova.source-certificate.v1");
    assert_eq!(c.rows, HEIGHT);
    assert_eq!(c.metric_names.len(), 8);
    assert_eq!(c.metric_names[2], "unique_words");
    let mut note = vec![0u8; HEIGHT];
    let mut next = 0;
    for (from, to, metrics) in c.metric_runs {
        assert_eq!(from, next);
        assert!(from < to && to <= HEIGHT && (1..=125).contains(&metrics[2]));
        let rank = metrics[2] - 1;
        assert!(PADDING_PORTS.contains(&rank));
        note[from..to].fill(rank as u8);
        next = to;
    }
    assert_eq!(next, HEIGHT);
    let mut signature = Vec::with_capacity(HEIGHT);
    for (row, &note_rank) in note.iter().enumerate() {
        let rank = signature_rank(row);
        assert!(PADDING_PORTS.contains(&rank) && rank < usize::from(note_rank));
        assert_eq!(packed::port_at(row, Bank::Signature, 4626), (rank, 0));
        assert_eq!(
            packed::port_at(row, Bank::Note, 417),
            (usize::from(note_rank), 0)
        );
        signature.push(rank as u8);
    }
    for (row, sig, n) in [
        (0, 43, 89),
        (1, 34, 80),
        (234, 57, 124),
        (600, 3, 49),
        (5369, 25, 71),
        (8191, 3, 49),
    ] {
        assert_eq!(
            (usize::from(signature[row]), usize::from(note[row])),
            (sig, n)
        );
    }
    Ranks { signature, note }
}
