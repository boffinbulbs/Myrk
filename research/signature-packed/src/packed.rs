//! Fixed private source words and complete-schedule byte read ports.
//!
//! The cache contains program addresses only. It never contains witness values,
//! field expressions, a native verdict, or a copy of a source byte bank.
use crate::{layout::*, sources, Witness};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use std::sync::OnceLock;

pub const WORDS: usize = 2547;
pub const PORTS: usize = 125;
const BITS_PER_PORT: usize = 24;
// Every changing early source family ends by row 448. Only the final comparison
// at 5369 and its end can change the word set afterwards: at most 449 + 2 epochs.
const MAX_EPOCHS: usize = 451;

const _: () = {
    assert!(HEIGHT == 8192 && CLOCK_LOW == 64 && CLOCK_HIGH == 128);
    assert!(KEY == 10724);
    assert!(crate::program::SOURCE_END == 414);
    assert!(crate::full_program::FINAL_END == 5370);
    assert!(SIGNATURE == KEY + 864 && NOTE == SIGNATURE + 1543);
    assert!(SOURCE_PORTS == NOTE + 140 && SOURCE_PORTS == KEY + WORDS);
    assert!(MESSAGE == SOURCE_PORTS + PORTS * BITS_PER_PORT);
    assert!(HEIGHT <= u16::MAX as usize);
    assert!(WORDS <= u16::MAX as usize);
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Bank {
    Key,
    Signature,
    Note,
}

impl Bank {
    pub const fn len(self) -> usize {
        match self {
            Self::Key => 2592,
            Self::Signature => 4627,
            Self::Note => 418,
        }
    }

    pub const fn is_empty(self) -> bool {
        false
    }

    const fn first_word(self) -> usize {
        match self {
            Self::Key => 0,
            Self::Signature => 864,
            Self::Note => 2407,
        }
    }

    fn word(self, byte: usize) -> u16 {
        assert!(byte < self.len(), "fixed source byte is out of bounds");
        (self.first_word() + byte / 3) as u16
    }
}

struct Epoch {
    from: u16,
    to: u16,
    // Sorted flattened IDs: key words, signature words, then note words.
    words: Vec<u16>,
}

struct PortRun {
    from: u16,
    to: u16,
    port: u16,
}

struct AllRowWord {
    word: u16,
    runs: Vec<PortRun>,
}

struct Routes {
    epochs: Vec<Epoch>,
    all_row: Vec<AllRowWord>,
}

static ROUTES: OnceLock<Routes> = OnceLock::new();

fn mark(mask: &mut [bool; WORDS], bank: Bank, first: usize, count: usize) {
    assert!(first <= bank.len() && count <= bank.len() - first);
    if count == 0 {
        return;
    }
    for word in first / 3..(first + count).div_ceil(3) {
        mask[bank.first_word() + word] = true;
    }
}

fn row_words(pc: usize) -> Vec<u16> {
    assert!(pc < HEIGHT);
    let mut mask = [false; WORDS];
    if pc < crate::program::SOURCE_END {
        for byte in 0..168 {
            match sources::message_source(pc / 6, byte) {
                sources::Source::Key(index) => mark(&mut mask, Bank::Key, index, 1),
                sources::Source::Signature(index) => {
                    mark(&mut mask, Bank::Signature, index, 1);
                }
                sources::Source::Note(index) => mark(&mut mask, Bank::Note, index, 1),
                sources::Source::Fixed(_) | sources::Source::Tr(_) | sources::Source::Public(_) => {
                }
            }
        }
    }
    if pc == 0 {
        mark(&mut mask, Bank::Key, 0, 32);
    }
    if pc < 256 {
        mark(&mut mask, Bank::Key, 32 + 10 * pc, 10);
    }
    if pc < 448 {
        mark(&mut mask, Bank::Signature, 64 + 10 * pc, 10);
    }
    if pc < 75 {
        mark(&mut mask, Bank::Signature, 4544 + pc, 1);
    }
    mark(&mut mask, Bank::Signature, 4619, 8);
    mark(&mut mask, Bank::Note, 49, 32);
    if pc == 234 {
        mark(&mut mask, Bank::Note, 141, 64);
    }
    for index in 0..Bank::Note.len() {
        if sources::note_fixed(index).is_some() {
            mark(&mut mask, Bank::Note, index, 1);
        }
    }
    if pc == crate::full_program::FINAL_END - 1 {
        mark(&mut mask, Bank::Signature, 0, 64);
    }
    let mut words = Vec::with_capacity(PORTS);
    for (word, used) in mask.into_iter().enumerate() {
        if used {
            assert!(
                words.len() < PORTS,
                "fixed source route exceeds port budget"
            );
            words.push(word as u16);
        }
    }
    words
}

fn build_routes() -> Routes {
    // Only one row's temporary mask/vector exists at a time. Equal consecutive
    // rows extend an epoch instead of retaining an 8192 x 125 address table.
    let mut epochs: Vec<Epoch> = Vec::with_capacity(MAX_EPOCHS);
    let mut seen = [false; WORDS];
    for pc in 0..HEIGHT {
        let words = row_words(pc);
        for &word in &words {
            seen[usize::from(word)] = true;
        }
        if let Some(last) = epochs.last_mut().filter(|last| last.words == words) {
            last.to = (pc + 1) as u16;
            continue;
        }
        assert!(epochs.len() < MAX_EPOCHS, "fixed route epoch bound changed");
        epochs.push(Epoch {
            from: pc as u16,
            to: (pc + 1) as u16,
            words,
        });
    }
    assert!(
        seen.into_iter().all(|used| used),
        "unread private source word"
    );

    let mut all_row = Vec::with_capacity(PORTS);
    for &word in &epochs[0].words {
        if epochs
            .iter()
            .any(|epoch| epoch.words.binary_search(&word).is_err())
        {
            continue;
        }
        let mut runs: Vec<PortRun> = Vec::with_capacity(MAX_EPOCHS);
        for epoch in &epochs {
            let port = epoch
                .words
                .binary_search(&word)
                .expect("checked all-row source word") as u16;
            if let Some(last) = runs
                .last_mut()
                .filter(|last| last.port == port && last.to == epoch.from)
            {
                last.to = epoch.to;
                continue;
            }
            runs.push(PortRun {
                from: epoch.from,
                to: epoch.to,
                port,
            });
        }
        all_row.push(AllRowWord { word, runs });
    }
    Routes { epochs, all_row }
}

fn routes() -> &'static Routes {
    // message_source and note_fixed are pure retained schedule functions. They
    // must never call this cache or an AIR/constructor entry while it initializes.
    ROUTES.get_or_init(build_routes)
}

fn epoch_at(routes: &Routes, pc: usize) -> &Epoch {
    assert!(pc < HEIGHT);
    let index = routes
        .epochs
        .partition_point(|epoch| usize::from(epoch.to) <= pc);
    let epoch = &routes.epochs[index];
    assert!(usize::from(epoch.from) <= pc);
    epoch
}

fn port_byte<AB: AirBuilder<F = BabyBear>>(
    row: &[AB::Var],
    port: usize,
    offset: usize,
) -> AB::Expr {
    assert!(port < PORTS && offset < 3 && row.len() >= MESSAGE);
    (0..8)
        .map(|bit| {
            row[SOURCE_PORTS + BITS_PER_PORT * port + 8 * offset + bit]
                * BabyBear::from_u32(1 << bit)
        })
        .sum()
}

/// Exact interval selector, conditionally equivalent to summing retained at(pc).
/// A complete 64-row low-clock block uses its high indicator because the actual
/// retained clock constrains the low indicators to sum to one on every row.
fn selector<AB: AirBuilder<F = BabyBear>>(row: &[AB::Var], from: usize, to: usize) -> AB::Expr {
    assert!(from <= to && to <= HEIGHT && row.len() >= MESSAGE);
    if from == 0 && to == HEIGHT {
        return AB::Expr::ONE;
    }
    let mut result = AB::Expr::ZERO;
    for high in from / CLOCK_LOW..to.div_ceil(CLOCK_LOW) {
        let start = from.saturating_sub(high * CLOCK_LOW);
        let end = (to - high * CLOCK_LOW).min(CLOCK_LOW);
        let upper: AB::Expr = row[CLOCK + CLOCK_LOW + high].into();
        if start == 0 && end == CLOCK_LOW {
            result += upper;
        } else {
            let lower: AB::Expr = row[CLOCK + start..CLOCK + end]
                .iter()
                .copied()
                .map(Into::into)
                .sum();
            result += upper * lower;
        }
    }
    result
}

/// One ungated byte expression for a fixed actual physical row. The caller must
/// apply its original selector exactly once. Ranks are recomputed per epoch,
/// including rank changes inside one six-row sponge interval.
pub fn byte_at<AB: AirBuilder<F = BabyBear>>(
    row: &[AB::Var],
    pc: usize,
    bank: Bank,
    index: usize,
) -> AB::Expr {
    let (port, offset) = port_at(pc, bank, index);
    port_byte::<AB>(row, port, offset)
}

/// Fixed program addresses used by the actual AIR accessor, never witness data.
pub fn word_ids_at(pc: usize) -> &'static [u16] {
    assert!(pc < HEIGHT, "fixed physical row is out of bounds");
    &epoch_at(routes(), pc).words
}

/// Fixed port/offset lookup. Returning a route is not witness verification.
pub fn port_at(pc: usize, bank: Bank, index: usize) -> (usize, usize) {
    assert!(pc < HEIGHT, "fixed physical row is out of bounds");
    let word = bank.word(index);
    let epoch = epoch_at(routes(), pc);
    let port = epoch
        .words
        .binary_search(&word)
        .expect("fixed consumer reads a word absent from its physical row");
    (port, index % 3)
}

/// Already selected across ALL physical rows. Intended for the original all-row
/// cut, fixed-note and context equations; the caller must add no outer selector.
/// Absence on even one row is a fixed-program error, never a zero fallback.
pub fn byte_all<AB: AirBuilder<F = BabyBear>>(
    row: &[AB::Var],
    bank: Bank,
    index: usize,
) -> AB::Expr {
    let word = bank.word(index);
    let data = routes();
    let position = data
        .all_row
        .binary_search_by_key(&word, |entry| entry.word)
        .expect("fixed all-row consumer word is missing on some row");
    data.all_row[position]
        .runs
        .iter()
        .map(|run| {
            selector::<AB>(row, usize::from(run.from), usize::from(run.to))
                * port_byte::<AB>(row, usize::from(run.port), index % 3)
        })
        .sum()
}

pub fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let row = main.current_slice();
    let next = main.next_slice();
    for column in KEY..SOURCE_PORTS {
        builder
            .when_transition()
            .assert_eq(next[column], row[column]);
    }
    for bit in &row[SOURCE_PORTS..MESSAGE] {
        builder.assert_bool(*bit);
    }
    let data = routes();
    let selectors: Vec<AB::Expr> = data
        .epochs
        .iter()
        .map(|epoch| selector::<AB>(row, usize::from(epoch.from), usize::from(epoch.to)))
        .collect();
    let signature_tail = Bank::Signature.word(Bank::Signature.len() - 1);
    let note_tail = Bank::Note.word(Bank::Note.len() - 1);
    for port in 0..PORTS {
        let selected: AB::Expr = data
            .epochs
            .iter()
            .zip(&selectors)
            .filter_map(|(epoch, select)| {
                epoch
                    .words
                    .get(port)
                    .map(|word| select.clone() * row[KEY + usize::from(*word)])
            })
            .sum();
        let packed = port_byte::<AB>(row, port, 0)
            + port_byte::<AB>(row, port, 1) * BabyBear::from_u32(256)
            + port_byte::<AB>(row, port, 2) * BabyBear::from_u32(65536);
        // An unused port selects zero. Its 24 Boolean bits then all vanish,
        // since their canonical integer sum is below 2^24 < the base-field prime.
        builder.assert_eq(packed, selected);
        let is_tail = |epoch: &Epoch| {
            epoch
                .words
                .get(port)
                .is_some_and(|word| *word == signature_tail || *word == note_tail)
        };
        if data.epochs.iter().any(is_tail) {
            let enabled: AB::Expr = data
                .epochs
                .iter()
                .zip(&selectors)
                .filter(|(epoch, _)| is_tail(epoch))
                .map(|(_, select)| select.clone())
                .sum();
            for offset in 1..3 {
                builder
                    .when(enabled.clone())
                    .assert_zero(port_byte::<AB>(row, port, offset));
            }
        }
    }
}

/// Fill only the held words and the routed Boolean ports from the original
/// typed private byte arrays. No derived operand or acceptance result is cached.
pub fn fill(row: &mut [BabyBear], pc: usize, witness: &Witness) {
    assert!(pc < HEIGHT && row.len() >= MESSAGE);
    for (bank, bytes) in [
        (Bank::Key, witness.key.as_slice()),
        (Bank::Signature, witness.signature.as_slice()),
        (Bank::Note, witness.note.as_slice()),
    ] {
        assert_eq!(bytes.len(), bank.len());
        for word in 0..bank.len().div_ceil(3) {
            let value: u32 = (0..3)
                .map(|offset| {
                    u32::from(bytes.get(3 * word + offset).copied().unwrap_or(0)) << (8 * offset)
                })
                .sum();
            row[KEY + bank.first_word() + word] = BabyBear::from_u32(value);
        }
    }
    row[SOURCE_PORTS..MESSAGE].fill(BabyBear::ZERO);
    for (port, &word) in epoch_at(routes(), pc).words.iter().enumerate() {
        let bank = if usize::from(word) < Bank::Signature.first_word() {
            Bank::Key
        } else if usize::from(word) < Bank::Note.first_word() {
            Bank::Signature
        } else {
            Bank::Note
        };
        let bytes: &[u8] = match bank {
            Bank::Key => &witness.key,
            Bank::Signature => &witness.signature,
            Bank::Note => &witness.note,
        };
        let first = 3 * (usize::from(word) - bank.first_word());
        for bit in 0..BITS_PER_PORT {
            let value = bytes.get(first + bit / 8).copied().unwrap_or(0);
            row[SOURCE_PORTS + BITS_PER_PORT * port + bit] =
                BabyBear::from_bool((value >> (bit % 8)) & 1 != 0);
        }
    }
}
