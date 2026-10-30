//! Selected logical addresses, independent of the mechanism's physical clock.

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
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct Word {
    pub bank: Bank,
    pub index: usize,
}

#[derive(Clone, Copy, Debug)]
pub struct Window {
    pub bank: Bank,
    pub first: usize,
    pub len: usize,
}

pub const WINDOWS: [Window; 8] = [
    Window {
        bank: Bank::Key,
        first: 32,
        len: 10,
    },
    Window {
        bank: Bank::Key,
        first: 0,
        len: 136,
    },
    Window {
        bank: Bank::Signature,
        first: 0,
        len: 10,
    },
    Window {
        bank: Bank::Note,
        first: 49,
        len: 10,
    },
    Window {
        bank: Bank::Note,
        first: 141,
        len: 10,
    },
    Window {
        bank: Bank::Signature,
        first: 4626,
        len: 1,
    },
    Window {
        bank: Bank::Note,
        first: 417,
        len: 1,
    },
    Window {
        bank: Bank::Signature,
        first: 0,
        len: 10,
    },
];

pub const WORD_COUNT: usize = 60;
pub const fn word(slot: usize) -> Word {
    assert!(slot < WORD_COUNT);
    match slot {
        0..=45 => Word {
            bank: Bank::Key,
            index: slot,
        },
        46..=49 => Word {
            bank: Bank::Signature,
            index: slot - 46,
        },
        50 => Word {
            bank: Bank::Signature,
            index: 1542,
        },
        51..=54 => Word {
            bank: Bank::Note,
            index: slot - 51 + 16,
        },
        55..=58 => Word {
            bank: Bank::Note,
            index: slot - 55 + 47,
        },
        _ => Word {
            bank: Bank::Note,
            index: 139,
        },
    }
}

pub fn port(window: Window, port: usize) -> Option<usize> {
    assert!(window.first + window.len <= window.bank.len());
    let first = window.first / 3;
    let end = (window.first + window.len).div_ceil(3);
    (first + port < end).then(|| {
        let requested = Word {
            bank: window.bank,
            index: first + port,
        };
        (0..WORD_COUNT)
            .find(|&slot| word(slot) == requested)
            .expect("fixed route word")
    })
}

pub const fn consumer(window: Window, byte: usize) -> Option<(usize, usize)> {
    if byte >= window.len {
        None
    } else {
        let index = window.first % 3 + byte;
        Some((index / 3, index % 3))
    }
}
