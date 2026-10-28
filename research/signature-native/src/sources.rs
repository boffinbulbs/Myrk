use crate::{
    authorization::PURE_CONTEXT,
    layout::*,
    packing,
    program::{self, Kind},
};
use core::borrow::Borrow;
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;
use p3_keccak_air::{KeccakCols, NUM_KECCAK_COLS};

#[derive(Clone, Copy)]
pub enum Source {
    Fixed(u8),
    Key(usize),
    Signature(usize),
    Note(usize),
    Tr(usize),
    Public(usize),
}
pub fn message_source(permutation: usize, byte: usize) -> Source {
    assert!(byte < 168);
    let Some(hash) = program::hash(permutation) else {
        return Source::Fixed(0);
    };
    if byte >= hash.rate {
        return Source::Fixed(0);
    }
    let offset = hash.block * hash.rate + byte;
    match hash.kind {
        Kind::Challenge => {
            if hash.block == 1 {
                return Source::Fixed(0);
            }
            match byte {
                0..=63 => Source::Signature(byte),
                64 => Source::Fixed(31),
                135 => Source::Fixed(128),
                _ => Source::Fixed(0),
            }
        }
        Kind::Owner | Kind::Tr => {
            if offset < 2592 {
                return Source::Key(offset);
            }
            let suffix = if hash.kind == Kind::Owner { 6 } else { 31 };
            Source::Fixed(if offset == 2592 {
                suffix
            } else if byte == hash.rate - 1 {
                128
            } else {
                0
            })
        }
        Kind::Mu => match offset {
            0..=63 => Source::Tr(offset),
            64 => Source::Fixed(0),
            65 => Source::Fixed(41),
            66..=106 => Source::Fixed(PURE_CONTEXT[offset - 66]),
            107..=302 => Source::Public(offset - 107),
            303 => Source::Fixed(31),
            407 => Source::Fixed(128),
            _ => Source::Fixed(0),
        },
        Kind::Note => {
            const DOMAIN: &[u8; 38] = b"thorum.relation-lab.note-commitment.v2";
            match offset {
                0..=3 => Source::Fixed((38u32.to_be_bytes())[offset]),
                4..=41 => Source::Fixed(DOMAIN[offset - 4]),
                42..=45 => Source::Fixed((418u32.to_be_bytes())[offset - 42]),
                46..=463 => Source::Note(offset - 46),
                464 => Source::Fixed(6),
                503 => Source::Fixed(128),
                _ => Source::Fixed(0),
            }
        }
    }
}

pub(crate) fn note_fixed(index: usize) -> Option<u8> {
    const FIELDS: [(usize, u32); 12] = [
        (0, 35),
        (39, 2),
        (45, 32),
        (81, 4),
        (89, 32),
        (125, 8),
        (137, 64),
        (205, 64),
        (273, 64),
        (341, 32),
        (377, 32),
        (413, 1),
    ];
    for (start, length) in FIELDS {
        if (start..start + 4).contains(&index) {
            return Some(length.to_be_bytes()[index - start]);
        }
    }
    match index {
        4..=38 => Some(b"thorum.relation-lab.note-opening.v2"[index - 4]),
        43 => Some(0),
        44 => Some(2),
        417 => Some(0),
        _ => None,
    }
}

pub(crate) fn eval<AB: AirBuilder<F = BabyBear>>(builder: &mut AB) {
    let main = builder.main();
    let local = main.current_slice();
    let next = main.next_slice();
    let public = builder.public_values().to_vec();
    let first: &KeccakCols<AB::Var> = local[..NUM_KECCAK_COLS].borrow();
    let last: &KeccakCols<AB::Var> = local[3 * NUM_KECCAK_COLS..4 * NUM_KECCAK_COLS].borrow();
    let next_first: &KeccakCols<AB::Var> = next[..NUM_KECCAK_COLS].borrow();
    for bit in &local[MESSAGE..RHO] {
        builder.assert_bool(*bit)
    }
    let sha3_phase: AB::Expr = (0..69)
        .filter(|p| matches!(program::hash(*p).unwrap().kind, Kind::Owner | Kind::Note))
        .map(|p| program::hash_selector::<AB>(local, p))
        .sum();
    let shake_phase: AB::Expr = (0..69)
        .filter(|p| !matches!(program::hash(*p).unwrap().kind, Kind::Owner | Kind::Note))
        .map(|p| program::hash_selector::<AB>(local, p))
        .sum();
    for byte in 0..168 {
        let expected: AB::Expr = (0..69)
            .map(|p| {
                let value: AB::Expr = match message_source(p, byte) {
                    Source::Fixed(v) => BabyBear::from_u8(v).into(),
                    Source::Key(i) => local[KEY + i].into(),
                    Source::Signature(i) => local[SIGNATURE + i].into(),
                    Source::Note(i) => local[NOTE + i].into(),
                    Source::Tr(i) => local[TR + i].into(),
                    Source::Public(i) => public[i].into(),
                };
                program::hash_selector::<AB>(local, p) * value
            })
            .sum();
        builder.assert_eq(
            packing::packed::<AB>(&local[MESSAGE + byte * 8..MESSAGE + (byte + 1) * 8]),
            expected,
        );
    }
    for limb in 0..84 {
        let value = packing::packed::<AB>(&local[OUTPUT + limb * 16..OUTPUT + (limb + 1) * 16]);
        let enabled = if limb < 36 {
            sha3_phase.clone() + shake_phase.clone()
        } else if limb < 68 {
            shake_phase.clone()
        } else {
            AB::Expr::ZERO
        };
        builder.when(enabled.clone()).assert_eq(
            value.clone(),
            last.a_prime_prime_prime(limb / 20, (limb / 4) % 5, limb % 4),
        );
        builder.when(AB::Expr::ONE - enabled).assert_zero(value);
    }
    let fresh: AB::Expr = (0..HEIGHT)
        .filter(|r| r % 6 == 0 && program::hash(r / 6).is_none_or(|h| h.block == 0))
        .map(|r| program::at::<AB>(local, r))
        .sum();
    let continue72: AB::Expr = (0..69)
        .filter(|p| {
            let h = program::hash(*p).unwrap();
            h.rate == 72 && h.block + 1 < h.blocks
        })
        .map(|p| program::at::<AB>(local, p * 6 + 5))
        .sum();
    let continue136: AB::Expr = (0..69)
        .filter(|p| {
            let h = program::hash(*p).unwrap();
            h.rate == 136 && h.block + 1 < h.blocks
        })
        .map(|p| program::at::<AB>(local, p * 6 + 5))
        .sum();
    for r in (0..HEIGHT).step_by(6) {
        builder
            .when(program::at::<AB>(local, r))
            .assert_one(first.step_flags[0]);
    }
    for limb in 0..100 {
        let (y, x, l) = (limb / 20, (limb / 4) % 5, limb % 4);
        let preimage = if limb < 84 {
            packing::packed::<AB>(&local[MESSAGE + limb * 16..MESSAGE + (limb + 1) * 16])
        } else {
            AB::Expr::ZERO
        };
        builder
            .when(fresh.clone())
            .assert_eq(first.preimage[y][x][l], preimage);
        let current: AB::Expr = last.a_prime_prime_prime(y, x, l).into();
        let xor = if limb < 68 {
            (0..16).rev().fold(AB::Expr::ZERO, |a, b| {
                let x: AB::Expr = local[OUTPUT + limb * 16 + b].into();
                let y: AB::Expr = next[MESSAGE + limb * 16 + b].into();
                a.double() + x.xor(&y)
            })
        } else {
            current.clone()
        };
        let sha3_next = if limb < 36 {
            xor.clone()
        } else {
            current.clone()
        };
        builder
            .when_transition()
            .when(continue72.clone())
            .assert_eq(next_first.preimage[y][x][l], sha3_next);
        builder
            .when_transition()
            .when(continue136.clone())
            .assert_eq(next_first.preimage[y][x][l], xor);
    }
    for (bank, end) in [(OWNER, 233), (TR, 353), (MU, 371), (NOTE_COMMITMENT, 413)] {
        let write = program::at::<AB>(local, end);
        for byte in 0..64 {
            let producer =
                packing::packed::<AB>(&local[OUTPUT + byte * 8..OUTPUT + (byte + 1) * 8]);
            builder.when_first_row().assert_zero(local[bank + byte]);
            builder.when_transition().assert_eq(
                next[bank + byte],
                local[bank + byte].into() + write.clone() * (producer - local[bank + byte]),
            );
        }
    }
    for byte in 0..272 {
        let write = program::at::<AB>(local, if byte < 136 { 5 } else { 11 });
        let producer =
            packing::packed::<AB>(&local[OUTPUT + (byte % 136) * 8..OUTPUT + (byte % 136 + 1) * 8]);
        builder
            .when_first_row()
            .assert_zero(local[CHALLENGE_XOF + byte]);
        builder.when_transition().assert_eq(
            next[CHALLENGE_XOF + byte],
            local[CHALLENGE_XOF + byte].into() + write * (producer - local[CHALLENGE_XOF + byte]),
        );
    }
    for byte in 0..32 {
        builder.when_first_row().assert_zero(local[RHO + byte]);
        builder.when_transition().assert_eq(
            next[RHO + byte],
            local[RHO + byte].into()
                + program::at::<AB>(local, 0) * (local[KEY + byte] - local[RHO + byte]),
        );
        builder.assert_eq(local[NOTE + 49 + byte], public[52 + byte]);
    }
    for byte in 0..64 {
        builder
            .when(program::at::<AB>(local, 234))
            .assert_eq(local[NOTE + 141 + byte], local[OWNER + byte]);
    }
    for index in 0..418 {
        if let Some(v) = note_fixed(index) {
            builder.assert_eq(local[NOTE + index], BabyBear::from_u8(v));
        }
    }
    for byte in 0..10 {
        let expected: AB::Expr = (0..256)
            .map(|r| program::at::<AB>(local, r) * local[KEY + 32 + 10 * r + byte])
            .sum();
        builder.assert_eq(
            packing::packed::<AB>(&local[T1_MESSAGE + byte * 8..T1_MESSAGE + (byte + 1) * 8]),
            expected,
        );
    }
    let a = packing::decode_t1(builder, &local[T1_MESSAGE..T1_MESSAGE + 40]);
    let b = packing::decode_t1(builder, &local[T1_MESSAGE + 40..T1_MESSAGE + 80]);
    let values = [
        a[0].clone(),
        a[1].clone(),
        a[2].clone(),
        a[3].clone(),
        b[0].clone(),
        b[1].clone(),
        b[2].clone(),
        b[3].clone(),
    ];
    for i in 0..2048 {
        builder.when_first_row().assert_zero(local[T1 + i]);
        builder.when_transition().assert_eq(
            next[T1 + i],
            local[T1 + i].into()
                + program::at::<AB>(local, i / 8) * (values[i % 8].clone() - local[T1 + i]),
        );
    }
}
