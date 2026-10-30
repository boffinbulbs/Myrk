use crate::{
    authorization::PURE_CONTEXT,
    layout::*,
    packing,
    program::{self, Kind},
};
use p3_air::{AirBuilder, WindowAccess};
use p3_baby_bear::BabyBear;
use p3_field::PrimeCharacteristicRing;

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
    crate::sponge::eval(builder);
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
                + program::at::<AB>(local, 0)
                    * (crate::packed::byte_at::<AB>(local, 0, crate::packed::Bank::Key, byte)
                        - local[RHO + byte]),
        );
        builder.assert_eq(
            crate::packed::byte_all::<AB>(local, crate::packed::Bank::Note, 49 + byte),
            public[52 + byte],
        );
    }
    for byte in 0..64 {
        builder.when(program::at::<AB>(local, 234)).assert_eq(
            crate::packed::byte_at::<AB>(local, 234, crate::packed::Bank::Note, 141 + byte),
            local[OWNER + byte],
        );
    }
    for index in 0..418 {
        if let Some(v) = note_fixed(index) {
            builder.assert_eq(
                crate::packed::byte_all::<AB>(local, crate::packed::Bank::Note, index),
                BabyBear::from_u8(v),
            );
        }
    }
    for byte in 0..10 {
        let expected: AB::Expr = (0..256)
            .map(|r| {
                program::at::<AB>(local, r)
                    * crate::packed::byte_at::<AB>(
                        local,
                        r,
                        crate::packed::Bank::Key,
                        32 + 10 * r + byte,
                    )
            })
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
