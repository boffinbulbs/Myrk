//! Independent locally exact products with disconnected control and register flow.

use super::*;
use air::Kind;
use p3_field::PrimeField32;

#[derive(Clone, Copy, Debug)]
pub(crate) enum Fault {
    Honest,
    WrongTwiddle(usize),
    DetachedY(usize),
    DroppedWrite(usize),
    NormFactor(usize),
    NormDroppedWrite(usize),
    SkippedInstruction,
    OutputDetach(usize),
    OutputBankReset,
    PaddingBankReset,
    InitialNonzero,
    DormantForwardPc,
    NonbooleanWrite(usize),
    NoncanonicalFinalWrite(usize),
}

fn power(mut x: u32, mut n: u32) -> u32 {
    let q = u64::from(mul::MODULUS);
    let mut out = 1u64;
    while n > 0 {
        if n & 1 != 0 {
            out = out * u64::from(x) % q;
        }
        x = (u64::from(x) * u64::from(x) % q) as u32;
        n >>= 1;
    }
    out as u32
}
fn input_for_noncanonical_write(slot: usize) -> [u32; 256] {
    if slot % 2 == 1 {
        return [0; 256];
    }
    let q = u64::from(mul::MODULUS);
    let mut bank = [0u32; 256];
    let (left, right, twiddle) = ntt::butterflies(Mode::Forward, 7)[120 + slot / 2];
    bank[left] = mul::MODULUS - 1;
    bank[right] = power(twiddle, mul::MODULUS - 2);
    let inv2 = u64::from(mul::MODULUS.div_ceil(2));
    for layer in (0..7).rev() {
        for (left, right, twiddle) in ntt::butterflies(Mode::Forward, layer) {
            let (u, v) = (u64::from(bank[left]), u64::from(bank[right]));
            bank[left] = ((u + v) * inv2 % q) as u32;
            bank[right] =
                ((u + q - v) * inv2 % q * u64::from(power(twiddle, mul::MODULUS - 2)) % q) as u32;
        }
    }
    bank
}
pub(crate) fn attack(mode: Mode, fault: Fault) -> (RowMajorMatrix<BabyBear>, Statement) {
    let input = if let Fault::NoncanonicalFinalWrite(slot) = fault {
        input_for_noncanonical_write(slot)
    } else {
        core::array::from_fn(|i| ((i as u64 * 431_271 + 92_873) % u64::from(mul::MODULUS)) as u32)
    };
    let instructions = air::program(mode);
    let out_start = if mode == Mode::Forward { 160 } else { 192 };
    let mut bank = [0u32; 256];
    let mut output = [0u32; 256];
    let mut values = vec![BabyBear::ZERO; air::WIDTH * air::HEIGHT];
    for row_index in 0..air::HEIGHT {
        if matches!(fault, Fault::InitialNonzero) && row_index == 0 {
            bank[255] = 1;
        }
        if matches!(fault, Fault::OutputBankReset) && row_index == out_start + 1 {
            bank[0] = (bank[0] + 1) % mul::MODULUS;
        }
        if matches!(fault, Fault::PaddingBankReset) && row_index == instructions.len() {
            bank[0] = (bank[0] + 1) % mul::MODULUS;
        }
        let pc = if matches!(fault, Fault::SkippedInstruction) && row_index == 47 {
            48
        } else if matches!(fault, Fault::DormantForwardPc) && row_index == 192 {
            192
        } else if row_index < instructions.len() {
            row_index
        } else {
            air::PAD
        };
        let row = &mut values[row_index * air::WIDTH..(row_index + 1) * air::WIDTH];
        row[pc] = BabyBear::ONE;
        for i in 0..256 {
            row[air::BANK + i] = BabyBear::from_u32(bank[i]);
        }
        let mut products = [ntt::product(0, 0); 8];
        let mut writes = [0u32; 16];
        let mut flags = [[false; 2]; 8];
        if let Some(instruction) = instructions.get(pc) {
            match instruction.kind {
                Kind::Initialize(group) => {
                    writes[..8].copy_from_slice(&input[group * 8..group * 8 + 8])
                }
                Kind::Output(group) => {
                    writes[..8].copy_from_slice(&bank[group * 8..group * 8 + 8]);
                    if let Fault::OutputDetach(slot) = fault
                        && group == 0
                    {
                        writes[slot] = (writes[slot] + 1) % mul::MODULUS;
                    }
                    output[group * 8..group * 8 + 8].copy_from_slice(&writes[..8]);
                }
                Kind::Normalize(group) => {
                    for slot in 0..8 {
                        let factor =
                            if matches!(fault,Fault::NormFactor(s) if s==slot) && group == 0 {
                                1
                            } else {
                                ntt::INVERSE_256
                            };
                        products[slot] = ntt::product(factor, bank[group * 8 + slot]);
                        writes[slot] = products[slot].values[3];
                    }
                }
                Kind::Butterfly { .. } => {
                    for slot in 0..8 {
                        let (left, right, mut twiddle) = instruction.butterflies[slot];
                        let (a, b) = (bank[left], bank[right]);
                        if matches!(fault,Fault::WrongTwiddle(s) if s==slot) && row_index == 32 {
                            twiddle = (twiddle + 1) % mul::MODULUS;
                        }
                        match mode {
                            Mode::Forward => {
                                let y = if matches!(fault,Fault::DetachedY(s) if s==slot)
                                    && row_index == 32
                                {
                                    (b + 1) % mul::MODULUS
                                } else {
                                    b
                                };
                                products[slot] = ntt::product(twiddle, y);
                                let t = products[slot].values[3];
                                let mut add = a + t >= mul::MODULUS;
                                let mut borrow = a < t;
                                if let Fault::NoncanonicalFinalWrite(write_slot) = fault
                                    && row_index == 159
                                    && slot == write_slot / 2
                                {
                                    if write_slot % 2 == 0 {
                                        assert_eq!(a + t, mul::MODULUS);
                                        add = false;
                                    } else {
                                        assert_eq!((a, t), (0, 0));
                                        borrow = true;
                                    }
                                }
                                flags[slot] = [add, borrow];
                                writes[slot * 2] = a + t - if add { mul::MODULUS } else { 0 };
                                writes[slot * 2 + 1] = (u64::from(a)
                                    + if borrow { u64::from(mul::MODULUS) } else { 0 }
                                    - u64::from(t))
                                    as u32;
                            }
                            Mode::Inverse => {
                                let difference = ((u64::from(a) + u64::from(mul::MODULUS)
                                    - u64::from(b))
                                    % u64::from(mul::MODULUS))
                                    as u32;
                                let y = if matches!(fault,Fault::DetachedY(s) if s==slot)
                                    && row_index == 32
                                {
                                    (difference + 1) % mul::MODULUS
                                } else {
                                    difference
                                };
                                products[slot] = ntt::product(twiddle, y);
                                flags[slot] = [a + b >= mul::MODULUS, a < b];
                                writes[slot * 2] = (a + b) % mul::MODULUS;
                                writes[slot * 2 + 1] = products[slot].values[3];
                            }
                        }
                    }
                }
            }
            for (slot, destination) in instruction.destinations.iter().enumerate() {
                if let Some(index) = destination {
                    let drop = matches!(fault,Fault::DroppedWrite(s) if s==slot) && row_index == 32
                        || matches!(fault,Fault::NormDroppedWrite(s) if s==slot)
                            && row_index == 160;
                    if !drop {
                        bank[*index] = writes[slot];
                    }
                }
            }
        }
        for slot in 0..8 {
            air::encode_product(
                &products[slot],
                &mut row
                    [air::PRODUCTS + slot * mul::WIDTH..air::PRODUCTS + (slot + 1) * mul::WIDTH],
            );
            row[air::FLAGS + slot * 2] = BabyBear::from_bool(flags[slot][0]);
            row[air::FLAGS + slot * 2 + 1] = BabyBear::from_bool(flags[slot][1]);
        }
        for slot in 0..16 {
            air::encode_write(
                writes[slot],
                &mut row[air::WRITES + slot * 46..air::WRITES + (slot + 1) * 46],
            );
        }
        if let Fault::NonbooleanWrite(slot) = fault
            && row_index == 32
        {
            row[air::WRITES + slot * 46] += BabyBear::from_u8(2);
            row[air::WRITES + slot * 46 + 1] -= BabyBear::ONE;
        }
    }
    (
        RowMajorMatrix::new(values, air::WIDTH),
        Statement {
            mode,
            input,
            output,
            context: [0x39; 64],
        },
    )
}
fn packed(bits: &[BabyBear]) -> u32 {
    bits.iter()
        .rev()
        .fold(0, |v, b| v * 2 + b.as_canonical_u32())
}
fn assert_integer_products(trace: &RowMajorMatrix<BabyBear>) {
    for row in trace.values.chunks_exact(air::WIDTH) {
        for slot in 0..8 {
            let bits =
                &row[air::PRODUCTS + slot * mul::WIDTH..air::PRODUCTS + (slot + 1) * mul::WIDTH];
            let v: [u32; 4] = core::array::from_fn(|i| packed(&bits[i * 23..(i + 1) * 23]));
            assert!(v.iter().all(|x| *x < mul::MODULUS));
            assert_eq!(
                u64::from(v[0]) * u64::from(v[1]),
                u64::from(mul::MODULUS) * u64::from(v[2]) + u64::from(v[3])
            );
        }
    }
}
fn actual_air_accepts(trace: &RowMajorMatrix<BabyBear>, statement: &Statement) -> bool {
    check_all_constraints(
        &air::NttAir::new(statement),
        trace,
        &air::public_values(statement),
        Some(1),
    )
    .is_ok()
}

#[test]
fn all_eight_product_slots_and_sixteen_write_routes_reject_detached_state() {
    let mut count = 0;
    for mode in [Mode::Forward, Mode::Inverse] {
        let (trace, s) = attack(mode, Fault::Honest);
        assert_integer_products(&trace);
        assert!(actual_air_accepts(&trace, &s));
        for slot in 0..8 {
            for fault in [
                Fault::WrongTwiddle(slot),
                Fault::DetachedY(slot),
                Fault::OutputDetach(slot),
            ] {
                let (trace, s) = attack(mode, fault);
                assert_integer_products(&trace);
                assert!(!actual_air_accepts(&trace, &s), "{mode:?} {fault:?}");
                count += 1;
            }
        }
        for slot in 0..16 {
            for fault in [Fault::DroppedWrite(slot), Fault::NonbooleanWrite(slot)] {
                let (trace, s) = attack(mode, fault);
                assert_integer_products(&trace);
                assert!(!actual_air_accepts(&trace, &s), "{mode:?} {fault:?}");
                count += 1;
            }
        }
    }
    assert_eq!(count, 112);
}

#[test]
fn valid_products_and_matching_outputs_do_not_override_control_or_hold_rules() {
    let mut count = 0;
    for mode in [Mode::Forward, Mode::Inverse] {
        for fault in [
            Fault::SkippedInstruction,
            Fault::OutputBankReset,
            Fault::PaddingBankReset,
            Fault::InitialNonzero,
        ] {
            let (trace, s) = attack(mode, fault);
            assert_integer_products(&trace);
            assert!(!actual_air_accepts(&trace, &s), "{mode:?} {fault:?}");
            count += 1;
        }
    }
    let (trace, s) = attack(Mode::Forward, Fault::DormantForwardPc);
    assert_integer_products(&trace);
    assert!(!actual_air_accepts(&trace, &s));
    count += 1;
    for slot in 0..8 {
        for fault in [Fault::NormFactor(slot), Fault::NormDroppedWrite(slot)] {
            let (trace, s) = attack(Mode::Inverse, fault);
            assert_integer_products(&trace);
            assert!(!actual_air_accepts(&trace, &s), "{fault:?}");
            count += 1;
        }
    }
    assert_eq!(count, 25);
}

#[test]
fn all_sixteen_final_write_windows_enforce_canonicality_inside_the_air() {
    for slot in 0..16 {
        let (trace, s) = attack(Mode::Forward, Fault::NoncanonicalFinalWrite(slot));
        assert_integer_products(&trace);
        assert!(s.output.contains(&mul::MODULUS));
        assert_eq!(s.validate(), Err(Error::InvalidStatement));
        assert!(!actual_air_accepts(&trace, &s), "slot {slot}");
    }
    for mode in [Mode::Forward, Mode::Inverse] {
        let (trace, s) = attack(mode, Fault::Honest);
        for output in [false, true] {
            for index in [0, 7, 127, 255] {
                let mut alias = s;
                if output {
                    alias.output[index] += 2_013_265_921;
                } else {
                    alias.input[index] += 2_013_265_921;
                }
                assert_eq!(alias.validate(), Err(Error::InvalidStatement));
                assert!(!actual_air_accepts(&trace, &alias));
            }
        }
    }
}
