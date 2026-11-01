use super::*;

type SavedCase = (
    &'static str,
    &'static str,
    u64,
    i128,
    u64,
    &'static str,
    &'static str,
);
include!("saved_cases.rs");

fn target(hex: &str) -> UnverifiedTarget256 {
    assert_eq!(hex.len(), 64);
    let mut bytes = [0; 32];
    for (i, byte) in bytes.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&hex[62 - 2 * i..64 - 2 * i], 16).unwrap();
    }
    UnverifiedTarget256::from_le_bytes(bytes).unwrap()
}

fn small(value: u64) -> UnverifiedTarget256 {
    UnverifiedTarget256([value, 0, 0, 0])
}

fn saved_targets() -> (usize, usize) {
    assert_eq!(SAVED.len(), 66);
    let mut context_count = 0;
    for &(label, initial, spacing, dt, dh, limit, expected) in SAVED {
        let (initial, limit, expected) = (target(initial), target(limit), target(expected));
        assert_eq!(
            asert(initial, limit, dt, dh, spacing).unwrap(),
            expected,
            "{label}"
        );
        assert_eq!(
            UnverifiedTarget256::from_le_bytes(expected.to_le_bytes()).unwrap(),
            expected
        );
        if spacing == 60 && dh < u64::MAX - 1 {
            let (genesis, previous) = if dt < 0 {
                ((-dt) as u64, 0)
            } else {
                (0, dt as u64)
            };
            let context = UnverifiedWorkContext::new(initial, limit, genesis).unwrap();
            assert_eq!(
                context.expected_target(dh + 1, previous).unwrap(),
                expected,
                "{label}"
            );
            context_count += 1;
        }
    }
    assert_eq!(context_count, 31);
    (SAVED.len(), context_count)
}

fn public_context_controls() {
    let context = UnverifiedWorkContext::new(small(100), small(1000), 10000).unwrap();
    assert_eq!(context.expected_target(0, 10000).unwrap(), small(100));
    assert_eq!(context.expected_target(1, 10060).unwrap(), small(100));
    assert_eq!(context.expected_target(2, 10120).unwrap(), small(100));
    assert_eq!(context.expected_target(1, 182860).unwrap(), small(200));
    assert_eq!(context.expected_target(u64::MAX - 1, 0).unwrap(), small(1));
    assert_eq!(
        context.expected_target(u64::MAX, 0),
        Err(ArithmeticError::HeightExhausted)
    );
    assert_eq!(
        context.expected_target(0, 10001),
        Err(ArithmeticError::GenesisTimeMismatch)
    );
    assert_eq!(
        UnverifiedTarget256::from_le_bytes([0; 32]),
        Err(ArithmeticError::ZeroTarget)
    );
    assert_eq!(
        UnverifiedWorkContext::new(small(2), small(1), 0).unwrap_err(),
        ArithmeticError::InitialAboveLimit
    );
    assert_eq!(
        asert(small(2), small(1), 60, 0, 60),
        Err(ArithmeticError::InitialAboveLimit)
    );
    for dt in [
        i128::MIN,
        -i128::from(u64::MAX) - 1,
        i128::from(u64::MAX) + 1,
        i128::MAX,
    ] {
        assert_eq!(
            asert(small(1), small(1), dt, 0, 60),
            Err(ArithmeticError::TimeDifferenceOutOfRange)
        );
    }
    for spacing in [0, 1, 59, 61, u64::MAX] {
        assert_eq!(
            asert(small(1), small(1), 60, 0, spacing),
            Err(ArithmeticError::UnsupportedSpacing)
        );
    }
    let maximum = UnverifiedTarget256([u64::MAX; 4]);
    let mut expected = [255; 32];
    expected[29] = 127; // MAX256 - 2^239, exponent=-1, fraction=65535.
    assert_eq!(
        asert(maximum, maximum, 57, 0, 60).unwrap().to_le_bytes(),
        expected
    );
    assert_eq!(multiply_target(maximum, 131071).bits(), 273);
    let context = UnverifiedWorkContext::new(maximum, maximum, u64::MAX).unwrap();
    assert_eq!(context.expected_target(1, 0).unwrap(), small(1));
    let source = std::array::from_fn(|i| i as u8);
    assert_eq!(
        UnverifiedTarget256::from_le_bytes(source)
            .unwrap()
            .to_le_bytes(),
        source
    );
    assert_eq!(small(256).to_le_bytes()[..3], [0, 1, 0]);
}

fn limb_controls() {
    let maximum = Word320([u64::MAX; 5]);
    assert_eq!(maximum.bits(), 320);
    assert_eq!(Word320::ZERO.bits(), 0);
    assert_eq!(maximum.add(Word320::ONE), Err(ArithmeticError::Overflow));
    assert_eq!(maximum, Word320([u64::MAX; 5]));
    assert_eq!(
        Word320::ZERO.sub(Word320::ONE),
        Err(ArithmeticError::Underflow)
    );
    for boundary in 1..5 {
        let mut before = [0; 5];
        before[..boundary].fill(u64::MAX);
        let mut after = [0; 5];
        after[boundary] = 1;
        let result = Word320(before).add(Word320::ONE).unwrap();
        assert_eq!(result, Word320(after));
        assert_eq!(result.sub(Word320::ONE).unwrap(), Word320(before));
    }
    assert_eq!(
        Word320([u64::MAX, 0, 0, 0, 0]).shl_one().unwrap(),
        Word320([u64::MAX - 1, 1, 0, 0, 0])
    );
    assert_eq!(maximum.shl_one(), Err(ArithmeticError::Overflow));
    for shift in 0..=321 {
        let got = maximum.shr(shift);
        for bit in 0..320 {
            let set = (got.0[bit / 64] >> (bit % 64)) & 1;
            assert_eq!(set, u64::from(bit + shift < 320));
        }
    }
    // Independent base-2^64 multiplication identity (B^4-1)*(B-1).
    assert_eq!(
        multiply_target(UnverifiedTarget256([u64::MAX; 4]), u64::MAX),
        Word320([1, u64::MAX, u64::MAX, u64::MAX, u64::MAX - 1])
    );
    assert_eq!(
        Word320([u64::MAX, 0, 0, 0, 0]).compare(Word320([0, 1, 0, 0, 0])),
        Ordering::Less
    );
}

fn work_controls() {
    let maximum = UnverifiedTarget256([u64::MAX; 4]);
    let independent = [
        (small(1), [0, 0, 0, 1 << 63, 0]),
        (small(3), [0, 0, 0, 1 << 62, 0]),
        (
            UnverifiedTarget256([u64::MAX, u64::MAX, u64::MAX, u64::MAX >> 1]),
            [2, 0, 0, 0, 0],
        ),
        (maximum, [1, 0, 0, 0, 0]),
        (
            UnverifiedTarget256([u64::MAX, u64::MAX, 0, 0]),
            [0, 0, 1, 0, 0],
        ),
        (
            small(2),
            [
                0x5555555555555555,
                0x5555555555555555,
                0x5555555555555555,
                0x5555555555555555,
                0,
            ],
        ),
    ];
    for (input, expected) in independent {
        assert_eq!(unverified_work(input).unwrap().0, Word320(expected));
    }
    assert_eq!(
        unverified_work(small(9)).unwrap().0,
        Word320([
            0x9999999999999999,
            0x9999999999999999,
            0x9999999999999999,
            0x1999999999999999,
            0
        ])
    );
    assert_eq!(
        unverified_work(UnverifiedTarget256([0, 1, 0, 0]))
            .unwrap()
            .0,
        Word320([u64::MAX, 0, u64::MAX, 0, 0])
    );
    for k in 1..=256 {
        let mut target_bytes = [0; 32];
        for bit in 0..k {
            target_bytes[bit / 8] |= 1 << (bit % 8);
        }
        let mut expected = [0; 40];
        expected[(256 - k) / 8] = 1 << ((256 - k) % 8);
        assert_eq!(
            unverified_work(UnverifiedTarget256::from_le_bytes(target_bytes).unwrap())
                .unwrap()
                .to_le_bytes(),
            expected
        );
    }
    let single = unverified_work(small(1)).unwrap();
    let mut sum = UnverifiedWork320::ZERO;
    for _ in 0..64 {
        sum = sum.checked_add(sum).unwrap().checked_add(single).unwrap();
    }
    assert_eq!(sum.0, Word320([0, 0, 0, 1 << 63, u64::MAX >> 1]));
    assert_eq!(sum.0.bits(), 319);
    let maximum = UnverifiedWork320::from_le_bytes([255; 40]);
    assert_eq!(maximum.to_le_bytes(), [255; 40]);
    assert_eq!(
        maximum.checked_add(UnverifiedWork320(Word320::ONE)),
        Err(ArithmeticError::Overflow)
    );
    assert_eq!(maximum.to_le_bytes(), [255; 40]);
    assert_eq!(maximum.compare_numeric(sum), Ordering::Greater);
    assert_eq!(sum.compare_numeric(sum), Ordering::Equal);
    assert_eq!(UnverifiedWork320::ZERO.checked_add(single).unwrap(), single);
}

fn time_controls() {
    use UnverifiedNumericTime::*;
    for count in 1..=11 {
        let mut previous = [0; 11];
        for (i, time) in previous[..count].iter_mut().enumerate() {
            *time = (count - i - 1) as u64;
        }
        let median = (count / 2) as u64;
        assert_eq!(
            classify_unverified_time(count as u64, median, &previous[..count], Some(100)).unwrap(),
            BelowOrEqualMedian
        );
        assert_eq!(
            classify_unverified_time(count as u64, median + 1, &previous[..count], Some(100))
                .unwrap(),
            NumericallyEligible
        );
    }
    let times = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 1000000000];
    for (candidate, utc, expected) in [
        (6, Some(100), BelowOrEqualMedian),
        (7, Some(100), NumericallyEligible),
        (7, None, DeferMissingClock),
        (10000, Some(2800), NumericallyEligible),
        (10001, Some(2800), DeferFuture),
        (u64::MAX, Some(u64::MAX), NumericallyEligible),
    ] {
        assert_eq!(
            classify_unverified_time(100, candidate, &times, utc).unwrap(),
            expected
        );
    }
    assert_eq!(
        classify_unverified_time(11, 7, &[7; 11], None).unwrap(),
        BelowOrEqualMedian
    );
    assert_eq!(
        classify_unverified_time(11, 8, &[7; 11], Some(0)).unwrap(),
        NumericallyEligible
    );
    assert_eq!(
        classify_unverified_time(0, 0, &[], None),
        Err(ArithmeticError::ZeroHeight)
    );
    for (height, times) in [
        (1, &[][..]),
        (1, &[0, 1][..]),
        (10, &[0; 11][..]),
        (11, &[0; 10][..]),
        (u64::MAX, &[0; 12][..]),
    ] {
        assert_eq!(
            classify_unverified_time(height, 100, times, None),
            Err(ArithmeticError::WindowLength)
        );
    }
    assert!(std::error::Error::source(&ArithmeticError::ZeroTarget).is_none());
    assert_eq!(ArithmeticError::ZeroTarget.to_string(), "ZeroTarget");
}

#[test]
#[ignore = "finite release diagnostic requires an external resource guard"]
fn bounded_native_suite() {
    const {
        assert!(!cfg!(debug_assertions), "release diagnostic only");
    }
    let (saved, contexts) = saved_targets();
    public_context_controls();
    limb_controls();
    work_controls();
    time_controls();
    println!(
        "saved_targets={saved} public_contexts={contexts} context_group=1 limb_group=1 right_shifts=322 bit_checks=103040 work_literals=8 mersenne_divisions=256 time_group=1 maximum_sum_bits=319"
    );
}
