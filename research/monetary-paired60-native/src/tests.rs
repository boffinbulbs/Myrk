use super::*;

type PairRow = [u64; 16];

struct ExpectedTransition {
    height: u64,
    before: [u64; 2],
    nominal: u64,
    capped: u64,
    allocation: [u64; 4],
    earned: u64,
    unearned: u64,
    actual: u64,
    burn: u64,
    after: [u64; 2],
    outstanding: u64,
    remaining: u64,
}

include!("saved_cases.rs");

fn a(value: u64) -> UnverifiedAmount {
    UnverifiedAmount::from_atomic(value)
}

fn vector(row: &PairRow, offset: usize) -> [u64; 4] {
    [
        row[offset],
        row[offset + 1],
        row[offset + 2],
        row[offset + 3],
    ]
}

fn schedule_and_cap_pairs() -> (usize, usize) {
    assert_eq!(PAIRS.len(), 240);
    let mut phase_checks = 0;
    let mut cap_pairs = 0;
    for row in PAIRS {
        let period = row[0];
        assert_eq!(PERIOD_SUBSIDIES_ATOMIC[period as usize], row[1]);
        assert_eq!(paired_amounts(a(row[1])), (a(row[2]), a(row[3])));
        let first = period * PERIOD_BLOCKS + 1;
        let last = first + PERIOD_BLOCKS - 1;
        for (height, expected) in [
            (first, row[2]),
            (first + 1, row[3]),
            (last - 1, row[2]),
            (last, row[3]),
        ] {
            assert_eq!(nominal_subsidy(height), a(expected));
            phase_checks += 1;
        }
        if period > 0 {
            assert_eq!(nominal_subsidy(first - 1), a(PAIRS[period as usize - 1][3]));
        }
        assert_eq!(planned_allocation(a(row[2])).atoms(), vector(row, 4));
        assert_eq!(planned_allocation(a(row[3])).atoms(), vector(row, 8));
        assert_eq!(planned_allocation(a(row[1])).atoms(), vector(row, 12));

        for (case, remaining) in [row[1], row[2] - 1, row[2], row[2] + 1]
            .into_iter()
            .enumerate()
        {
            let mut totals = UnverifiedTotals::new(a(CAP_ATOMS - remaining), a(0)).unwrap();
            let qa = totals.quote(first);
            let ia = totals
                .issue(first, qa.allocation().staking_budget())
                .unwrap();
            let qb = totals.quote(first + 1);
            let ib = totals
                .issue(first + 1, qb.allocation().staking_budget())
                .unwrap();
            let expected = match case {
                0 => vector(row, 12),
                1 => [row[4] + 2, row[5] - 1, row[6] - 1, row[7] - 1],
                2 => vector(row, 4),
                3 => [row[4] + 1, row[5], row[6], row[7]],
                _ => unreachable!(),
            };
            let actual_a = ia.budget().allocation().atoms();
            let actual_b = ib.budget().allocation().atoms();
            for index in 0..4 {
                assert_eq!(actual_a[index] + actual_b[index], expected[index]);
            }
            assert_eq!(ia.unearned(), a(0));
            assert_eq!(ib.unearned(), a(0));
            assert_eq!(totals.issued(), a(CAP_ATOMS));
            assert_eq!(totals.burned(), a(0));
            assert_eq!(totals.remaining(), a(0));
            cap_pairs += 1;
        }
    }
    assert_eq!(phase_checks, 960);
    assert_eq!(cap_pairs, 960);
    (phase_checks, cap_pairs)
}

fn saved_literals_and_prefixes() {
    for &(height, expected) in NOMINAL {
        assert_eq!(nominal_subsidy(height), a(expected));
    }
    for &(total, first, second) in MANUAL_PAIRS {
        assert_eq!(paired_amounts(a(total)), (a(first), a(second)));
    }
    for &(total, expected) in ALLOCATIONS {
        assert_eq!(planned_allocation(a(total)).atoms(), expected);
    }
    for &(height, expected) in PREFIXES {
        assert_eq!(nominal_prefix(height).unwrap(), expected);
    }
    assert_eq!(
        planned_allocation(a(u64::MAX)).atoms(),
        [
            11_068_046_444_225_730_970,
            3_689_348_814_741_910_323,
            1_844_674_407_370_955_161,
            1_844_674_407_370_955_161
        ]
    );
    assert!(nominal_prefix(u64::MAX).unwrap() < (1u128 << 90));
    assert_eq!(nominal_subsidy(FIRST_TAIL_HEIGHT - 1), a(25_363_636));
    assert_eq!(nominal_subsidy(FIRST_TAIL_HEIGHT), a(25_000_000));
}

fn saved_transitions() {
    assert_eq!(TRANSITIONS.len(), 3);
    for expected in TRANSITIONS {
        let mut totals =
            UnverifiedTotals::new(a(expected.before[0]), a(expected.before[1])).unwrap();
        let quote = totals.quote(expected.height);
        assert_eq!(quote.height(), expected.height);
        assert_eq!(quote.nominal(), a(expected.nominal));
        assert_eq!(quote.capped(), a(expected.capped));
        assert_eq!(quote.allocation().atoms(), expected.allocation);
        let issued = totals.issue(expected.height, a(expected.earned)).unwrap();
        assert_eq!(issued.budget(), quote);
        assert_eq!(issued.earned(), a(expected.earned));
        assert_eq!(issued.unearned(), a(expected.unearned));
        assert_eq!(issued.actual(), a(expected.actual));
        totals.burn(a(expected.burn)).unwrap();
        assert_eq!(totals.issued(), a(expected.after[0]));
        assert_eq!(totals.burned(), a(expected.after[1]));
        assert_eq!(totals.outstanding(), a(expected.outstanding));
        assert_eq!(totals.remaining(), a(expected.remaining));
    }
    assert_eq!(TRANSITIONS[0].actual + TRANSITIONS[1].actual, 96);
    assert_eq!(TRANSITIONS[1].remaining, 4);
    // The old single-budget comparison is saved data, not a new-profile call.
    assert_eq!(OLD_SINGLE_ACTUAL, 80);
    assert_eq!(OLD_SINGLE_REMAINING, 20);
    let totals = UnverifiedTotals::new(a(CAP_ATOMS), a(0)).unwrap();
    assert_eq!(totals.quote(167_804_684).capped(), a(0));
}

fn earned_burn_cases() -> usize {
    let mut cases = 0;
    for period in [0usize, 1, 239] {
        let row = &PAIRS[period];
        for phase in 0..2 {
            let amounts = vector(row, 4 + 4 * phase);
            for earned in [0, amounts[1] / 2, amounts[1]] {
                let height = period as u64 * PERIOD_BLOCKS + 1 + phase as u64;
                let mut totals = UnverifiedTotals::genesis();
                let result = totals.issue(height, a(earned)).unwrap();
                let expected = amounts[0] + amounts[2] + amounts[3] + earned;
                assert_eq!(result.actual(), a(expected));
                assert_eq!(result.unearned(), a(amounts[1] - earned));
                assert_eq!(result.budget().allocation().atoms(), amounts);
                assert_eq!(totals.issued(), a(expected));
                totals.burn(a(1)).unwrap();
                assert_eq!(totals.burned(), a(1));
                assert_eq!(totals.outstanding(), a(expected - 1));
                assert_eq!(totals.remaining(), a(CAP_ATOMS - expected));
                cases += 1;
            }
        }
    }
    assert_eq!(cases, 18);
    cases
}

fn actual_failures() -> usize {
    let mut refusals = 0;
    for (issued, burned, expected) in [
        (
            CAP_ATOMS + 1,
            0,
            NumericError::IssuedAboveCap {
                issued: CAP_ATOMS + 1,
            },
        ),
        (
            u64::MAX,
            u64::MAX,
            NumericError::IssuedAboveCap { issued: u64::MAX },
        ),
        (
            0,
            1,
            NumericError::BurnedAboveIssued {
                issued: 0,
                burned: 1,
            },
        ),
        (
            1,
            2,
            NumericError::BurnedAboveIssued {
                issued: 1,
                burned: 2,
            },
        ),
    ] {
        assert_eq!(UnverifiedTotals::new(a(issued), a(burned)), Err(expected));
        refusals += 1;
    }
    assert_eq!(a(u64::MAX).checked_add(a(1)), Err(NumericError::Overflow));
    assert_eq!(a(0).checked_sub(a(1)), Err(NumericError::Underflow));
    refusals += 2;
    assert_eq!(a(u64::MAX).checked_sub(a(u64::MAX)).unwrap(), a(0));
    assert_eq!(a(0).checked_add(a(u64::MAX)).unwrap(), a(u64::MAX));

    let mut genesis = UnverifiedTotals::genesis();
    assert_eq!(genesis.issue(0, a(0)).unwrap().actual(), a(0));
    assert_eq!(
        genesis.issue(0, a(1)),
        Err(NumericError::EarnedAboveBudget {
            earned: 1,
            budget: 0
        })
    );
    assert_eq!(genesis, UnverifiedTotals::genesis());
    refusals += 1;
    assert_eq!(
        genesis.burn(a(1)),
        Err(NumericError::BurnAboveOutstanding {
            requested: 1,
            available: 0
        })
    );
    assert_eq!(genesis, UnverifiedTotals::genesis());
    refusals += 1;

    for earned in [160_000_001, u64::MAX] {
        let mut totals = UnverifiedTotals::genesis();
        let before = totals;
        assert_eq!(
            totals.issue(1, a(earned)),
            Err(NumericError::EarnedAboveBudget {
                earned,
                budget: 160_000_000
            })
        );
        assert_eq!(totals, before);
        refusals += 1;
    }
    let mut last = UnverifiedTotals::new(a(CAP_ATOMS - 1), a(0)).unwrap();
    let before = last;
    assert_eq!(
        last.issue(1, a(1)),
        Err(NumericError::EarnedAboveBudget {
            earned: 1,
            budget: 0
        })
    );
    assert_eq!(last, before);
    refusals += 1;

    let mut totals = UnverifiedTotals::new(a(CAP_ATOMS - 100), a(0)).unwrap();
    let old_quote = totals.quote(1);
    totals
        .issue(1, old_quote.allocation().staking_budget())
        .unwrap();
    let before = totals;
    assert_eq!(
        totals.issue(2, old_quote.allocation().staking_budget()),
        Err(NumericError::EarnedAboveBudget {
            earned: 20,
            budget: 0
        })
    );
    assert_eq!(totals, before);
    refusals += 1;
    for requested in [76, u64::MAX] {
        let mut totals = UnverifiedTotals::new(a(100), a(25)).unwrap();
        let before = totals;
        assert_eq!(
            totals.burn(a(requested)),
            Err(NumericError::BurnAboveOutstanding {
                requested,
                available: 75
            })
        );
        assert_eq!(totals, before);
        refusals += 1;
    }
    let mut burned = UnverifiedTotals::new(a(CAP_ATOMS), a(100)).unwrap();
    burned.burn(a(5)).unwrap();
    assert_eq!(burned.burned(), a(105));
    assert_eq!(burned.remaining(), a(0));
    let before = burned;
    assert_eq!(
        burned.issue(1, a(1)),
        Err(NumericError::EarnedAboveBudget {
            earned: 1,
            budget: 0
        })
    );
    assert_eq!(burned, before);
    refusals += 1;

    let mut rounded = UnverifiedTotals::genesis();
    assert_eq!(
        rounded.issue(43_801, a(157_706_111)),
        Err(NumericError::EarnedAboveBudget {
            earned: 157_706_111,
            budget: 157_706_110
        })
    );
    assert_eq!(rounded, UnverifiedTotals::genesis());
    refusals += 1;
    assert_eq!(NumericError::Overflow.to_string(), "Overflow");
    assert!(std::error::Error::source(&NumericError::Overflow).is_none());
    assert_eq!(refusals, 16);
    refusals
}

#[test]
#[ignore = "finite release diagnostic requires an external resource guard"]
fn bounded_native_accounting() {
    const {
        assert!(!cfg!(debug_assertions), "release diagnostic only");
    }
    let (boundaries, cap_pairs) = schedule_and_cap_pairs();
    saved_literals_and_prefixes();
    saved_transitions();
    let earned = earned_burn_cases();
    let refusals = actual_failures();
    println!(
        "period_pairs=240 phase_boundaries={boundaries} cap_pairs={cap_pairs} earned_burn_cases={earned} actual_numeric_refusals={refusals} saved_prefixes=9 saved_transitions=3 manual_nominal=13 manual_pair=7 manual_allocation=6"
    );
}
