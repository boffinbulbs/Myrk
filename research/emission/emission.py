"""Exact-integer emission and accounting research reference.

This module models monetary arithmetic. It does not implement consensus,
staking eligibility, transaction validation, privacy, or cryptography.
All monetary values are integer atomic units unless named otherwise.
"""

from __future__ import annotations

import argparse
import csv
import hashlib
import io
import json
from pathlib import Path

ATOMS_PER_COIN = 100_000_000
CAP_ATOMS = 63_000_000 * ATOMS_PER_COIN
BLOCK_SECONDS = 120
BLOCKS_PER_YEAR = 365 * 86_400 // BLOCK_SECONDS
BLOCKS_PER_PERIOD = 21_900
DECLINING_PERIODS = 240
LONG_REWARD_ATOMS = ATOMS_PER_COIN // 2
LONG_REWARD_FIRST_INDEX = DECLINING_PERIODS * BLOCKS_PER_PERIOD
LONG_REWARD_FIRST_HEIGHT = LONG_REWARD_FIRST_INDEX + 1
MAX_HEIGHT = 2**64 - 1
REFERENCE_VERSION = "1"

def _natural(value: int, name: str, maximum: int | None = None) -> int:
    if type(value) is not int or value < 0 or (maximum is not None and value > maximum):
        raise ValueError(f"{name} must be a nonnegative integer" +
                         (f" no greater than {maximum}" if maximum is not None else ""))
    return value


def integer_nth_root(value: int, degree: int) -> int:
    """Return floor(value ** (1 / degree)) with integer arithmetic only."""
    _natural(value, "value")
    if type(degree) is not int or degree < 1:
        raise ValueError("degree must be a positive integer")
    low, high = 0, 1 << ((value.bit_length() + degree - 1) // degree)
    while low + 1 < high:
        middle = (low + high) // 2
        if middle**degree <= value:
            low = middle
        else:
            high = middle
    return low if high**degree > value else high


def generate_schedule() -> tuple[int, ...]:
    """Exact floor(16 * 10**8 * 2**(-period / 48)), period 0..239.

    floor(root48(floor(A**48 / 2**period))) equals
    floor(A * 2**(-period / 48)); no floating-point decision is involved.
    """
    power = (16 * ATOMS_PER_COIN) ** 48
    return tuple(integer_nth_root(power >> period, 48)
                 for period in range(DECLINING_PERIODS))


SCHEDULE = generate_schedule()


def coins(amount_atoms: int) -> str:
    _natural(amount_atoms, "amount_atoms")
    whole, fraction = divmod(amount_atoms, ATOMS_PER_COIN)
    return f"{whole}.{fraction:08d}"


def scheduled_reward_for_index(reward_block_index: int) -> int:
    _natural(reward_block_index, "reward_block_index", MAX_HEIGHT - 1)
    period = reward_block_index // BLOCKS_PER_PERIOD
    return SCHEDULE[period] if period < DECLINING_PERIODS else LONG_REWARD_ATOMS


def scheduled_subsidy(height: int) -> int:
    _natural(height, "height", MAX_HEIGHT)
    return 0 if height == 0 else scheduled_reward_for_index(height - 1)


def split_budget(amount_atoms: int) -> tuple[int, int]:
    _natural(amount_atoms, "amount_atoms", CAP_ATOMS)
    miner = amount_atoms * 7 // 10
    return miner, amount_atoms - miner


def block_transition(height: int, cumulative_issued_before_atoms: int = 0,
                     cumulative_burned_before_atoms: int = 0,
                     earned_staking_atoms: int | None = None,
                     burn_after_atoms: int = 0) -> dict:
    """Clip the budget, issue earned amounts, then apply a burn.

    None means the entire staking budget is earned. Stake eligibility is an
    input assumption, not a capability implemented by this reference.
    The miner budget is assumed earned whenever the block is issued.
    """
    scheduled = scheduled_subsidy(height)
    issued = _natural(cumulative_issued_before_atoms, "cumulative_issued_before_atoms", CAP_ATOMS)
    burned = _natural(cumulative_burned_before_atoms, "cumulative_burned_before_atoms", issued)
    remaining = CAP_ATOMS - issued
    capped = min(scheduled, remaining)
    miner, staking = split_budget(capped)
    earned = staking if earned_staking_atoms is None else _natural(
        earned_staking_atoms, "earned_staking_atoms", staking)
    actual = miner + earned
    issued_after = issued + actual
    burn = _natural(burn_after_atoms, "burn_after_atoms", issued_after - burned)
    burned_after = burned + burn
    return {
        "height": height,
        "reward_block_index": None if height == 0 else height - 1,
        "cumulative_issued_before_atoms": issued,
        "cumulative_burned_before_atoms": burned,
        "remaining_cap_before_atoms": remaining,
        "scheduled_reward_atoms": scheduled,
        "capped_reward_atoms": capped,
        "miner_atoms": miner,
        "staking_budget_atoms": staking,
        "earned_staking_atoms": earned,
        "unearned_staking_atoms": staking - earned,
        "actual_issued_atoms": actual,
        "burn_after_atoms": burn,
        "cumulative_issued_after_atoms": issued_after,
        "cumulative_burned_after_atoms": burned_after,
        "outstanding_after_atoms": issued_after - burned_after,
        "remaining_cap_after_atoms": CAP_ATOMS - issued_after,
    }


def nominal_issued_through_height(height: int) -> int:
    """Uncapped fully earned schedule through a completed block height."""
    _natural(height, "height", MAX_HEIGHT)
    complete_periods, extra_blocks = divmod(min(height, LONG_REWARD_FIRST_INDEX), BLOCKS_PER_PERIOD)
    total = sum(SCHEDULE[:complete_periods]) * BLOCKS_PER_PERIOD
    if complete_periods < DECLINING_PERIODS:
        total += extra_blocks * SCHEDULE[complete_periods]
    total += max(0, height - LONG_REWARD_FIRST_INDEX) * LONG_REWARD_ATOMS
    return total


def fully_earned_issued_through_height(height: int) -> int:
    return min(CAP_ATOMS, nominal_issued_through_height(height))


def cap_exhaustion() -> dict:
    before_long = nominal_issued_through_height(LONG_REWARD_FIRST_INDEX)
    remaining = CAP_ATOMS - before_long
    long_blocks = (remaining + LONG_REWARD_ATOMS - 1) // LONG_REWARD_ATOMS
    height = LONG_REWARD_FIRST_INDEX + long_blocks
    before = fully_earned_issued_through_height(height - 1)
    return {
        "first_exhausted_height": height,
        "reward_block_index": height - 1,
        "target_elapsed_seconds": height * BLOCK_SECONDS,
        "target_model_years": f"{height / BLOCKS_PER_YEAR:.12f}",
        "issued_before_final_block_atoms": before,
        "final_capped_reward_atoms": CAP_ATOMS - before,
        "final_block": block_transition(height, before),
    }


def schedule_csv() -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\n")
    writer.writerow(["period", "first_reward_block_index", "last_reward_block_index",
                     "first_paid_height", "last_paid_height", "reward_atoms", "reward_coins"])
    for period, amount in enumerate(SCHEDULE):
        first = period * BLOCKS_PER_PERIOD
        writer.writerow([period, first, first + BLOCKS_PER_PERIOD - 1,
                         first + 1, first + BLOCKS_PER_PERIOD, amount, coins(amount)])
    return stream.getvalue().encode("ascii")


def schedule_values_sha256() -> str:
    canonical = "".join(f"{period}:{amount}\n" for period, amount in enumerate(SCHEDULE)).encode("ascii")
    return hashlib.sha256(canonical).hexdigest()


def golden_vectors() -> dict:
    cap_info = cap_exhaustion()
    cases = [
        ("genesis", 0, 0, 0, None, 0),
        ("first_paid", 1, 0, 0, None, 0),
        ("first_period_last", BLOCKS_PER_PERIOD, 0, 0, None, 0),
        ("second_period_first", BLOCKS_PER_PERIOD + 1, 0, 0, None, 0),
        ("half_life_first", 48 * BLOCKS_PER_PERIOD + 1, 0, 0, None, 0),
        ("decline_last", LONG_REWARD_FIRST_HEIGHT - 1, 0, 0, None, 0),
        ("long_reward_first", LONG_REWARD_FIRST_HEIGHT, 0, 0, None, 0),
        ("maximum_height", MAX_HEIGHT, 0, 0, None, 0),
        ("staking_unavailable", 1, 0, 0, 0, 0),
        ("staking_partially_earned", 1, 0, 0, 123_456_789, 0),
        ("cap_clip_seven_atoms", LONG_REWARD_FIRST_HEIGHT, CAP_ATOMS - 7, 0, None, 0),
        ("cap_clip_one_earned", LONG_REWARD_FIRST_HEIGHT, CAP_ATOMS - 1, 0, 1, 0),
        ("cap_clip_one_unearned", LONG_REWARD_FIRST_HEIGHT, CAP_ATOMS - 1, 0, 0, 0),
        ("cap_exhausted", LONG_REWARD_FIRST_HEIGHT, CAP_ATOMS, 0, None, 0),
        ("burn_does_not_reopen_cap", LONG_REWARD_FIRST_HEIGHT, CAP_ATOMS, 10 * ATOMS_PER_COIN, None, 0),
        ("burn_after_first_paid", 1, 0, 0, None, 3 * ATOMS_PER_COIN),
        ("cap_clip_after_burn", LONG_REWARD_FIRST_HEIGHT, CAP_ATOMS - 7, 99, None, 2),
        ("fully_earned_final_block", cap_info["first_exhausted_height"],
         cap_info["issued_before_final_block_atoms"], 0, None, 0),
    ]
    transitions = [{"id": identifier, **block_transition(height, issued, burned, earned, burn)}
                   for identifier, height, issued, burned, earned, burn in cases]
    return {
        "schema_version": 1,
        "units": "integer atomic units; 100000000 atomic units per coin",
        "semantics": {
            "height_zero": "zero reward; reward_block_index is null",
            "cap": "cumulative actual issuance; burns do not reopen capacity",
            "clipping": "clip scheduled subsidy to remaining capacity before budget splitting",
            "split": "miner=floor(capped_reward*7/10); staking=capped_reward-miner",
            "staking": "only earned_staking_atoms are issued; unearned budget remains unissued",
            "burn": "burn_after_atoms is applied after issuance and reduces outstanding supply",
            "vectors": "independent input states, not consecutive blocks or eligibility proofs",
        },
        "transitions": transitions,
        "split_vectors": [{"amount_atoms": amount, "miner_atoms": split_budget(amount)[0],
                           "staking_budget_atoms": split_budget(amount)[1]}
                          for amount in [0, 1, 2, 7, 9, 10, 11, 50_000_000, 1_577_061_117]],
        "invalid_cases": [
            {"id": "negative_height", "input": {"height": -1}},
            {"id": "height_over_u64", "input": {"height": MAX_HEIGHT + 1}},
            {"id": "issued_above_cap", "input": {"height": 1, "cumulative_issued_before_atoms": CAP_ATOMS + 1}},
            {"id": "burned_above_issued", "input": {"height": 1, "cumulative_burned_before_atoms": 1}},
            {"id": "staking_above_budget", "input": {"height": 1, "earned_staking_atoms": 480_000_001}},
            {"id": "burn_above_outstanding", "input": {"height": 1, "burn_after_atoms": 1_600_000_001}},
        ],
    }


def projection_rows(step_blocks: int, count: int):
    for point in range(count + 1):
        height = point * step_blocks
        issued = fully_earned_issued_through_height(height)
        next_year_issued = fully_earned_issued_through_height(height + BLOCKS_PER_YEAR) - issued
        next_block = block_transition(height + 1, issued)
        yield {
            "completed_height": height,
            "target_elapsed_seconds": height * BLOCK_SECONDS,
            "model_years": f"{height / BLOCKS_PER_YEAR:.12f}",
            "cumulative_issued_atoms": issued,
            "cumulative_issued_coins": coins(issued),
            "cumulative_burned_atoms": 0,
            "outstanding_atoms": issued,
            "remaining_cap_atoms": CAP_ATOMS - issued,
            "next_block_scheduled_atoms": next_block["scheduled_reward_atoms"],
            "next_block_capped_atoms": next_block["capped_reward_atoms"],
            "next_block_miner_atoms": next_block["miner_atoms"],
            "next_block_staking_budget_atoms": next_block["staking_budget_atoms"],
            "next_year_issued_atoms": next_year_issued,
            "next_year_issued_coins": coins(next_year_issued),
            "next_year_gross_issuance_percent": None if not issued else f"{100 * next_year_issued / issued:.12f}",
        }


def projection_csv(step_blocks: int, count: int) -> bytes:
    rows = list(projection_rows(step_blocks, count))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("ascii")


def _json_bytes(value: dict) -> bytes:
    return (json.dumps(value, indent=2, ensure_ascii=True) + "\n").encode("ascii")


def golden_vectors_csv() -> bytes:
    rows = golden_vectors()["transitions"]
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=list(rows[0]), lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return stream.getvalue().encode("ascii")


def generated_files() -> dict[str, bytes]:
    files = {
        "schedule.csv": schedule_csv(),
        "golden_vectors.json": _json_bytes(golden_vectors()),
        "golden_vectors.csv": golden_vectors_csv(),
        "projection_annual.csv": projection_csv(BLOCKS_PER_YEAR, 330),
        "projection_monthly.csv": projection_csv(BLOCKS_PER_PERIOD, 330 * 12),
    }
    metadata = {
        "reference_version": REFERENCE_VERSION,
        "implementation_status": "monetary research reference; open construction",
        "atomic_decimals": 8,
        "cap_atoms": CAP_ATOMS,
        "block_seconds": BLOCK_SECONDS,
        "blocks_per_model_year": BLOCKS_PER_YEAR,
        "blocks_per_reward_period": BLOCKS_PER_PERIOD,
        "declining_periods": DECLINING_PERIODS,
        "long_reward_atoms": LONG_REWARD_ATOMS,
        "long_reward_first_index": LONG_REWARD_FIRST_INDEX,
        "long_reward_first_height": LONG_REWARD_FIRST_HEIGHT,
        "schedule_values_sha256": schedule_values_sha256(),
        "schedule_hash_encoding": "ASCII decimal period:reward_atoms followed by LF for each of 240 entries",
        "assumptions": ["all scheduled miner and staking budgets fully earned",
                        "zero-reward genesis; first paid height 1 maps to reward index 0",
                        "target 120-second block spacing; 365-day model years",
                        "no burns", "no premine", "no bootstrap or omitted-budget timing adjustment"],
        "cap_exhaustion": cap_exhaustion(),
        "artifacts_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
        "open_questions": ["stake eligibility and distribution", "bootstrap and launch rules",
                           "privacy and post-quantum consensus construction", "fees and security after cap exhaustion"],
    }
    files["metadata.json"] = _json_bytes(metadata)
    return files


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare frozen artifacts without rewriting them")
    args = parser.parse_args()
    directory = Path(__file__).resolve().parent
    mismatches = []
    for name, data in generated_files().items():
        destination = directory / name
        if args.check:
            if not destination.exists() or destination.read_bytes() != data:
                mismatches.append(name)
        else:
            destination.write_bytes(data)
    if mismatches:
        parser.exit(1, "Frozen artifacts differ: " + ", ".join(mismatches) + "\n")
    print("Frozen artifacts match." if args.check else "Generated schedule, vectors, projections, and metadata.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
