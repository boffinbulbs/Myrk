"""Invariants and checks of frozen artifacts for the monetary reference."""

import json
import hashlib
from pathlib import Path
import random
import unittest

import emission as model


class ScheduleTests(unittest.TestCase):
    def test_exact_floor_proof_for_every_entry(self):
        power = (16 * model.ATOMS_PER_COIN) ** 48
        for period, reward in enumerate(model.SCHEDULE):
            with self.subTest(period=period):
                self.assertLessEqual((reward**48) << period, power)
                self.assertGreater(((reward + 1)**48) << period, power)

    def test_frozen_values_hash(self):
        self.assertEqual(len(model.SCHEDULE), 240)
        self.assertEqual(model.schedule_values_sha256(),
                         "ab8097f05a6993a38a3666ca5056c0cd30a6609ab2d5c3192a038bf2e27c8f7b")
        self.assertEqual(hashlib.sha256(model.schedule_csv()).hexdigest(),
                         "1a06338798693b63261c76bcc4dc873437f716b4d6f413a961f32c8ecd336918")
        self.assertTrue(all(a >= b for a, b in zip(model.SCHEDULE, model.SCHEDULE[1:])))

    def test_genesis_and_every_period_boundary(self):
        self.assertEqual(model.scheduled_subsidy(0), 0)
        self.assertEqual(model.scheduled_subsidy(1), 16 * model.ATOMS_PER_COIN)
        for period in range(240):
            first_height = period * model.BLOCKS_PER_PERIOD + 1
            self.assertEqual(model.scheduled_subsidy(first_height), model.SCHEDULE[period])
            self.assertEqual(model.scheduled_subsidy(first_height + model.BLOCKS_PER_PERIOD - 1),
                             model.SCHEDULE[period])
        self.assertEqual(model.scheduled_subsidy(model.LONG_REWARD_FIRST_HEIGHT), 50_000_000)
        self.assertEqual(model.scheduled_subsidy(model.MAX_HEIGHT), 50_000_000)

    def test_half_lives_and_time_units(self):
        self.assertEqual(model.BLOCKS_PER_YEAR, 262_800)
        self.assertEqual(12 * model.BLOCKS_PER_PERIOD, model.BLOCKS_PER_YEAR)
        for period, coins in [(0, 16), (48, 8), (96, 4), (144, 2), (192, 1)]:
            self.assertEqual(model.SCHEDULE[period], coins * model.ATOMS_PER_COIN)

    def test_integer_root_edges(self):
        for degree in [1, 2, 3, 48]:
            for value in [0, 1, 2, 15, 16, 17, 2**200]:
                root = model.integer_nth_root(value, degree)
                self.assertLessEqual(root**degree, value)
                self.assertGreater((root + 1)**degree, value)


class AccountingTests(unittest.TestCase):
    def test_budget_conservation_and_remainder(self):
        values = [0, 1, 2, 7, 9, 10, 11, *model.SCHEDULE, model.CAP_ATOMS]
        for amount in values:
            miner, staking, pool, development = model.split_budget(amount)
            self.assertEqual(miner + staking + pool + development, amount)
            self.assertEqual(staking, 2 * amount // 10)
            self.assertEqual(pool, amount // 10)
            self.assertEqual(development, amount // 10)
            self.assertTrue(0 <= miner - 6 * amount // 10 <= 3)
        self.assertEqual(model.split_budget(0), (0, 0, 0, 0))
        self.assertEqual(model.split_budget(1), (1, 0, 0, 0))
        self.assertEqual(model.split_budget(7), (6, 1, 0, 0))
        self.assertEqual(model.split_budget(9), (8, 1, 0, 0))
        self.assertEqual(model.split_budget(10), (6, 2, 1, 1))
        self.assertEqual(model.split_budget(11), (7, 2, 1, 1))

    def test_cap_clips_before_split(self):
        result = model.block_transition(1, model.CAP_ATOMS - 7)
        self.assertEqual((result["capped_reward_atoms"], result["miner_atoms"],
                          result["staking_budget_atoms"], result["protocol_pool_atoms"],
                          result["development_maintenance_atoms"]), (7, 6, 1, 0, 0))
        self.assertEqual(result["cumulative_issued_after_atoms"], model.CAP_ATOMS)

    def test_unearned_staking_is_unissued(self):
        result = model.block_transition(1, earned_staking_atoms=0)
        self.assertEqual(result["actual_issued_atoms"], 1_280_000_000)
        self.assertEqual(result["unearned_staking_atoms"], 320_000_000)
        result = model.block_transition(1, model.CAP_ATOMS - 1, earned_staking_atoms=0)
        self.assertEqual(result["actual_issued_atoms"], 1)
        self.assertEqual(result["remaining_cap_after_atoms"], 0)
        result = model.block_transition(1, model.CAP_ATOMS - 5, earned_staking_atoms=0)
        self.assertEqual(result["actual_issued_atoms"], 4)
        self.assertEqual(result["remaining_cap_after_atoms"], 1)

    def test_pool_and_development_are_issued_without_a_spending_action(self):
        result = model.block_transition(1, earned_staking_atoms=0)
        self.assertEqual(result["miner_atoms"], 960_000_000)
        self.assertEqual(result["protocol_pool_atoms"], 160_000_000)
        self.assertEqual(result["development_maintenance_atoms"], 160_000_000)
        self.assertEqual(result["outstanding_after_atoms"],
                         result["miner_atoms"] + result["protocol_pool_atoms"] +
                         result["development_maintenance_atoms"])
        self.assertEqual(result["cumulative_issued_after_atoms"], result["outstanding_after_atoms"])

    def test_genesis_has_no_allocation(self):
        result = model.block_transition(0)
        for field in ["miner_atoms", "staking_budget_atoms", "protocol_pool_atoms",
                      "development_maintenance_atoms", "actual_issued_atoms"]:
            self.assertEqual(result[field], 0)

    def test_burn_conservation_and_no_reminting(self):
        result = model.block_transition(1, burn_after_atoms=300_000_000)
        self.assertEqual(result["cumulative_issued_after_atoms"], 1_600_000_000)
        self.assertEqual(result["outstanding_after_atoms"], 1_300_000_000)
        result = model.block_transition(1, model.CAP_ATOMS, 2_000_000_000)
        self.assertEqual(result["actual_issued_atoms"], 0)
        self.assertEqual(result["outstanding_after_atoms"], model.CAP_ATOMS - 2_000_000_000)

    def test_random_accounting_invariants(self):
        rng = random.Random(63_000_000)
        for _ in range(500):
            issued = rng.randrange(model.CAP_ATOMS + 1)
            burned = rng.randrange(issued + 1)
            height = rng.randrange(model.MAX_HEIGHT + 1)
            budget = model.block_transition(height, issued, burned)
            earned = rng.randrange(budget["staking_budget_atoms"] + 1)
            credited = budget["miner_atoms"] + budget["protocol_pool_atoms"] + budget["development_maintenance_atoms"]
            available = issued - burned + credited + earned
            burn = rng.randrange(available + 1)
            result = model.block_transition(height, issued, burned, earned, burn)
            self.assertEqual(result["actual_issued_atoms"], credited + earned)
            self.assertEqual(result["capped_reward_atoms"],
                             result["actual_issued_atoms"] + result["unearned_staking_atoms"])
            self.assertLessEqual(result["cumulative_issued_after_atoms"], model.CAP_ATOMS)
            self.assertEqual(result["outstanding_after_atoms"],
                             issued - burned + result["actual_issued_atoms"] - burn)

    def test_invalid_inputs(self):
        for case in model.golden_vectors()["invalid_cases"]:
            with self.subTest(case=case["id"]), self.assertRaises(ValueError):
                model.block_transition(**case["input"])
        for bad in [-1, 0.5, True, "1"]:
            with self.subTest(value=bad), self.assertRaises(ValueError):
                model.scheduled_subsidy(bad)
        with self.assertRaises(ValueError):
            model.split_budget(model.CAP_ATOMS + 1)
        with self.assertRaises(ValueError):
            model.block_transition(1, earned_staking_atoms=-1)


class ProjectionAndArtifactTests(unittest.TestCase):
    def test_projection_matches_block_iteration(self):
        total = 0
        allocations = [0, 0, 0, 0]
        for height in range(1, 2 * model.BLOCKS_PER_PERIOD + 2):
            reward = model.scheduled_subsidy(height)
            total += reward
            allocations = [before + after for before, after in zip(allocations, model.split_budget(reward))]
            if height in [1, model.BLOCKS_PER_PERIOD, model.BLOCKS_PER_PERIOD + 1,
                          2 * model.BLOCKS_PER_PERIOD + 1]:
                self.assertEqual(model.nominal_issued_through_height(height), total)
                self.assertEqual(model.fully_earned_allocations_through_height(height), tuple(allocations))

    def test_final_cap_block(self):
        data = model.cap_exhaustion()
        height = data["first_exhausted_height"]
        self.assertLess(model.fully_earned_issued_through_height(height - 1), model.CAP_ATOMS)
        self.assertEqual(model.fully_earned_issued_through_height(height), model.CAP_ATOMS)
        self.assertEqual(model.fully_earned_issued_through_height(height + 1), model.CAP_ATOMS)
        final = data["final_block"]
        self.assertGreater(final["actual_issued_atoms"], 0)
        self.assertLessEqual(final["actual_issued_atoms"], model.LONG_REWARD_ATOMS)
        self.assertEqual((final["miner_atoms"], final["staking_budget_atoms"],
                          final["protocol_pool_atoms"], final["development_maintenance_atoms"]),
                         (7_270_740, 2_423_580, 1_211_790, 1_211_790))
        self.assertEqual(sum(model.fully_earned_allocations_through_height(height)), model.CAP_ATOMS)
        self.assertEqual(model.fully_earned_allocations_through_height(height),
                         model.fully_earned_allocations_through_height(model.MAX_HEIGHT))

    def test_projection_allocations_conserve_each_total(self):
        for row in model.projection_rows(model.BLOCKS_PER_YEAR, 330):
            self.assertEqual(sum(row["cumulative_" + name + "_atoms"] for name in model.ALLOCATION_NAMES),
                             row["cumulative_issued_atoms"])
            self.assertEqual(sum(row["next_year_" + name + "_atoms"] for name in model.ALLOCATION_NAMES),
                             row["next_year_issued_atoms"])

    def test_development_sunset_is_not_encoded(self):
        metadata = json.loads(model.generated_files()["metadata.json"])
        self.assertIsNone(metadata["allocation_profile"]["development_sunset_height"])

    def test_projection_known_values(self):
        self.assertEqual(model.nominal_issued_through_height(0), 0)
        self.assertEqual(model.nominal_issued_through_height(20 * model.BLOCKS_PER_YEAR),
                         2_367_682_937_882_100)
        self.assertEqual(model.nominal_issued_through_height(21 * model.BLOCKS_PER_YEAR) -
                         model.nominal_issued_through_height(20 * model.BLOCKS_PER_YEAR),
                         131_400 * model.ATOMS_PER_COIN)

    def test_frozen_artifacts_are_reproducible(self):
        directory = Path(__file__).resolve().parent
        for name, expected in model.generated_files().items():
            with self.subTest(artifact=name):
                self.assertEqual((directory / name).read_bytes(), expected)

    def test_frozen_golden_vectors(self):
        directory = Path(__file__).resolve().parent
        frozen = json.loads((directory / "golden_vectors.json").read_text(encoding="ascii"))
        for vector in frozen["transitions"]:
            actual = model.block_transition(
                vector["height"], vector["cumulative_issued_before_atoms"],
                vector["cumulative_burned_before_atoms"], vector["earned_staking_atoms"],
                vector["burn_after_atoms"])
            self.assertEqual(actual, {key: value for key, value in vector.items() if key != "id"})


if __name__ == "__main__":
    unittest.main()
