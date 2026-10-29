"""Adversarial checks for the independent finite reference corpus."""
import copy
import json
from pathlib import Path
import unittest

from reference import Q, calculate

HERE = Path(__file__).resolve().parent


class ReferenceTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.corpus = json.loads((HERE / "fixtures/salts.json").read_text())

    def changed(self):
        return copy.deepcopy(self.corpus)

    def test_all_roots_match_retained_artifact(self):
        expected = json.loads((HERE / "fixtures/reference.json").read_text())
        self.assertEqual(calculate(self.corpus), expected)

    def test_false_root_rejected(self):
        corpus = self.changed()
        corpus[0]["root"][0] ^= 1
        with self.assertRaises(ValueError):
            calculate(corpus)

    def test_canonical_salt_mutation_rejected(self):
        corpus = self.changed()
        corpus[2]["salts"][0][127][8] = (corpus[2]["salts"][0][127][8] + 1) % Q
        with self.assertRaises(ValueError):
            calculate(corpus)

    def test_noncanonical_salt_rejected(self):
        corpus = self.changed()
        corpus[0]["salts"][0][0][0] = Q
        with self.assertRaises(ValueError):
            calculate(corpus)

    def test_missing_salt_rejected(self):
        corpus = self.changed()
        corpus[0]["salts"][0][0].pop()
        with self.assertRaises(ValueError):
            calculate(corpus)

    def test_changed_mixed_height_geometry_rejected(self):
        corpus = self.changed()
        corpus[3]["dimensions"][0][0] = 128
        with self.assertRaises(ValueError):
            calculate(corpus)

    def test_matrix_order_rejected(self):
        corpus = self.changed()
        corpus[3]["salts"][0], corpus[3]["salts"][2] = corpus[3]["salts"][2], corpus[3]["salts"][0]
        with self.assertRaises(ValueError):
            calculate(corpus)

    def test_boolean_identifiers_and_dimensions_rejected(self):
        for field in ["id", "dimensions"]:
            corpus = self.changed()
            if field == "id":
                corpus[0][field] = True
            else:
                corpus[0][field][0][1] = True
            with self.assertRaises(ValueError):
                calculate(corpus)

    def test_boolean_digest_words_rejected(self):
        corpus = self.changed()
        corpus[0]["root"][0] = False
        with self.assertRaises(ValueError):
            calculate(corpus)


if __name__ == "__main__":
    unittest.main()
