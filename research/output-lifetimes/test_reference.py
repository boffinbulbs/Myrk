import unittest
from reference import MAP, certificate, conflicts, windows


class LifetimeReference(unittest.TestCase):
    def test_safe_and_unsafe_full_coordinates(self):
        self.assertEqual(conflicts(MAP), [])
        unsafe = MAP.copy()
        unsafe[14] = 6
        bad = conflicts(unsafe)
        self.assertEqual(len(bad), 12160)
        self.assertEqual(set(x[:2] for x in bad), {(6, 14), (14, 15)})
        self.assertNotIn(255, set(x[2] for x in bad if x[:2] == (6,14)))

    def test_exact_last_consumer_and_next_row_visibility(self):
        self.assertEqual(windows(6)[-1], (3288, 3330))
        self.assertEqual(610 + 192 * 14, 3298)
        self.assertLess(610 + 192 * 14, 3329)
        self.assertEqual(641 + 192 * 14 + 1, 3330)

    def test_earlier_reuse_collides(self):
        bad = MAP.copy()
        bad[8] = 6
        self.assertTrue(conflicts(bad))

    def test_finite_reference_shape(self):
        data = certificate()
        self.assertEqual(data["read_checks"], 5728)
        self.assertEqual(len(data["sources"]), 16)
        self.assertEqual(data["raw_field_bytes"], data["height"] * data["width"] * 4)


if __name__ == "__main__":
    unittest.main()
