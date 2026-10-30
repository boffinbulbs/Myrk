import unittest
import compare

class CostTests(unittest.TestCase):
    def test_fewer_assertions_preserve_field_storage_limits(self):
        before = compare.costs(8192, 47058, 4, 181221)
        after = compare.costs(8192, 47058, 4, 74725)
        self.assertEqual(after['constraint_row_positions'], 4897177600)
        self.assertLess(after['constraint_row_positions'], before['constraint_row_positions'])
        for name in ['all_field_file_bytes', 'field_file_count', 'main_query_payload_at_64_distinct_indices_bytes']:
            self.assertEqual(after[name], before[name])
        self.assertFalse(after['current_shape_limit_accepts'])
        self.assertFalse(after['current_two_mib_field_limit_accepts'])

    def test_reference_profile_and_factorized_file_gate(self):
        previous = compare.costs(8192, 55049, 4, 205201)
        current = compare.costs(8192, 47049, 6, 181203)
        self.assertEqual(previous['raw_trace_bytes'], 1803845632)
        self.assertEqual(previous['all_field_file_bytes'], 32509329408)
        self.assertEqual(previous['quotient_chunks'], 8)
        self.assertEqual(current['quotient_chunks'], 16)
        self.assertGreater(current['constraint_row_positions'], previous['constraint_row_positions'])
        self.assertLess(current['raw_trace_bytes'], previous['raw_trace_bytes'])
        self.assertEqual(current['field_file_count'], 19)
        self.assertFalse(current['current_sixteen_file_limit_accepts'])
        self.assertFalse(current['current_shape_limit_accepts'])
        bound = compare.costs(8192,47058,4,181221)
        self.assertEqual(bound['quotient_chunks'],previous['quotient_chunks'])
        self.assertEqual(bound['field_file_count'],11)
        self.assertTrue(bound['current_sixteen_file_limit_accepts'])
        self.assertLess(bound['constraint_row_positions'],previous['constraint_row_positions'])
        self.assertFalse(bound['current_shape_limit_accepts'])

    def test_degree_boundary_changes_quotient_domain(self):
        for degree, chunks in [(2, 4), (3, 8), (4, 8), (5, 16), (6, 16), (8, 16), (9, 32)]:
            with self.subTest(degree=degree):
                result = compare.costs(32, 12, degree, 100)
                self.assertEqual(result['quotient_chunks'], chunks)
                self.assertEqual(result['retained_blowup_eight_covers_domain'], degree <= 8)

    def test_invalid_shapes_are_refused(self):
        for values in [(0, 2, 4, 10), (3, 2, 4, 10), (32, True, 4, 10), (32, 2, 0, 10), (32, 2, 2**32, 10)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                compare.costs(*values)

if __name__ == '__main__':
    unittest.main()
