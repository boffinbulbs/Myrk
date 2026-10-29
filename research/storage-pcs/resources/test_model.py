import json
import unittest

import model


class ResourceTests(unittest.TestCase):
    def test_field_counts_match_completed_proof_record(self):
        measured = json.loads((model.ROOT / 'research/storage-pcs/validation.json').read_text())
        calculated = model.payloads(256, 2, 4)
        for execution in measured['proof_checks']:
            self.assertEqual(calculated['committed_field_file_shapes'], execution['committed_field_file_shapes'])
            self.assertEqual(calculated['committed_field_file_bytes'], execution['committed_field_bytes'])
            self.assertEqual(calculated['prepared_source_bytes'], execution['prepared_source_bytes'])
            self.assertEqual(calculated['all_field_file_bytes'], execution['total_field_bytes'])
            self.assertEqual(calculated['main_mask_field_draws'], execution['prepared_field_draws'])
        self.assertTrue(calculated['current_field_store_shape_accepts'])
        self.assertTrue(calculated['current_field_store_byte_budget_accepts'])

    def test_enumerated_tiny_file_layout(self):
        calculated = model.payloads(2, 3, 1)
        # Count actual scalar positions in the separate tiny shapes.
        prepared = [[0] * 7 for _ in range(4)]
        files = [[[0] * 7 for _ in range(32)]]
        files.extend([[[0] * 8 for _ in range(32)] for _ in range(9)])
        count = sum(1 for matrix in [prepared] + files for row in matrix for _ in row)
        self.assertEqual(calculated['all_field_file_bytes'], count * 4)
        self.assertEqual(calculated['main_preparation_scalar_window_reads'], len(prepared) * len(prepared[0]))

    def test_native_shape_exceeds_existing_limits(self):
        native = model.payloads(8192, 55049, 205201)
        self.assertEqual(native['raw_trace_bytes'], 1803845632)
        self.assertFalse(native['current_field_store_shape_accepts'])
        self.assertFalse(native['current_field_store_byte_budget_accepts'])
        self.assertGreater(native['main_query_field_payload_at_64_distinct_queries_bytes'], 2 * 1024**2)
        self.assertEqual(native['main_preparation_scalar_window_reads'], 901988352)

    def test_invalid_dimensions_are_rejected_before_calculation(self):
        for values in [(0, 2, 4), (3, 2, 4), (-2, 2, 4), (256, 0, 4),
                       (256, True, 4), (256, 2, 0), (256.0, 2, 4), (2**32, 2, 4)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                model.payloads(*values)


if __name__ == '__main__':
    unittest.main()
