import copy
import json
import unittest

import reference


class ProfileTests(unittest.TestCase):
    def setUp(self):
        self.record = json.loads((reference.HERE / 'fixtures/report.json').read_text(encoding='utf8'))

    def test_known_storage_identity_and_query_effect(self):
        self.assertEqual(reference.cost(4, 4, 64)['all_field_bytes'], 27796045824)
        self.assertEqual(reference.cost(8, 8, 128)['all_field_bytes'], 27836153856)
        before, after = reference.cost(4, 4, 64), reference.cost(4, 4, 128)
        self.assertEqual(before['all_field_bytes'], after['all_field_bytes'])
        self.assertEqual(after['main_query_field_bytes_at_distinct_indices'], 2 * before['main_query_field_bytes_at_distinct_indices'])

    def test_weak_masks_and_invalid_dimensions_reject(self):
        for values in [(8, 4, 64), (4, 4, 0), (4, 4, 4096), (8, 8, 2**64), (4, 2**64, 64), (0, 4, 64), (True, 4, 64)]:
            with self.subTest(values=values), self.assertRaises(ValueError):
                reference.cost(*values)

    def test_false_batch_count_and_cost_reject(self):
        reference.validate(self.record)
        for field in ['batched_opening_functions', 'challenge_field_bits_floor']:
            changed = copy.deepcopy(self.record)
            changed['reports'][1][field] = 1
            with self.assertRaises(ValueError):
                reference.validate(changed)
        self.record['reports'][1]['costs']['all_field_bytes'] -= 1
        with self.assertRaises(ValueError):
            reference.validate(self.record)

    def test_model_is_not_a_quantum_or_knowledge_certificate(self):
        for flag in ['parameter_selection', 'quantum_security_established', 'knowledge_soundness_established']:
            changed = copy.deepcopy(self.record)
            changed[flag] = True
            with self.subTest(flag=flag), self.assertRaises(ValueError):
                reference.validate(changed)
        first, second = self.record['reports'][:2]
        self.assertEqual(first['library_classical_rbr_bits'], second['library_classical_rbr_bits'])
        self.assertNotEqual(first['constraints'], second['constraints'])


if __name__ == '__main__':
    unittest.main()
