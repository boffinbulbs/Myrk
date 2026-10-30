import copy
import json
import struct
import unittest

import reference


class ReferenceTests(unittest.TestCase):
    def test_extension_relation_and_fold_order(self):
        self.assertEqual(reference.multiply([0, 0, 0, 1], [0, 1, 0, 0]), [11, 0, 0, 0])
        self.assertEqual(reference.fold([3, 5], [0, 1, 0, 0]), [5, 3, 0, 0])
        self.assertEqual(reference.fold([reference.P - 1, 1], [0, 1, 0, 0]), [1, reference.P - 1, 0, 0])

    def test_canonical_decoder_and_shape_limits(self):
        self.assertEqual(reference.decode(struct.pack('<I', reference.P - 1), 1), [reference.P - 1])
        for data, count in [(b'\x00', 1), (b'\x00' * 8, 1), (struct.pack('<I', reference.P), 1),
                            (b'', 0), (b'', True), (b'', 2**32)]:
            with self.subTest(count=count), self.assertRaises(ValueError):
                reference.decode(data, count)
        for alpha in [[1, 2], [1, 2, 3, -1], [1, 2, 3, reference.P], [1, 2, 3, True]]:
            with self.subTest(alpha=alpha), self.assertRaises(ValueError):
                reference.fold([1], alpha)

    def test_changed_residual_and_alpha_disagree(self):
        path = reference.HERE / 'fixtures'
        data = bytearray(reference.read_bounded(path / 'residuals.bin'))
        report = json.loads(reference.read_bounded(path / 'measurement.json'))
        reference.validate(data, report)
        data[0] ^= 1
        with self.assertRaises(ValueError):
            reference.validate(data, report)
        changed = copy.deepcopy(report)
        changed['alpha'][0] += 1
        with self.assertRaises(ValueError):
            reference.validate(reference.read_bounded(path / 'residuals.bin'), changed)

    def test_changed_inverse_vanishing_rejects(self):
        path = reference.HERE / 'fixtures'
        report = json.loads(reference.read_bounded(path / 'measurement.json'))
        report['groups'][0]['inverse_vanishing'][0] ^= 1
        with self.assertRaises(ValueError):
            reference.validate(reference.read_bounded(path / 'residuals.bin'), report)


if __name__ == '__main__':
    unittest.main()
