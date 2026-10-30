"""Independent integer folding over F_p[X]/(X^4-11)."""
import argparse
import json
from pathlib import Path
import struct

HERE = Path(__file__).resolve().parent
P = 2013265921
COUNT = 74725
LIMIT = 1024 * 1024
ALPHA = [3, 5, 7, 11]


def canonical(value):
    if type(value) is not int or not 0 <= value < P:
        raise ValueError('canonical field element required')
    return value


def multiply(left, right):
    if len(left) != 4 or len(right) != 4:
        raise ValueError('four basis coefficients required')
    left = [canonical(value) for value in left]
    right = [canonical(value) for value in right]
    result = [0] * 4
    for i in range(4):
        for j in range(4):
            index = i + j
            result[index % 4] += left[i] * right[j] * (11 if index >= 4 else 1)
    return [value % P for value in result]


def fold(residuals, alpha=ALPHA):
    if len(alpha) != 4:
        raise ValueError('four alpha coefficients required')
    alpha = [canonical(value) for value in alpha]
    result = [0] * 4
    for residual in residuals:
        result = multiply(result, alpha)
        result[0] = (result[0] + canonical(residual)) % P
    return result


def decode(data, count=COUNT):
    if type(count) is not int or not 0 < count <= LIMIT // 4:
        raise ValueError('bounded positive count required')
    if len(data) > LIMIT or len(data) != count * 4:
        raise ValueError('exact residual length required')
    return [canonical(word[0]) for word in struct.iter_unpack('<I', data)]


def vectors():
    cases = []
    for index, length in enumerate([1, 2, 3, 4, 8, 16, 17, 31]):
        residuals = [(1234567 * (position + 1) + 97 * index) % P for position in range(length)]
        alpha = [(value + index * (i + 1)) % P for i, value in enumerate(ALPHA)]
        cases.append(dict(alpha=alpha, residuals=residuals, folded=fold(residuals, alpha)))
    return dict(format='kova.constraint-folding.extension-reference.v1', base_modulus=P,
                extension_nonresidue=11, cases=cases)


def read_bounded(path):
    if not path.is_file() or path.stat().st_size > LIMIT:
        raise ValueError('bounded regular fixture required')
    return path.read_bytes()


def validate(data, report):
    values = decode(data)
    if (report['constraints'], report['width'], report['alpha']) != (COUNT, 47058, ALPHA):
        raise ValueError('unexpected conditional source shape')
    if fold(values) != report['groups'][0]['folded'][0]:
        raise ValueError('independent fold mismatch')
    points = 0
    for group in report['groups']:
        if len(group['points']) != len(group['inverse_vanishing']):
            raise ValueError('matching selector dimensions required')
        for point, inverse in zip(group['points'], group['inverse_vanishing']):
            point, inverse = canonical(point), canonical(inverse)
            vanishing = (pow(point, 8192, P) - 1) % P
            if not vanishing or pow(vanishing, -1, P) != inverse:
                raise ValueError('inverse vanishing mismatch')
            points += 1
    if report['signature_trace_allocations'] != 0 or report['backend_proofs'] != 0:
        raise ValueError('unexpected execution scope')
    return dict(independent_residuals=len(values), inverse_vanishing_checks=points)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--write-vectors', action='store_true')
    parser.add_argument('--check', action='store_true')
    args = parser.parse_args()
    text = json.dumps(vectors(), indent=2) + '\n'
    path = HERE / 'fixtures/extension-reference.json'
    if args.write_vectors and not args.check:
        path.write_text(text, encoding='utf8', newline='\n')
    elif args.check and not args.write_vectors:
        if path.read_text(encoding='utf8') != text:
            raise SystemExit('Independent extension vectors changed')
        report = json.loads(read_bounded(HERE / 'fixtures/measurement.json'))
        print(json.dumps(validate(read_bounded(HERE / 'fixtures/residuals.bin'), report)))
    else:
        parser.error('Select --write-vectors or --check')


if __name__ == '__main__':
    main()
