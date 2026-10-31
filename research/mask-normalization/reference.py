"""Dormant independent integer mask reference. No cryptography imports."""
import json

P = 2013265921
SHIFT = 31
ROOT_2048 = 0x4FE61226
ROWS = 256
WIDTH = 8
CHUNKS = 8
MAX_INPUT = 65536
MAX_REPORT = 16384

def field(value):
    if type(value) is not int or not 0 <= value < P:
        raise ValueError('Noncanonical literal field')
    return value

def vector(value, length):
    if type(value) is not list or len(value) != length:
        raise ValueError('Invalid fixed vector shape')
    return [field(v) for v in value]

def inverse(value):
    if value % P == 0:
        raise ValueError('Zero normalizer denominator')
    return pow(value, P - 2, P)

def recipe(chunk, row, column):
    # This is a public deterministic test bank, never production entropy.
    if row == 0 and column == 0:
        return 0
    if row == ROWS - 1 and column == WIDTH - 1:
        return P - 1
    return (11 + 23 * chunk + 9 * row + 17 * column) % P

def normalizers(domains, monic=False):
    powers = [pow(a, ROWS, P) for a in domains]
    result = []
    for i in range(CHUNKS):
        product = 1
        for j in range(CHUNKS):
            if i == j:
                continue
            # The actual normalized coset polynomial is (x/a_j)^h - 1.
            term = powers[i] - powers[j] if monic else powers[i] * inverse(powers[j]) - 1
            product = product * term % P
        result.append(inverse(product))
    return result

def final_bank(cis, sign=-1, omit_added=False):
    weights = [c * inverse(cis[7]) % P for c in cis[:7]]
    result = []
    for row in range(ROWS):
        for column in range(WIDTH):
            value = sign * sum(weights[i] * recipe(i, row, column) for i in range(7)) % P
            result.append(0 if omit_added and column >= 4 else value)
    return result

def differences(a, b):
    if len(a) != len(b):
        raise ValueError('Mismatched comparison dimensions')
    return sum(x != y for x, y in zip(a, b))

def compare(raw):
    if type(raw) is not bytes or len(raw) > MAX_INPUT:
        raise ValueError('Input exceeds fixed class')
    data = json.loads(raw)
    if type(data) is not dict or set(data) != {'format', 'domains', 'normalizers', 'final_bank', 'recipe'}:
        raise ValueError('Unexpected capture fields')
    if data['format'] != 'kova.mask-normalization.capture.v1' or data['recipe'] != 'edge-affine-v1':
        raise ValueError('Unexpected capture identity')
    actual_domains = vector(data['domains'], 8)
    actual_cis = vector(data['normalizers'], 8)
    actual_final = vector(data['final_bank'], ROWS * WIDTH)
    if pow(ROOT_2048, 2048, P) != 1 or pow(ROOT_2048, 1024, P) == 1:
        raise ValueError('Literal root order mismatch')
    domains = [SHIFT * pow(ROOT_2048, i, P) % P for i in range(CHUNKS)]
    cis = normalizers(domains)
    expected = final_bank(cis)
    residuals = []
    for row in range(ROWS):
        for column in range(WIDTH):
            k = row * WIDTH + column
            residuals.append((sum(cis[i] * recipe(i, row, column) for i in range(7))
                              + cis[7] * actual_final[k]) % P)
    controls = {
        'reversed_reported_domain_order': differences(domains, list(reversed(domains))),
        'monic_normalizer_values': differences(cis, normalizers(domains, monic=True)),
        'monic_final_coupling': differences(expected, final_bank(normalizers(domains, monic=True))),
        'wrong_final_sign': differences(expected, final_bank(cis, sign=1)),
        'omitted_random_column_masks': differences(expected, final_bank(cis, omit_added=True)),
        'zero_final_bank': differences(expected, [0] * (ROWS * WIDTH)),
    }
    # Equal-size normalized subcosets have equal normalizers. Reordering just
    # the normalizer vector or omitting a common factor need not change the
    # final coupling. Those degenerate mutations are not separation claims.
    report = {
        'format': 'kova.mask-normalization.reference.v1',
        'domain_order_equal': actual_domains == domains,
        'normalizers_equal': actual_cis == cis,
        'final_bank_equal': actual_final == expected,
        'zero_residual_coordinates': sum(v == 0 for v in residuals),
        'coordinates_compared': ROWS * WIDTH,
        'literal_zero_inputs': CHUNKS - 1,
        'literal_modulus_minus_one_inputs': CHUNKS - 1,
        'normalizers_all_equal': len(set(cis)) == 1,
        'controls': controls,
        'all_selected_controls_separate': all(v > 0 for v in controls.values()),
        'scope': 'Conditional arithmetic for one public deterministic mask bank, no randomness or proof test',
    }
    encoded = json.dumps(report, sort_keys=True).encode()
    if len(encoded) > MAX_REPORT:
        raise ValueError('Report exceeds fixed class')
    return report
