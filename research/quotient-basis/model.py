"""Finite independent integer quotient-basis reference. No proof implementation."""
import itertools
import json
import os
from pathlib import Path
import re

HERE = Path(__file__).resolve().parent
P, H, C = 17, 2, 4


def trim(poly):
    out = [x % P for x in poly]
    while len(out) > 1 and out[-1] == 0:
        out.pop()
    return out or [0]


def add(a, b):
    return trim([(a[i] if i < len(a) else 0) + (b[i] if i < len(b) else 0)
                 for i in range(max(len(a), len(b)))])


def scale(a, scalar):
    return trim([x * scalar for x in a])


def mul(a, b):
    out = [0] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] = (out[i+j] + x*y) % P
    return trim(out)


def at(poly, x):
    out = 0
    for coefficient in reversed(poly):
        out = (out*x + coefficient) % P
    return out


def remainder(poly, divisor):
    out = trim(poly)
    while len(out) >= len(divisor) and out != [0]:
        factor = out[-1] * pow(divisor[-1], -1, P) % P
        shifted = [0] * (len(out)-len(divisor)) + scale(divisor, factor)
        out = add(out, scale(shifted, -1))
    return out


def transform(matrix, polynomials):
    rows = []
    for row in matrix:
        total = [0]
        for scalar, poly in zip(row, polynomials, strict=True):
            total = add(total, scale(poly, scalar))
        rows.append(total)
    return rows


def weights(shifts, height=H):
    z = [[-1] + [0]*(height-1) + [pow(pow(x, height, P), -1, P)] for x in shifts]
    basis, normalizers = [], []
    for i, x in enumerate(shifts):
        numerator, denominator = [1], 1
        for j, poly in enumerate(z):
            if i != j:
                numerator = mul(numerator, poly)
                denominator = denominator * at(poly, x) % P
        normalizer = pow(denominator, -1, P)
        basis.append(scale(numerator, normalizer))
        normalizers.append(normalizer)
    return z, basis, normalizers


def reconstruct(basis, chunks):
    total = [0]
    for weight, chunk in zip(basis, chunks, strict=True):
        total = add(total, mul(weight, chunk))
    return total


def segments_reconstruct(segments, spacing=H):
    total = [0]
    for i, poly in enumerate(segments):
        total = add(total, [0]*(spacing*i) + poly)
    return total


def run():
    with (HERE/'fixtures/literals.json').open('rb') as source:
        raw = source.read(8193)
    assert len(raw) <= 8192
    fixture = json.loads(raw)
    assert [fixture[k] for k in ('field', 'height', 'chunks', 'generator', 'domain_generator')] == [17, 2, 4, 3, 9]
    shifts, roots = fixture['shifts'], fixture['roots']
    assert shifts == [3 * pow(9, i, P) % P for i in range(C)]
    assert roots == [pow(x, H, P) for x in shifts]
    v, inverse = fixture['vandermonde'], fixture['inverse']
    assert v == [[pow(a, j, P) for j in range(C)] for a in roots]
    assert inverse == [[pow(C, -1, P)*pow(a, -j, P) % P for a in roots] for j in range(C)]
    for left, right in ((v, inverse), (inverse, v)):
        assert [[sum(left[i][k]*right[k][j] for k in range(C)) % P for j in range(C)] for i in range(C)] == [[int(i == j) for j in range(C)] for i in range(C)]
    polynomial = fixture['polynomial']
    chunks = [remainder(polynomial, [-a, 0, 1]) for a in roots]
    assert chunks == fixture['remainders']
    assert transform(inverse, chunks) == fixture['segments']
    z, basis, normalizers = weights(shifts)
    assert normalizers == fixture['normalizers'] == [4]*C
    assert reconstruct(basis, chunks) == polynomial
    masks = fixture['masks']
    transformed = transform(inverse, masks)
    assert transformed == [trim(p) for p in fixture['transformed_masks']]
    masked = [add(chunk, mul(zero, mask)) for chunk, zero, mask in zip(chunks, z, masks, strict=True)]
    assert masked == fixture['masked_chunks']
    segment_masks = transform(inverse, masked)
    assert segment_masks == [trim(p) for p in fixture['masked_segments']]
    telescoping = []
    for j, segment in enumerate(fixture['segments']):
        upper = [0]*H + transformed[j+1] if j+1 < C else [0]
        telescoping.append(add(segment, add(upper, scale(transformed[j], -1))))
    assert segment_masks == telescoping
    assert reconstruct(basis, masked) == segments_reconstruct(segment_masks) == polynomial
    image = set()
    for free in itertools.product(range(P), repeat=C-1):
        coefficient = [*free, -sum(free) % P]
        output = [sum(row[i]*coefficient[i] for i in range(C)) % P for row in inverse]
        assert output[0] == 0
        image.add(tuple(output[1:]))
    assert len(image) == fixture['coefficient_image'] == 4913
    rejected, restored = [], 0
    def control(name, actual):
        nonlocal restored
        assert actual != polynomial, name
        rejected.append(name)
        assert reconstruct(basis, masked) == segments_reconstruct(segment_masks) == polynomial
        restored += 1
    monic = [[-a, 0, 1] for a in roots]
    control('mixed_normalization', reconstruct(basis, [add(q, mul(z, t)) for q, z, t in zip(chunks, monic, masks, strict=True)]))
    uncoupled = [add(q, mul(z, t)) for q, z, t in zip(chunks, z, [*masks[:3], [0]], strict=True)]
    control('uncoupled_mask', reconstruct(basis, uncoupled))
    control('permuted_chunks', reconstruct(basis, [masked[1], masked[0], *masked[2:]]))
    control('transposed_transform', segments_reconstruct(transform(list(map(list, zip(*inverse))), masked)))
    control('wrong_segment_spacing', segments_reconstruct(segment_masks, 1))
    changed = [[*row] for row in masked]
    changed[0][0] = (changed[0][0]+1) % P
    control('altered_chunk', reconstruct(basis, changed))
    try:
        weights(shifts, 2*H)
    except ValueError:
        rejected.append('overlapping_masked_domains')
        assert reconstruct(basis, masked) == polynomial
        restored += 1
    else:
        raise AssertionError('overlapping domains accepted')
    return dict(format='kova.quotient-basis.reference.v1', field=P, height=H, chunks=C,
                normalizers=normalizers, transformed_masks=transformed,
                masked_segments=segment_masks, coefficient_image=len(image),
                coefficient_tuples_enumerated=4913, adversarial_controls=rejected,
                restored_positive_checks=restored, production_field_runs=0,
                commitments=0, transcripts=0, proofs=0, security_scores=0)


if __name__ == '__main__':
    if not __debug__ or os.environ.get('KOVA_QUOTIENT_BASIS_GATE') != 'reviewed-external-resource-admission':
        raise RuntimeError('Finite reference admission required')
    name = os.environ['KOVA_QUOTIENT_BASIS_OUTPUT']
    assert re.fullmatch(r'[a-z0-9-]{1,60}\.json', name)
    encoded = json.dumps(run(), sort_keys=True, separators=(',', ':')).encode()
    assert len(encoded) <= 4096
    with (HERE/'results'/name).open('xb') as output:
        output.write(encoded)
    print(encoded.decode())
