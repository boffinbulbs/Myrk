"""Independent finite oracle algebra for coupled quotient observations."""
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 257
H = 8
Z = (0, 0)
O = (1, 0)


def f(a):
    return (a % P, 0)


def plus(a, b):
    return ((a[0]+b[0]) % P, (a[1]+b[1]) % P)


def minus(a):
    return ((-a[0]) % P, (-a[1]) % P)


def times(a, b):
    return ((a[0]*b[0]+3*a[1]*b[1]) % P, (a[0]*b[1]+a[1]*b[0]) % P)


def exponent(a, n):
    out = O
    while n:
        if n & 1:
            out = times(out, a)
        a = times(a, a)
        n >>= 1
    return out


def clean(a):
    a = list(a)
    while a and a[-1] == Z:
        a.pop()
    return a


def psum(a, b):
    return clean(plus(a[i] if i < len(a) else Z, b[i] if i < len(b) else Z)
                 for i in range(max(len(a), len(b))))


def scaled(a, c):
    return clean(times(x, c) for x in a)


def product(a, b):
    if not a or not b:
        return []
    out = [Z]*(len(a)+len(b)-1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] = plus(out[i+j], times(x, y))
    return clean(out)


def polynomial_power(a, n):
    out = [O]
    for _ in range(n):
        out = product(out, a)
    return out


def value(a, x):
    out = Z
    for c in reversed(a):
        out = plus(times(out, x), c)
    return out


def divide(a, b):
    assert b and b[-1] == O
    a = clean(a)
    quotient = [Z]*max(0, len(a)-len(b)+1)
    while a and len(a) >= len(b):
        k, c = len(a)-len(b), a[-1]
        quotient[k] = c
        a = psum(a, [Z]*k+scaled(b, minus(c)))
    return clean(quotient), a


def rank(rows):
    rows = [[x % P for x in row] for row in rows]
    pivot = 0
    for column in range(len(rows[0])):
        choice = next((i for i in range(pivot, len(rows)) if rows[i][column]), None)
        if choice is None:
            continue
        rows[pivot], rows[choice] = rows[choice], rows[pivot]
        inverse = pow(rows[pivot][column], -1, P)
        rows[pivot] = [(x*inverse) % P for x in rows[pivot]]
        for i, row in enumerate(rows):
            if i != pivot and row[column]:
                coefficient = row[column]
                rows[i] = [(x-coefficient*y) % P for x, y in zip(row, rows[pivot])]
        pivot += 1
        if pivot == len(rows):
            break
    return pivot


def product_zero(left, right):
    return all(sum(x*y for x, y in zip(row, column)) % P == 0
               for row in left for column in zip(*right))


def normalizers(x, roots):
    xh = exponent(x, H)
    masks = [plus(times(xh, f(pow(a, -1, P))), f(-1)) for a in roots]
    lagrange = []
    for i in range(8):
        out = f(32)
        for j, z in enumerate(masks):
            if i != j:
                out = times(out, z)
        lagrange.append(out)
    return masks, lagrange


def observation_maps(queries, roots, independent=False, last_weight=1):
    points = [(0, 1)]+[f(x) for x in queries]
    count = 2+len(queries)
    columns = 8*(8 if independent else 7)
    masks = [[0]*columns for _ in range(8*count)]
    recomposition = [[0]*(8*count) for _ in range(count)]
    for n, x in enumerate(points):
        zs, ls = normalizers(x, roots)
        for chunk in range(8):
            start = chunk*count
            if n == 0:
                a, b = ls[chunk]
                recomposition[0][start], recomposition[0][start+1] = a, 3*b % P
                recomposition[1][start], recomposition[1][start+1] = b, a
            else:
                assert ls[chunk][1] == 0
                recomposition[n+1][start+n+1] = ls[chunk][0]
        for bank in range(8 if independent else 7):
            for k in range(H):
                column = bank*H+k
                destinations = [(bank, O)] if independent else [(bank, O), (7, f(-last_weight))]
                for chunk, weight in destinations:
                    observed = times(times(zs[chunk], exponent(x, k)), weight)
                    row = chunk*count+(0 if n == 0 else n+1)
                    masks[row][column] = observed[0]
                    if n == 0:
                        masks[row+1][column] = observed[1]
    return masks, recomposition


def main_map(queries, generator, translates=True):
    points = [(0, 1), (0, generator)]
    for x in queries:
        points.append(f(x))
        if translates:
            points.append(f(x*generator))
    rows = []
    for x in points:
        factor = plus(exponent(x, H), f(-1))
        assert factor != Z
        evaluations = [times(factor, exponent(x, k)) for k in range(H)]
        rows.append([a for a, _ in evaluations])
        if x[1]:
            rows.append([b for _, b in evaluations])
    return rows


def run():
    fixture = json.loads((HERE/'fixtures/literals.json').read_bytes())
    assert fixture['format'] == 'kova.joint-observation.literals.v1'
    assert pow(3, 128, P) == 256
    generator = pow(3, 32, P)
    roots = [pow(3*pow(81, i, P) % P, H, P) for i in range(8)]
    assert generator == fixture['trace_generator'] == 64
    assert roots == fixture['chunk_powers']
    assert (-pow(8, -1, P)) % P == fixture['normalizer'] == 32
    physical = [3*pow(9, i, P) % P for i in range(128)]
    construction = {3*pow(81, i, P) % P for i in range(64)}
    assert len(set(physical)) == 128 and len(construction) == 64
    assert construction < set(physical)

    # This synthetic AIR has quartic and affine transition assertions.
    raw = [f(2), O]
    vanishing = [f(-1)]+[Z]*7+[O]
    mask = [f(i) for i in range(1, 9)]
    main = psum(raw, product(vanishing, mask))
    second = psum(polynomial_power(raw, 4), scaled(vanishing, f(5)))
    quartic, remainder = divide(psum(polynomial_power(main, 4), scaled(second, f(-1))), vanishing)
    assert not remainder
    following = [times(c, f(pow(generator, i, P))) for i, c in enumerate(main)]
    transition_numerator = psum(psum(following, scaled(main, f(-generator))), [f(-2*(1-generator))])
    transition, remainder = divide(transition_numerator, vanishing)
    assert not remainder
    assert (len(quartic)-1, quartic[-1][0], quartic[0][0], value(quartic, O)[0]) == tuple(fixture['quartic_literals'])
    assert transition[0] == f(194)
    z = (0, 1)
    coordinates = [value(transition, z), value(quartic, z)]
    assert coordinates == [tuple(x) for x in fixture['coordinate_claims']]
    combined = plus(coordinates[0], times(z, coordinates[1]))
    assert combined == tuple(fixture['combined_claim'])

    anchor = nonanchor = 0
    for x in physical:
        zs, ls = normalizers(f(x), roots)
        assert sum(a for a, b in ls) % P == 1 and all(b == 0 for a, b in ls)
        zero = [i for i, a in enumerate(zs) if a == Z]
        assert len(zero) == (1 if x in construction else 0)
        matrices, reconstruction = observation_maps([x], roots)
        assert rank(matrices) == 21 and rank(reconstruction) == 3
        assert product_zero(reconstruction, matrices)
        if zero:
            anchor += 1
            row = zero[0]*3+2
            assert not any(matrices[row]) and ls[zero[0]] == O
        else:
            nonanchor += 1
    assert (anchor, nonanchor) == (64, 64)
    joint, reconstruction = observation_maps([3, 27], roots)
    assert (rank(joint), rank(reconstruction)) == (28, 4)
    assert product_zero(reconstruction, joint)
    main_ranks = [rank(main_map(q, generator)) for q in ([3], [27], [3, 27])]
    assert main_ranks == fixture['main_ranks'] == [6, 6, 8]

    # Each alternative changes an actual algebraic conditioning or relation.
    _, ls = normalizers(f(3), roots)
    assert sum(a*pow(32, -1, P) for a, _ in ls) % P != 1
    independent, reconstruction = observation_maps([3, 27], roots, independent=True)
    assert not product_zero(reconstruction, independent)
    wrong_coupling, reconstruction = observation_maps([3, 27], roots, last_weight=2)
    assert not product_zero(reconstruction, wrong_coupling)
    assert rank(main_map([3], generator, translates=False)) == 5
    mz = [f(-3), Z, O]
    mgz = [f(-3*generator*generator), Z, O]
    missing = product(product(mz, mgz), [f(-3), O])
    assert value(missing, f(3)) == value(missing, z) == value(missing, (0, generator)) == Z
    assert value(missing, f(3*generator)) != Z
    assert any(c[1] for c in coordinates)
    assert (f(combined[0]), f(combined[1])) != tuple(coordinates)
    swapped = plus(coordinates[1], times(z, coordinates[0]))
    assert swapped == tuple(fixture['swapped_claim']) and swapped != combined
    alias = [f(-241)]+[Z]*63+[O]
    assert all(value(alias, f(x)) == Z for x in construction)
    assert value(alias, f(27)) == f(32) and value(alias, z) == f(80)
    assert len(psum(quartic, alias))-1 >= 64 > len(quartic)-1
    matrices, reconstruction = observation_maps([3], roots)
    assert not any(matrices[2]) and product_zero(reconstruction, matrices)
    # Restored source relations above are unchanged by these alternate constructions.
    assert rank(joint) == 28 and main_ranks == [6, 6, 8]

    return dict(format='kova.joint-observation.reference.v1', prime=P, raw_height=H,
                chunks=8, physical_points=128, anchors=anchor, nonanchors=nonanchor,
                single_query_rank=21, single_recomposition_rank=3,
                joint_rank=28, joint_recomposition_rank=4, main_ranks=main_ranks,
                honest_quotient_degree=len(quartic)-1, construction_degree_bound=64,
                hostile_alternatives=8, kova_runtime_calls=0, cryptographic_proofs=0)


if __name__ == '__main__':
    if not __debug__ or os.environ.get('KOVA_JOINT_OBSERVATION_GATE') != 'reviewed-external-resource-admission':
        raise RuntimeError('A separate finite reference admission is required')
    result = run()
    with (HERE/'results/reference-v1.json').open('x', encoding='utf8', newline='\n') as output:
        output.write(json.dumps(result, sort_keys=True, separators=(',', ':'))+'\n')
    print(json.dumps(result, sort_keys=True))
