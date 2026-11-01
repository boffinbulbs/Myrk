"""Finite integer reference for a conditional auxiliary isolation sublemma."""
from collections import Counter
from itertools import product
import json
import os
from pathlib import Path

HERE = Path(__file__).resolve().parent
P = 17
ZERO = (0, 0)
ONE = (1, 0)


def base(n):
    return (n % P, 0)


def add(a, b):
    return ((a[0] + b[0]) % P, (a[1] + b[1]) % P)


def neg(a):
    return ((-a[0]) % P, (-a[1]) % P)


def mul(a, b):
    return ((a[0]*b[0] + 3*a[1]*b[1]) % P,
            (a[0]*b[1] + a[1]*b[0]) % P)


def power(a, n):
    result = ONE
    while n:
        if n & 1:
            result = mul(result, a)
        a = mul(a, a)
        n >>= 1
    return result


def trim(poly):
    poly = list(poly)
    while poly and poly[-1] == ZERO:
        poly.pop()
    return tuple(poly)


def padd(a, b):
    return trim(add(a[i] if i < len(a) else ZERO,
                    b[i] if i < len(b) else ZERO)
                for i in range(max(len(a), len(b))))


def scale(a, c):
    return trim(mul(x, c) for x in a)


def pmul(a, b):
    if not a or not b:
        return ()
    out = [ZERO] * (len(a) + len(b) - 1)
    for i, x in enumerate(a):
        for j, y in enumerate(b):
            out[i+j] = add(out[i+j], mul(x, y))
    return trim(out)


def evaluate(a, x):
    result = ZERO
    for c in reversed(a):
        result = add(mul(result, x), c)
    return result


def divide(a, b):
    assert b and b[-1] == ONE
    remainder = trim(a)
    quotient = [ZERO] * max(0, len(a) - len(b) + 1)
    while remainder and len(remainder) >= len(b):
        position = len(remainder) - len(b)
        coefficient = remainder[-1]
        quotient[position] = coefficient
        subtract = (ZERO,) * position + scale(b, neg(coefficient))
        remainder = padd(remainder, subtract)
    return trim(quotient), remainder


def linear(z):
    return (neg(z), ONE)


def divided_difference(a, z):
    quotient, remainder = divide(padd(a, (neg(evaluate(a, z)),)), linear(z))
    assert not remainder
    return quotient


def lift_literal(values):
    return trim(tuple(x) if isinstance(x, list) else base(x) for x in values)


def run():
    raw = (HERE/'fixtures/literals.json').read_bytes()
    assert len(raw) < 16384
    fixture = json.loads(raw)
    assert fixture['format'] == 'kova.joint-hiding.literals.v1'
    assert (fixture['prime'], fixture['nonresidue'], fixture['degree_bound']) == (17, 3, 8)
    assert pow(3, 8, 17) == 16
    z = (0, 1)
    conjugate = (0, 16)
    translated = mul(base(4), z)
    query = base(3)
    minimum = pmul(linear(z), linear(conjugate))
    translated_minimum = pmul(linear(translated), linear(neg(translated)))
    vanishing = pmul(minimum, linear(query))
    witness_delta = pmul(vanishing, translated_minimum)
    kernel, remainder = divide(vanishing, linear(z))
    current = divided_difference(witness_delta, z)
    following = divided_difference(witness_delta, translated)
    assert not remainder
    actual = dict(vanishing=vanishing, witness_delta=witness_delta,
                  kernel=kernel, current=current, following=following)
    assert all(actual[name] == lift_literal(fixture[name]) for name in actual)
    assert all(evaluate(witness_delta, x) == ZERO for x in (z, translated, query))
    assert all(c[1] == 0 for c in vanishing + witness_delta)
    assert len(witness_delta) <= 8

    full = proper = basis_cases = translated_coverage = deficient_shifts = 0
    for alpha in product(range(P), repeat=2):
        assert power(alpha, P) == (alpha[0], (-alpha[1]) % P)
        images = Counter(add(base(a), mul(base(b), alpha))
                         for a, b in product(range(P), repeat=2))
        basis_cases += P*P
        shift = padd(scale(current, power(alpha, 4)),
                     scale(following, power(alpha, 8)))
        target, remainder = divide(shift, kernel)
        assert not remainder
        if alpha[1]:
            full += 1
            assert len(images) == P*P and set(images.values()) == {1}
            # Solve the actual basis (1, alpha), not a supplied fixed basis.
            left, right = [], []
            for c in target:
                b = c[1] * pow(alpha[1], -1, P) % P
                a = (c[0] - b*alpha[0]) % P
                assert add(base(a), mul(base(b), alpha)) == c
                left.append(base(a))
                right.append(base(b))
            aux0 = pmul(vanishing, left)
            aux1 = pmul(vanishing, right)
            assert len(aux0) <= 8 and len(aux1) <= 8
            assert all(evaluate(a, x) == ZERO for a in (aux0, aux1) for x in (z, query))
            reduced = padd(divided_difference(aux0, z),
                           scale(divided_difference(aux1, z), alpha))
            assert reduced == shift
            translated_coverage += 1
        else:
            proper += 1
            assert len(images) == P and set(images.values()) == {P}
            if alpha != ZERO:
                assert any(c[1] for c in target)
                deficient_shifts += 1
            else:
                assert not shift
    assert (full, proper, basis_cases, translated_coverage, deficient_shifts) == (272, 17, 83521, 272, 16)

    alpha = z
    powers = [power(alpha, i) for i in range(4)]
    images = Counter()
    for coefficients in product(range(P), repeat=4):
        value = ZERO
        for c, a in zip(coefficients, powers):
            value = add(value, mul(base(c), a))
        images[value] += 1
    assert len(images) == 289 and set(images.values()) == {289}

    for mode in range(5):
        monomial = (ZERO,) * mode + (ONE,)
        aux0 = scale(pmul(vanishing, monomial), base(5))
        aux1 = scale(pmul(vanishing, monomial), base(7))
        assert all(evaluate(a, x) == ZERO for a in (aux0, aux1) for x in (z, query))
        assert padd(divided_difference(aux0, z), scale(divided_difference(aux1, z), alpha)) == scale(pmul(kernel, monomial), (5, 7))

    shift = padd(current, following)
    shift_coordinates, remainder = divide(shift, kernel)
    assert not remainder and shift_coordinates == lift_literal(fixture['base_alpha_shift'])
    # Each alternate below violates a concrete original conditioning or equation.
    omit_conjugate = pmul(linear(z), linear(query))
    assert evaluate(omit_conjugate, conjugate) != ZERO
    assert evaluate(vanishing, conjugate) == ZERO
    assert evaluate(minimum, query) != ZERO
    assert evaluate(vanishing, query) == ZERO
    composite_only = padd((base(-3),), scale((ZERO, ONE), z))
    assert evaluate(composite_only, z) == ZERO
    assert evaluate((base(-3),), z) != ZERO and evaluate((ZERO, ONE), z) != ZERO
    assert evaluate(vanishing, z) == ZERO
    assert (0, 1) not in {add(base(a), base(b)) for a, b in product(range(P), repeat=2)}
    assert (0, 1) in {add(base(a), mul(base(b), z)) for a, b in product(range(P), repeat=2)}
    assert any(c[1] for c in shift_coordinates)
    assert divided_difference(witness_delta, z) != lift_literal(fixture['following'])
    assert divided_difference(witness_delta, translated) == lift_literal(fixture['following'])
    assert pmul(linear(z), scale(current, base(-1))) != witness_delta
    assert pmul(linear(z), current) == witness_delta

    return dict(format='kova.joint-hiding.reference.v1', prime=P, extension_degree=2,
                degree_bound=8, literal_polynomials=6, alpha_values=289,
                full_rank=full, proper_subfield=proper, basis_cases=basis_cases,
                four_column_assignments=83521, four_column_images=len(images),
                equal_fibers=289, polynomial_modes=5,
                translated_coverage=translated_coverage,
                deficient_conditional_shifts=deficient_shifts,
                hostile_alternatives=6, restored_checks=6,
                kova_runtime_calls=0, cryptographic_proofs=0)


if __name__ == '__main__':
    if not __debug__ or os.environ.get('KOVA_JOINT_HIDING_GATE') != 'reviewed-external-resource-admission':
        raise RuntimeError('A separate reviewed finite reference admission is required')
    result = run()
    with (HERE/'results/reference-v1.json').open('x', encoding='utf8', newline='\n') as output:
        output.write(json.dumps(result, sort_keys=True, separators=(',', ':')) + '\n')
    print(json.dumps(result, sort_keys=True))
