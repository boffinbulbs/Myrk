"""Independent integer quotient comparison for fixed synthetic captures.

This file has no command line entry point and accepts no paths or callbacks.
Inputs must come from the separately recorded actual construction capture.
The comparison is arithmetic evidence, never AIR or proof acceptance.

Formula attribution: Plonky3 0.8.0, MIT OR Apache-2.0, upstream
https://github.com/Plonky3/Plonky3 at a21e3ed42905040ad49c519e402f018381c12d0c.
See SOURCE-EVIDENCE.md for exact source pins and independence limitations.
The implementation below is an independent schoolbook integer derivation.
It does not import upstream arithmetic, a producer, a folder, Rust, or FFI.
"""

import json


P = 0x78000001
N = 256
Q = 2048
TRACE_ROOT = 0x67456167
QUOTIENT_ROOT = 0x4FE61226
SHIFT = 31
MAX_INPUT_BYTES = 196608
MAX_OUTPUT_BYTES = 16384


def _fail():
    raise ValueError("invalid bounded literal input")


def _integer(token):
    # Positive canonical decimal fields and fixed metadata fit ten digits.
    if not 1 <= len(token) <= 10 or not token.isascii() or not token.isdecimal():
        _fail()
    if len(token) > 1 and token[0] == "0":
        _fail()
    return int(token)


def _noninteger(token):
    _fail()


def _object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _fail()
        result[key] = value
    return result


def _canonical(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode("ascii")


def _field(value):
    if type(value) is not int or not 0 <= value < P:
        _fail()


def _matrix(value, width):
    if type(value) is not list or len(value) != Q:
        _fail()
    for row in value:
        if type(row) is not list or len(row) != width:
            _fail()
        for field in row:
            _field(field)


def _parse(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= MAX_INPUT_BYTES:
        _fail()
    # The accepted schema has no escapes and nesting depth at most three.
    # Reject oversized nesting before invoking the JSON parser.
    if any(byte > 127 or byte == 92 for byte in raw):
        _fail()
    depth = 0
    quoted = False
    for byte in raw:
        if byte == 34:
            quoted = not quoted
        elif not quoted:
            if byte in (91, 123):
                depth += 1
                if depth > 3:
                    _fail()
            elif byte in (93, 125):
                depth -= 1
                if depth < 0:
                    _fail()
    if quoted or depth != 0:
        _fail()
    obj = json.loads(raw, parse_int=_integer, parse_float=_noninteger,
                     parse_constant=_noninteger, object_pairs_hook=_object)
    if type(obj) is not dict or set(obj) != {
        "alpha", "candidate", "capture_receipt_sha256", "field", "main",
        "public", "quotient_domain", "schema", "trace_domain",
    }:
        _fail()
    if obj["schema"] != "kova-quartic-quotient-reference-v40-input":
        _fail()
    if obj["field"] != "babybear-power-basis-x4-minus11":
        _fail()
    for key, expected in (("trace_domain", {"height": N, "shift": 1}),
                          ("quotient_domain", {"height": Q, "shift": SHIFT})):
        domain = obj[key]
        if type(domain) is not dict or domain != expected:
            _fail()
        if any(type(value) is not int for value in domain.values()):
            _fail()
    receipt = obj["capture_receipt_sha256"]
    if type(receipt) is not str or len(receipt) != 64:
        _fail()
    if any(char not in "0123456789abcdef" for char in receipt):
        _fail()
    if type(obj["public"]) is not list or obj["public"] != [5, 260]:
        _fail()
    for value in obj["public"]:
        _field(value)
    if type(obj["alpha"]) is not list or len(obj["alpha"]) != 4:
        _fail()
    for value in obj["alpha"]:
        _field(value)
    _matrix(obj["main"], 2)
    _matrix(obj["candidate"], 4)
    if _canonical(obj) != raw:
        _fail()
    return obj


def _power(base, exponent):
    # Only fixed exponents bounded by P - 2 or Q are passed internally.
    result = 1
    while exponent:
        if exponent & 1:
            result = result * base % P
        base = base * base % P
        exponent >>= 1
    return result


def _inverse(value):
    value %= P
    if value == 0:
        raise ValueError("zero denominator in fixed disjoint coset")
    return _power(value, P - 2)


def _multiply(left, right, reducer=11):
    # Schoolbook polynomial convolution followed by u^4 = reducer.
    convolution = [0] * 7
    for i in range(4):
        for j in range(4):
            convolution[i + j] += left[i] * right[j]
    for degree in range(6, 3, -1):
        convolution[degree - 4] += reducer * convolution[degree]
    return [coefficient % P for coefficient in convolution[:4]]


def _weights(alpha, reducer=11):
    square = _multiply(alpha, alpha, reducer)
    cube = _multiply(square, alpha, reducer)
    return [cube, square, alpha, [1, 0, 0, 0]]


def _fold(residuals, weights, inverse_z):
    return [sum(residuals[j] * weights[j][d] for j in range(4)) * inverse_z % P
            for d in range(4)]


def _reverse11(row):
    result = 0
    for _ in range(11):
        result = (result << 1) | (row & 1)
        row >>= 1
    return result


def _residuals(current, next_a, first, last, transition):
    a, b = current
    square = a * a % P
    return [(b - square * square) % P,
            transition * (next_a - a - 1) % P,
            first * (a - 5) % P,
            last * (a - 260) % P]


def _roots_and_basis_controls():
    # These identities check the independent implementation against literal
    # primary-source roots and polynomial identities, not producer output.
    u = [0, 1, 0, 0]
    u2 = _multiply(u, u)
    u3 = _multiply(u2, u)
    u4 = _multiply(u3, u)
    return {
        "trace_root_exact_order": _power(TRACE_ROOT, 256) == 1 and _power(TRACE_ROOT, 128) != 1,
        "quotient_root_exact_order": _power(QUOTIENT_ROOT, 2048) == 1 and _power(QUOTIENT_ROOT, 1024) != 1,
        "stride_root_identity": _power(QUOTIENT_ROOT, 8) == TRACE_ROOT,
        "shift_disjoint": _power(_power(SHIFT, 256), 8) != 1,
        "u_squared": u2 == [0, 0, 1, 0],
        "u_cubed": u3 == [0, 0, 0, 1],
        "u_fourth": u4 == [11, 0, 0, 0],
    }


def compare_literal(raw):
    """Return at most16 KiB of canonical comparison results.

    Input <=192 KiB. No files, network, subprocesses, dynamic imports,
    callbacks, generators of main evaluations, or verifier decisions.
    Every one of 2048 rows and all 8192 coefficients are compared.
    """
    obj = _parse(raw)
    main = obj["main"]
    candidate = obj["candidate"]
    alpha = obj["alpha"]
    weights = _weights(alpha)
    wrong_reducer_weights = _weights(alpha, 2)
    last_trace_point = _inverse(TRACE_ROOT)
    inverse_n = _inverse(N)
    identities = _roots_and_basis_controls()
    if not all(identities.values()):
        raise ValueError("fixed arithmetic identity failed")
    names = ("next_stride1", "next_clamped_no_wrap", "ascending_alpha_powers",
             "reversed_basis_output", "wrong_binomial_x4_minus2",
             "normalized_boundary_selectors", "bit_reversed_logical_input",
             "swapped_main_columns", "boolean_selector_flags")
    controls = {name: {"distinct_rows": 0, "first_distinct_row": None} for name in names}
    mismatch_rows = 0
    mismatch_coefficients = 0
    first_mismatches = []
    selector_nonzero = {"first": 0, "last": 0, "transition": 0}
    x = SHIFT
    for row in range(Q):
        z = (_power(x, N) - 1) % P
        inverse_z = _inverse(z)
        first = z * _inverse(x - 1) % P
        last = z * _inverse(x - last_trace_point) % P
        transition = (x - last_trace_point) % P
        selector_nonzero["first"] += int(first != 0)
        selector_nonzero["last"] += int(last != 0)
        selector_nonzero["transition"] += int(transition != 0)
        next_row = (row + 8) % Q
        residuals = _residuals(main[row], main[next_row][0], first, last, transition)
        expected = _fold(residuals, weights, inverse_z)
        bad_row = False
        for coefficient in range(4):
            if candidate[row][coefficient] != expected[coefficient]:
                bad_row = True
                mismatch_coefficients += 1
                if len(first_mismatches) < 16:
                    first_mismatches.append({"row": row, "coefficient": coefficient,
                                             "expected": expected[coefficient],
                                             "candidate": candidate[row][coefficient]})
        mismatch_rows += int(bad_row)
        mutants = {
            "next_stride1": _fold(_residuals(main[row], main[(row + 1) % Q][0], first, last, transition), weights, inverse_z),
            "next_clamped_no_wrap": _fold(_residuals(main[row], main[min(row + 8, Q - 1)][0], first, last, transition), weights, inverse_z),
            "ascending_alpha_powers": _fold(residuals, list(reversed(weights)), inverse_z),
            "reversed_basis_output": list(reversed(expected)),
            "wrong_binomial_x4_minus2": _fold(residuals, wrong_reducer_weights, inverse_z),
            "normalized_boundary_selectors": _fold(_residuals(main[row], main[next_row][0], first * inverse_n % P,
                last * last_trace_point * inverse_n % P, transition), weights, inverse_z),
            "bit_reversed_logical_input": _fold(_residuals(main[_reverse11(row)], main[_reverse11(next_row)][0], first, last, transition), weights, inverse_z),
            "swapped_main_columns": _fold(_residuals(list(reversed(main[row])), main[next_row][1], first, last, transition), weights, inverse_z),
            "boolean_selector_flags": _fold(_residuals(main[row], main[next_row][0], int(row == 0), int(row == Q - 1), int(row != Q - 1)), weights, inverse_z),
        }
        for name in names:
            if mutants[name] != expected:
                controls[name]["distinct_rows"] += 1
                if controls[name]["first_distinct_row"] is None:
                    controls[name]["first_distinct_row"] = row
        x = x * QUOTIENT_ROOT % P
    separating = all(control["distinct_rows"] > 0 for control in controls.values())
    report = {
        "schema": "kova-quartic-quotient-reference-v40-report",
        "capture_receipt_sha256": obj["capture_receipt_sha256"],
        "arithmetic_equivalent": mismatch_coefficients == 0,
        "rows_compared": Q,
        "coefficients_compared": 8192,
        "mismatch_rows": mismatch_rows,
        "mismatch_coefficients": mismatch_coefficients,
        "first_mismatches": first_mismatches,
        "identities": identities,
        "selector_nonzero_rows": selector_nonzero,
        "controls": controls,
        "all_controls_separate": separating,
        "control_status": "separating" if separating else "inconclusive",
        "meaning": "conditional arithmetic comparison only; no proof acceptance",
    }
    encoded = _canonical(report)
    if len(encoded) > MAX_OUTPUT_BYTES:
        raise ValueError("bounded report exceeded")
    return encoded
