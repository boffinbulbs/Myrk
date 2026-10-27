#!/usr/bin/env python3
"""Transparent offline ML DSA 87 verification oracle using Python integers.

This reference is not a proof verifier or a wallet authorization interface.
It implements no signing and consumes no signing seed. Inputs and diagnostic
values belong to public synthetic fixtures, never operational private data.
"""

from __future__ import annotations

import hashlib
import hmac
import json
from pathlib import Path

Q = 8380417
N = 256
GAMMA1 = 524288
GAMMA2 = 261888
BETA = 120
OMEGA = 75
PSI = 1753
ZETAS = [0] + [pow(PSI, int(f"{i:08b}"[::-1], 2), Q) for i in range(1, 256)]
INVERSE_N = pow(N, -1, Q)
ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).resolve().parent
SELECTED_SHA256 = "fe61306ae7bafad8b36d2ef8cac9cf12ce3706afe12171b8e7b27d97edba7de4"


def load_selected() -> dict:
    encoded = (ROOT / "research/crypto/vectors/selected.json").read_bytes()
    if hashlib.sha256(encoded).hexdigest() != SELECTED_SHA256:
        raise ValueError("retained official vector digest")
    return json.loads(encoded)


def unpack(data: bytes, count: int, bits: int) -> list[int]:
    if len(data) * 8 != count * bits:
        raise ValueError("exact polynomial packing length")
    word = int.from_bytes(data, "little")
    mask = (1 << bits) - 1
    return [(word >> (bits * i)) & mask for i in range(count)]


def pack(values: list[int], bits: int) -> bytes:
    if any(v < 0 or v >= 1 << bits for v in values):
        raise ValueError("packing range")
    word = sum(v << (bits * i) for i, v in enumerate(values))
    return word.to_bytes(len(values) * bits // 8, "little")


def decode(pk: bytes, signature: bytes) -> tuple:
    if len(pk) != 2592 or len(signature) != 4627:
        raise ValueError("key or signature length")
    rho = pk[:32]
    t1 = [unpack(pk[32 + 320 * i:32 + 320 * (i + 1)], N, 10) for i in range(8)]
    challenge = signature[:64]
    z = []
    for i in range(7):
        values = unpack(signature[64 + 640 * i:64 + 640 * (i + 1)], N, 20)
        polynomial = [GAMMA1 - value for value in values]
        if any(abs(value) >= GAMMA1 - BETA for value in polynomial):
            raise ValueError("strict z norm")
        z.append(polynomial)
    indices, cuts = signature[4544:4619], signature[4619:4627]
    if any(end > OMEGA for end in cuts) or any(a > b for a, b in zip(cuts, cuts[1:])):
        raise ValueError("hint cuts")
    if any(indices[cuts[-1]:]):
        raise ValueError("unused hint indices")
    hints = [[0] * N for _ in range(8)]
    start = 0
    for row, end in enumerate(cuts):
        segment = indices[start:end]
        if any(a >= b for a, b in zip(segment, segment[1:])):
            raise ValueError("hint index order")
        for index in segment:
            hints[row][index] = 1
        start = end
    return rho, t1, challenge, z, hints


def ntt(polynomial: list[int]) -> list[int]:
    values = [x % Q for x in polynomial]
    k = 0
    length = 128
    while length:
        for start in range(0, N, length * 2):
            k += 1
            twiddle = ZETAS[k]
            for j in range(start, start + length):
                t = twiddle * values[j + length] % Q
                values[j + length] = (values[j] - t) % Q
                values[j] = (values[j] + t) % Q
        length //= 2
    return values


def inverse_ntt(polynomial: list[int]) -> list[int]:
    values = list(polynomial)
    k = 256
    length = 1
    while length < N:
        for start in range(0, N, length * 2):
            k -= 1
            twiddle = -ZETAS[k] % Q
            for j in range(start, start + length):
                a, b = values[j], values[j + length]
                values[j] = (a + b) % Q
                values[j + length] = twiddle * (a - b) % Q
        length *= 2
    return [value * INVERSE_N % Q for value in values]


def matrix_poly(rho: bytes, row: int, column: int) -> tuple[list[int], dict]:
    stream = hashlib.shake_128(rho + bytes([column, row]))
    length = 840
    data = stream.digest(length)
    cursor = 0
    coefficients = []
    rejected = []
    while len(coefficients) < N:
        if cursor + 3 > len(data):
            length *= 2
            data = stream.digest(length)
        raw = int.from_bytes(data[cursor:cursor + 3], "little") & 0x7fffff
        if raw < Q:
            coefficients.append(raw)
        else:
            rejected.append(cursor // 3)
        cursor += 3
    return coefficients, {"bytes_consumed": cursor, "rejected_candidate_indices": rejected}


def challenge_poly(seed: bytes) -> tuple[list[int], dict]:
    stream = hashlib.shake_256(seed)
    length = 136
    data = stream.digest(length)
    signs = int.from_bytes(data[:8], "little")
    cursor = 8
    values = [0] * N
    rejected = []
    for i in range(N - 60, N):
        while True:
            if cursor == len(data):
                length *= 2
                data = stream.digest(length)
            j = data[cursor]
            cursor += 1
            if j <= i:
                break
            rejected.append(cursor - 1)
        values[i] = values[j]
        values[j] = 1 - 2 * ((signs >> (i + 60 - N)) & 1)
    return values, {"bytes_consumed": cursor, "rejected_byte_indices": rejected}


def decompose(value: int) -> tuple[int, int]:
    if not 0 <= value < Q:
        raise ValueError("canonical residue")
    low = value % (2 * GAMMA2)
    if low > GAMMA2:
        low -= 2 * GAMMA2
    if value - low == Q - 1:
        return 0, low - 1
    return (value - low) // (2 * GAMMA2), low


def use_hint(value: int, hint: int) -> int:
    high, low = decompose(value)
    if hint == 0:
        return high
    if hint != 1:
        raise ValueError("Boolean hint")
    return (high + (1 if low > 0 else -1)) % 16


def verify(pk: bytes, signature: bytes, message: bytes, context: bytes) -> dict:
    if len(context) > 255:
        return {"valid": False, "rejection": "context length"}
    try:
        rho, t1, challenge, z, hints = decode(pk, signature)
    except ValueError as error:
        return {"valid": False, "rejection": str(error)}
    tr = hashlib.shake_256(pk).digest(64)
    mu_preimage = tr + bytes([0, len(context)]) + context + message
    mu = hashlib.shake_256(mu_preimage).digest(64)
    c, challenge_cursor = challenge_poly(challenge)
    c_hat = ntt(c)
    z_hat = [ntt(polynomial) for polynomial in z]
    t1_hat = [ntt([8192 * value for value in polynomial]) for polynomial in t1]
    w1 = []
    reconstruction = []
    matrix_cursors = []
    for row in range(8):
        products = [0] * N
        for column in range(7):
            a, cursor = matrix_poly(rho, row, column)
            matrix_cursors.append({"row": row, "column": column, **cursor})
            products = [(v + x * y) % Q for v, x, y in zip(products, a, z_hat[column])]
        reduced = [(a - b * t) % Q for a, b, t in zip(products, c_hat, t1_hat[row])]
        polynomial = inverse_ntt(reduced)
        reconstruction.append(polynomial)
        w1.extend(use_hint(value, hint) for value, hint in zip(polynomial, hints[row]))
    encoded_w1 = pack(w1, 4)
    challenge_preimage = mu + encoded_w1
    expected_challenge = hashlib.shake_256(challenge_preimage).digest(64)
    return {
        "valid": hmac.compare_digest(challenge, expected_challenge),
        "rejection": None if challenge == expected_challenge else "challenge equality",
        "owner_binding_hex": hashlib.sha3_512(pk).hexdigest(),
        "tr_hex": tr.hex(), "mu_hex": mu.hex(),
        "mu_preimage_hex": mu_preimage.hex(),
        "reconstructed_coefficients": reconstruction,
        "w1_encoded_hex": encoded_w1.hex(),
        "challenge_expected_hex": expected_challenge.hex(),
        "challenge_received_hex": challenge.hex(),
        "matrix_cursors": matrix_cursors, "challenge_cursor": challenge_cursor,
        "hint_weight": sum(sum(row) for row in hints),
        "z_max_norm": max(abs(v) for row in z for v in row),
    }


def main() -> None:
    selected = load_selected()
    reports = []
    for case in selected["cases"]:
        if not case["id"].startswith("ml_dsa_87_verify_"):
            continue
        values = {key: bytes.fromhex(value) for key, value in case["input"].items()}
        result = verify(values["pk"], values["signature"], values["message"], values["context"])
        assert result["valid"] == case["expected"]["testPassed"], case["id"]
        reports.append({"id": case["id"], "expected_valid": case["expected"]["testPassed"], **result})
    print(json.dumps([{key: report[key] for key in ["id", "valid", "rejection", "hint_weight", "z_max_norm"]} for report in reports], indent=2))


if __name__ == "__main__":
    main()
