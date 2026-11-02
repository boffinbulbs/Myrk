"""Whole portable GCM integer relation, source under review, not yet admitted.

AES equations are transcribed from RustCrypto aes 0.9.1 fixslice64.
Copyright (c) 2018-2024 The RustCrypto Project Developers.
Copyright (c) 2018 Artyom Pavlov.
Original fixsliced C implementation: Alexandre Adomnicai.
Portable POLYVAL equations derive from RustCrypto polyval 0.7.3 and
BearSSL ghash_ctmul64.c, Copyright (c) 2016 Thomas Pornin.
Original MIT and Apache notices are preserved in licenses/.

This computes public synthetic integer data. It is not a field AIR,
cryptographic proof, hardware-backend check or payment acceptance API.
"""

from array import array
import json
import os
import sys

MASK = (1 << 64) - 1
MAX_NODES = 5_000_000
K, INPUT, XOR, AND, OR, NOT, SHL, SHR, ROR, REV, BIT, PART, SUM, CARRY = range(14)


class RelationError(ValueError):
    def __init__(self, cause, position=None):
        self.cause = cause
        self.position = position
        super().__init__(cause if position is None else f"{cause} at node {position}")


def require(condition, cause, position=None):
    if not condition:
        raise RelationError(cause, position)


def uint(value, bits):
    require(type(value) is int and 0 <= value < (1 << bits), "word-range")
    return value


class Trace:
    __slots__ = ("values", "left", "right", "ops", "args", "roots", "stats", "sealed")

    def __init__(self):
        self.values = array("Q")
        self.left = array("I")
        self.right = array("I")
        self.ops = array("B")
        self.args = array("B")
        require((self.values.itemsize, self.left.itemsize, self.ops.itemsize) == (8, 4, 1),
                "array-width")
        self.roots = ()
        self.stats = {}
        self.sealed = False

    def shape(self):
        n = len(self.values)
        require(n <= MAX_NODES, "node-limit")
        require(all(len(a) == n for a in (self.left, self.right, self.ops, self.args)),
                "trace-shape")


class Word:
    __slots__ = ("owner", "index")

    def __init__(self, owner, index):
        self.owner = owner
        self.index = index

    def __xor__(self, other):
        return self.owner.binary(XOR, self, other)

    def __rxor__(self, other):
        return self.owner.binary(XOR, other, self)

    def __and__(self, other):
        return self.owner.binary(AND, self, other)

    def __rand__(self, other):
        return self.owner.binary(AND, other, self)

    def __or__(self, other):
        return self.owner.binary(OR, self, other)

    def __ror__(self, other):
        return self.owner.binary(OR, other, self)

    def __invert__(self):
        return self.owner.unary(NOT, self, 0)

    def __lshift__(self, shift):
        return self.owner.unary(SHL, self, shift)

    def __rshift__(self, shift):
        return self.owner.unary(SHR, self, shift)


class Engine:
    """One owned word trace, or fixed-program replay of those same arrays."""

    def __init__(self, trace=None):
        self.reading = trace is not None
        self.trace = Trace() if trace is None else trace
        if self.reading:
            self.trace.shape()
            require(self.trace.sealed, "unsealed-trace")
        self.cursor = 0
        self.constants = {}
        self.input_count = 0
        self.aes_calls = 0
        self.poly_calls = 0

    def close(self):
        # Break the Engine -> constant Word -> Engine ownership cycle.
        self.constants.clear()

    def value(self, word):
        require(type(word) is Word and word.owner is self, "foreign-wire")
        require(0 <= word.index < self.cursor, "wire-range")
        return self.trace.values[word.index]

    def node(self, op, left, right, arg, expected=None):
        position = self.cursor
        require(position < MAX_NODES, "node-limit", position)
        require(0 <= op <= CARRY and 0 <= arg <= 63, "descriptor-range", position)
        if self.reading:
            require(position < len(self.trace.values), "truncated-trace", position)
            actual_op = self.trace.ops[position]
            a, b = self.trace.left[position], self.trace.right[position]
            if actual_op >= XOR:
                require(a < position and b < position, "forward-reference", position)
            require((actual_op, a, b, self.trace.args[position]) == (op, left, right, arg),
                    "descriptor", position)
            value = self.trace.values[position]
            if op == BIT:
                require(value <= 1, "bit-range", position)
            if op == INPUT:
                require(value <= 255, "byte-range", position)
            if expected is not None:
                require(value == expected, "equation", position)
        else:
            require(not self.trace.sealed, "sealed-trace")
            value = uint(expected, 64)
            self.trace.values.append(value)
            self.trace.left.append(uint(left, 32))
            self.trace.right.append(uint(right, 32))
            self.trace.ops.append(op)
            self.trace.args.append(arg)
        self.cursor += 1
        return Word(self, position)

    def constant(self, value):
        uint(value, 64)
        if value not in self.constants:
            self.constants[value] = self.node(K, value & 0xFFFFFFFF, value >> 32, 0, value)
        return self.constants[value]

    def source(self, data):
        require(type(data) is bytes, "source-type")
        result = []
        for value in data:
            result.append(self.node(INPUT, self.input_count, 0, 0, value))
            self.input_count += 1
        return tuple(result)

    def word(self, value):
        if type(value) is Word:
            self.value(value)
            return value
        return self.constant(value)

    def binary(self, op, left, right):
        a, b = self.word(left), self.word(right)
        x, y = self.value(a), self.value(b)
        if op == XOR:
            value = x ^ y
        elif op == AND:
            value = x & y
        elif op == OR:
            value = x | y
        else:
            raise RelationError("unsupported-binary")
        return self.node(op, a.index, b.index, 0, value)

    def unary(self, op, word, arg):
        a = self.word(word)
        uint(arg, 6)
        x = self.value(a)
        if op == NOT:
            value = x ^ MASK
        elif op == SHL:
            value = (x << arg) & MASK
        elif op == SHR:
            value = x >> arg
        elif op == ROR:
            value = ((x >> arg) | (x << ((64 - arg) % 64))) & MASK
        elif op == REV:
            value = sum(((x >> bit) & 1) << (63 - bit) for bit in range(64))
        elif op == BIT:
            value = (x >> arg) & 1
        else:
            raise RelationError("unsupported-unary")
        return self.node(op, a.index, a.index, arg, value)

    def add(self, left, right):
        a, b = self.word(left), self.word(right)
        x, y = self.value(a), self.value(b)
        if self.reading:
            s = self.node(SUM, a.index, b.index, 0)
            c = self.node(CARRY, a.index, b.index, 0)
            total, carry = self.value(s), self.value(c)
            require(total == (x ^ y ^ carry), "sum-equation", s.index)
            require(carry == (((x & y) | ((x ^ y) & carry)) << 1) & MASK,
                    "carry-equation", c.index)
        else:
            total = (x + y) & MASK
            s = self.node(SUM, a.index, b.index, 0, total)
            self.node(CARRY, a.index, b.index, 0, x ^ y ^ total)
        return s

    def multiply(self, left, right):
        a, b = self.word(left), self.word(right)
        accumulator = self.constant(0)
        for bit in range(64):
            selector = self.unary(BIT, b, bit)
            selected = ((self.value(a) << bit) & MASK) if self.value(selector) else 0
            row = self.node(PART, a.index, selector.index, bit, selected)
            accumulator = self.add(accumulator, row)
        return accumulator

    def finish(self, words):
        roots = tuple(w.index for w in words)
        values = tuple(self.value(w) for w in words)
        if self.reading:
            require(self.cursor == len(self.trace.values), "trailing-trace")
            require(roots == self.trace.roots, "terminal-roots")
            require(self.trace.stats == {"logical_aes_requests": self.aes_calls,
                                         "represented_multiplications": self.poly_calls}, "action-counts")
        else:
            self.trace.roots = roots
            self.trace.stats = {"logical_aes_requests": self.aes_calls,
                                "represented_multiplications": self.poly_calls}
            self.trace.sealed = True
        return values


def ror(word, count):
    return word.owner.unary(ROR, word, count)


def reverse(word):
    return word.owner.unary(REV, word, 0)


def delta(word, count, mask):
    t = (word ^ (word >> count)) & mask
    return word ^ t ^ (t << count)


def swap(words, i, j, count, mask):
    a, b = words[i], words[j]
    t = (a ^ (b >> count)) & mask
    words[i], words[j] = a ^ t, b ^ (t << count)


def swaps(words):
    for i, j in ((1, 0), (3, 2), (5, 4), (7, 6)):
        swap(words, i, j, 1, 0x5555555555555555)
    for i, j in ((2, 0), (3, 1), (6, 4), (7, 5)):
        swap(words, i, j, 2, 0x3333333333333333)
    for i, j in ((4, 0), (5, 1), (6, 2), (7, 3)):
        swap(words, i, j, 4, 0x0F0F0F0F0F0F0F0F)


REORDER = (0, 8, 1, 9, 2, 10, 3, 11)


def bitslice(blocks):
    require(len(blocks) == 4 and all(len(b) == 16 for b in blocks), "batch-shape")
    e = blocks[0][0].owner
    words = []
    for start in (0, 4):
        for block in blocks:
            word = e.constant(0)
            for byte, index in enumerate(REORDER):
                word = word | (block[start + index] << (byte * 8))
            words.append(word)
    swaps(words)
    return words


def inv_bitslice(state):
    require(len(state) == 8, "state-shape")
    words = list(state)
    swaps(words)
    e = words[0].owner
    blocks = [[e.constant(0)] * 16 for _ in range(4)]
    for start, bank in ((0, 0), (4, 4)):
        for b in range(4):
            for byte, index in enumerate(REORDER):
                blocks[b][start + index] = (words[bank + b] >> (byte * 8)) & 255
    return tuple(tuple(block) for block in blocks)


def sub_bytes(state):
    u7, u6, u5, u4, u3, u2, u1, u0 = state
    y14 = u3 ^ u5
    y13 = u0 ^ u6
    y12 = y13 ^ y14
    t1 = u4 ^ y12
    y15 = t1 ^ u5
    t2 = y12 & y15
    y6 = y15 ^ u7
    y20 = t1 ^ u1
    y9 = u0 ^ u3
    y11 = y20 ^ y9
    t12 = y9 & y11
    y7 = u7 ^ y11
    y8 = u0 ^ u5
    t0 = u1 ^ u2
    y10 = y15 ^ t0
    y17 = y10 ^ y11
    t13 = y14 & y17
    t14 = t13 ^ t12
    y19 = y10 ^ y8
    t15 = y8 & y10
    t16 = t15 ^ t12
    y16 = t0 ^ y11
    y21 = y13 ^ y16
    t7 = y13 & y16
    y18 = u0 ^ y16
    y1 = t0 ^ u7
    y4 = y1 ^ u3
    t5 = y4 & u7
    t6 = t5 ^ t2
    t18 = t6 ^ t16
    t22 = t18 ^ y19
    y2 = y1 ^ u0
    t10 = y2 & y7
    t11 = t10 ^ t7
    t20 = t11 ^ t16
    t24 = t20 ^ y18
    y5 = y1 ^ u6
    t8 = y5 & y1
    t9 = t8 ^ t7
    t19 = t9 ^ t14
    t23 = t19 ^ y21
    y3 = y5 ^ y8
    t3 = y3 & y6
    t4 = t3 ^ t2
    t17 = t4 ^ y20
    t21 = t17 ^ t14
    t26 = t21 & t23
    t27 = t24 ^ t26
    t31 = t22 ^ t26
    t25 = t21 ^ t22
    t28 = t25 & t27
    t29 = t28 ^ t22
    z14 = t29 & y2
    z5 = t29 & y7
    t30 = t23 ^ t24
    t32 = t31 & t30
    t33 = t32 ^ t24
    t35 = t27 ^ t33
    t36 = t24 & t35
    t38 = t27 ^ t36
    t39 = t29 & t38
    t40 = t25 ^ t39
    t43 = t29 ^ t40
    z3 = t43 & y16
    tc12 = z3 ^ z5
    z12 = t43 & y13
    z13 = t40 & y5
    z4 = t40 & y1
    tc6 = z3 ^ z4
    t34 = t23 ^ t33
    t37 = t36 ^ t34
    t41 = t40 ^ t37
    z8 = t41 & y10
    z17 = t41 & y8
    t44 = t33 ^ t37
    z0 = t44 & y15
    z9 = t44 & y12
    z10 = t37 & y3
    z1 = t37 & y6
    tc5 = z1 ^ z0
    tc11 = tc6 ^ tc5
    z11 = t33 & y4
    t42 = t29 ^ t33
    t45 = t42 ^ t41
    z7 = t45 & y17
    tc8 = z7 ^ tc6
    z16 = t45 & y14
    z6 = t42 & y11
    tc16 = z6 ^ tc8
    z15 = t42 & y9
    tc20 = z15 ^ tc16
    tc1 = z15 ^ z16
    tc2 = z10 ^ tc1
    tc21 = tc2 ^ z11
    tc3 = z9 ^ tc2
    s0 = tc3 ^ tc16
    s3 = tc3 ^ tc11
    s1 = s3 ^ tc16
    tc13 = z13 ^ tc1
    z2 = t33 & u7
    tc4 = z0 ^ z2
    tc7 = z12 ^ tc4
    tc9 = z8 ^ tc7
    tc10 = tc8 ^ tc9
    tc17 = z14 ^ tc10
    s5 = tc21 ^ tc17
    tc26 = tc17 ^ tc20
    s2 = tc26 ^ z17
    tc14 = tc4 ^ tc12
    tc18 = tc13 ^ tc14
    s6 = tc10 ^ tc18
    s7 = z12 ^ tc18
    s4 = tc14 ^ s3
    return [s7, s6, s5, s4, s3, s2, s1, s0]


def nots(state):
    result = list(state)
    for index in (0, 1, 5, 6):
        result[index] = ~result[index]
    return result


def shift_rows(state, times):
    if times == 1:
        return [delta(delta(x, 8, 0x00F000FF000F0000), 4, 0x0F0F00000F0F0000) for x in state]
    if times == 2:
        return [delta(x, 8, 0x00FF000000FF0000) for x in state]
    require(times == 3, "row-transform")
    return [delta(delta(x, 8, 0x000F00FF00F00000), 4, 0x0F0F00000F0F0000) for x in state]


def expand_key(key, variant):
    e = key[0].owner
    keys = [e.constant(0)] * 120
    keys[:8] = bitslice((key[:16],) * 4)
    keys[8:16] = bitslice((key[16:],) * 4)
    offset = 8
    for rcon in range(7):
        for first in (True, False):
            if not first and rcon == 6:
                break
            keys[offset + 8:offset + 16] = keys[offset:offset + 8]
            offset += 8
            keys[offset:offset + 8] = nots(sub_bytes(keys[offset:offset + 8]))
            if first:
                keys[offset + rcon] = keys[offset + rcon] ^ 0x00000000F0000000
            distance = 28 if first else 12
            if variant == "key-rotation" and first:
                distance = 12
            for i in range(8):
                j = offset + i
                rk = keys[j - 16] ^ (ror(keys[j], distance) & 0x000F000F000F000F)
                keys[j] = rk ^ ((rk << 4) & 0xFFF0FFF0FFF0FFF0) ^ ((rk << 8) & 0xFF00FF00FF00FF00) ^ ((rk << 12) & 0xF000F000F000F000)
    require(offset == 112, "key-schedule-boundary")
    for i in range(8, 104, 32):
        keys[i:i + 8] = shift_rows(keys[i:i + 8], 3)
        keys[i + 8:i + 16] = shift_rows(keys[i + 8:i + 16], 2)
        keys[i + 16:i + 24] = shift_rows(keys[i + 16:i + 24], 1)
    keys[104:112] = shift_rows(keys[104:112], 3)
    if variant != "omitted-key-nots":
        for i in range(8, 120, 8):
            keys[i:i + 8] = nots(keys[i:i + 8])
    return tuple(keys)


def rotate_first(word, kind):
    if kind == 0:
        return ror(word, 16)
    masks = (0, 0x0FFF0FFF0FFF0FFF, 0x00FF00FF00FF00FF, 0x000F000F000F000F)
    return (ror(word, 16 + 4 * kind) & masks[kind]) | (ror(word, 4 * kind) & (MASK ^ masks[kind]))


def rotate_second(word, kind):
    if kind in (0, 2):
        return ror(word, 32)
    return (ror(word, 40) & 0x00FF00FF00FF00FF) | (ror(word, 24) & 0xFF00FF00FF00FF00)


def mix(state, kind, variant):
    original = tuple(state)
    result = list(state)
    b = tuple(rotate_first(x, kind) for x in original)
    c = tuple(x ^ y for x, y in zip(original, b))
    for i in range(8):
        if variant == "updated-mix":
            a = tuple(result)
            b = tuple(rotate_first(x, kind) for x in a)
            c = tuple(x ^ y for x, y in zip(a, b))
        value = b[i] ^ rotate_second(c[i], kind)
        if i:
            value = value ^ c[i - 1]
        if i in (0, 1, 3, 4):
            value = value ^ c[7]
        result[i] = value
    return result


def encrypt_batch(keys, blocks, variant):
    state = bitslice(blocks)
    if variant == "bit-planes":
        state[0], state[1] = state[1], state[0]
    state = [x ^ y for x, y in zip(state, keys[:8])]
    for round_number in range(1, 14):
        state = sub_bytes(state)
        if variant == "added-encryption-nots":
            state = nots(state)
        state = mix(state, round_number % 4, variant)
        state = [x ^ y for x, y in zip(state, keys[8 * round_number:8 * (round_number + 1)])]
    state = sub_bytes(shift_rows(state, 2))
    if variant == "added-encryption-nots":
        state = nots(state)
    return inv_bitslice([x ^ y for x, y in zip(state, keys[112:120])])


def encrypt_one(keys, block, variant):
    keys[0].owner.aes_calls += 1
    zero = (keys[0].owner.constant(0),) * 16
    return encrypt_batch(keys, (block, zero, zero, zero), variant)[0]


def from_block(block):
    require(len(block) == 16, "block-width")
    e = block[0].owner
    result = []
    for start in (0, 8):
        word = e.constant(0)
        for i in range(8):
            word = word | (block[start + i] << (8 * i))
        result.append(word)
    return tuple(result)


def to_block(pair):
    return tuple((word >> (8 * i)) & 255 for word in pair for i in range(8))


def mulx(pair):
    lo, hi = pair
    high = hi.owner.unary(BIT, hi, 63)
    return ((lo << 1) ^ high,
            (hi << 1) ^ (lo >> 63) ^ (high << 57) ^ (high << 62) ^ (high << 63))


def bmul(x, y):
    e = x.owner
    masks = tuple(0x1111111111111111 << i for i in range(4))
    a = tuple(x & m for m in masks)
    b = tuple(y & m for m in masks)
    z = []
    for i in range(4):
        word = e.constant(0)
        for j in range(4):
            word = word ^ e.multiply(a[j], b[(i - j) % 4])
        z.append(word & masks[i])
    return z[0] | z[1] | z[2] | z[3]


def represented_multiply(left, right, variant):
    left[0].owner.poly_calls += 1
    h0, h1 = left
    y0, y1 = right
    h0r, h1r = reverse(h0), reverse(h1)
    y0r, y1r = reverse(y0), reverse(y1)
    z0, z1 = bmul(y0, h0), bmul(y1, h1)
    z2 = bmul(y0 ^ y1, h0 ^ h1) ^ z0 ^ z1
    z0h, z1h = bmul(y0r, h0r), bmul(y1r, h1r)
    z2h = bmul(y0r ^ y1r, h0r ^ h1r) ^ z0h ^ z1h
    z0h, z1h, z2h = reverse(z0h) >> 1, reverse(z1h) >> 1, reverse(z2h) >> 1
    v0, v1, v2, v3 = z0, z0h ^ z2, z1 ^ z2h, z1h
    if variant == "omitted-reduction":
        return v0, v1
    old_v1 = v1
    v2 = v2 ^ v0 ^ (v0 >> 1) ^ (v0 >> 2) ^ (v0 >> 7)
    v1 = v1 ^ (v0 << 63) ^ (v0 << 62) ^ (v0 << 57)
    selected = old_v1 if variant == "stale-reduction" else v1
    v3 = v3 ^ selected ^ (selected >> 1) ^ (selected >> 2) ^ (selected >> 7)
    v2 = v2 ^ (selected << 63) ^ (selected << 62) ^ (selected << 57)
    return v2, v3


def padded_blocks(words, zero):
    for i in range(0, len(words), 16):
        block = tuple(words[i:i + 16])
        yield block + (zero,) * (16 - len(block))


def gcm_program(e, key, nonce, aad, plaintext, variant="correct"):
    require(variant in ("correct",) + WRONG, "variant")
    require(type(key) is bytes and len(key) == 32, "key-width")
    require(type(nonce) is bytes and len(nonce) == 12, "nonce-width")
    require(type(aad) is bytes and len(aad) <= 1789, "aad-bound")
    require(type(plaintext) is bytes and len(plaintext) <= 418, "body-bound")
    kw, nw, aw, pw = e.source(key), e.source(nonce), e.source(aad), e.source(plaintext)
    keys = expand_key(kw, variant)
    zero = e.constant(0)
    h = encrypt_one(keys, (zero,) * 16, variant)
    mask_counter = 0 if variant == "mask-zero" else 1
    mask = encrypt_one(keys, nw + tuple(e.constant(x) for x in mask_counter.to_bytes(4, "big")), variant)
    body = []
    for i in range(0, len(pw), 16):
        counter = i // 16 + (1 if variant == "counter-one" else 2)
        order = "little" if variant == "counter-little" else "big"
        block = nw + tuple(e.constant(x) for x in counter.to_bytes(4, order))
        stream = encrypt_one(keys, block, variant)
        body.extend(x ^ stream[j] for j, x in enumerate(pw[i:i + 16]))
    cipher = tuple(body)
    hash_body = pw if variant == "hash-plaintext" else cipher
    hp = mulx(from_block(tuple(reversed(h))))
    accumulator = (zero, zero)
    blocks = (padded_blocks(aw + hash_body, zero) if variant == "combined-padding"
              else (*padded_blocks(aw, zero), *padded_blocks(hash_body, zero)))
    for block in blocks:
        selected = block if variant == "no-reversal" else tuple(reversed(block))
        pair = from_block(selected)
        accumulator = represented_multiply(tuple(a ^ b for a, b in zip(accumulator, pair)), hp, variant)
    multiplier = 1 if variant == "byte-lengths" else 8
    lengths = (len(aad) * multiplier).to_bytes(8, "big") + (len(plaintext) * multiplier).to_bytes(8, "big")
    pair = from_block(tuple(e.constant(x) for x in reversed(lengths)))
    accumulator = represented_multiply(tuple(a ^ b for a, b in zip(accumulator, pair)), hp, variant)
    digest = tuple(reversed(to_block(accumulator)))
    tag = tuple(x ^ y for x, y in zip(digest, mask))
    values = e.finish(cipher + tag)
    require(all(v <= 255 for v in values), "terminal-byte")
    return bytes(values)


def check_record(record, variant="correct", replay=True):
    key, nonce, aad, plaintext, ciphertext, tag = record
    engine = Engine()
    output = gcm_program(engine, key, nonce, aad, plaintext, variant)
    trace = engine.trace
    nodes = engine.cursor
    engine.close()
    del engine
    if replay:
        reader = Engine(trace)
        try:
            reconstructed = gcm_program(reader, key, nonce, aad, plaintext, variant)
            require(reconstructed == output, "replay-output")
        finally:
            reader.close()
        del reader
    return output, trace, nodes


def load_records(path):
    with open(path, "rb") as source:
        raw = source.read(8193)
    require(len(raw) <= 8192, "literal-size")
    data = json.loads(raw)
    require(type(data) is dict and data.get("format") == "kova.gcm.primary-literals.v89",
            "literal-format")
    records = data.get("records")
    require(type(records) is list and len(records) == 6, "literal-count")
    fields = ("key", "nonce", "aad", "plaintext", "ciphertext", "tag")
    result = []
    for item in records:
        require(type(item) is dict and set(item) == set(fields) | {"label", "source_lines"},
                "literal-fields")
        decoded = []
        for field in fields:
            value = item[field]
            require(type(value) is str and len(value) % 2 == 0
                    and all(c in "0123456789abcdef" for c in value), "literal-hex")
            decoded.append(bytes.fromhex(value))
        key, nonce, aad, plaintext, ciphertext, tag = decoded
        require(len(key) == 32 and len(nonce) == 12 and len(tag) == 16
                and len(ciphertext) == len(plaintext), "literal-width")
        result.append(tuple(decoded))
    require(tuple((len(r[3]), len(r[2])) for r in result)
            == ((0, 0), (0, 16), (16, 0), (13, 16), (51, 0), (51, 90)), "literal-shapes")
    require(result[0][0][:4].hex() == "b52c505a" and result[0][5].hex()
            == "bdc1ac884d332457a1d2664f168c76f0", "literal-anchor")
    require(result[-1][5].hex() == "3bf3fbab9b48486fd08a5552604df639", "literal-anchor")
    return tuple(result)


def routes():
    for position in range(512):
        blocks = [bytearray(16) for _ in range(4)]
        b, within = divmod(position, 128)
        byte, bit = divmod(within, 8)
        blocks[b][byte] = 1 << bit
        e = Engine()
        sources = tuple(e.source(bytes(block)) for block in blocks)
        state = bitslice(sources)
        expected = [0] * 8
        c, r = divmod(byte, 4)
        expected[bit] = 1 << (16 * r + 4 * c + b)
        require(tuple(e.value(x) for x in state) == tuple(expected), "route-axis")
        back = inv_bitslice(state)
        values = e.finish(tuple(x for block in back for x in block))
        require(bytes(values) == b"".join(bytes(block) for block in blocks), "inverse-route")
        e.close()
    # Independently fixed axis endpoints of the coordinate convention.
    require((16 * 3 + 4 * 3 + 3, 16 * 0 + 4 * 1 + 2) == (63, 6), "manual-axis")
    return 512


def separation(key):
    e = Engine()
    keys = expand_key(e.source(key), "correct")
    inputs = tuple(bytes((17 * b + 9 * i) & 255 for i in range(16)) for b in range(4))
    wires = tuple(e.source(b) for b in inputs)
    batch = encrypt_batch(keys, wires, "correct")
    reordered = encrypt_batch(keys, (wires[2], wires[0], wires[3], wires[1]), "correct")
    singles = tuple(encrypt_one(keys, w, "correct") for w in wires)
    for i in range(4):
        require(tuple(e.value(w) for w in batch[i]) == tuple(e.value(w) for w in singles[i]),
                "batch-separation")
    for i, source in enumerate((2, 0, 3, 1)):
        require(tuple(e.value(w) for w in reordered[i]) == tuple(e.value(w) for w in batch[source]),
                "batch-permutation")
    e.finish(tuple(w for block in batch + reordered + singles for w in block))
    e.close()
    return {"independent_blocks": 4, "reordered_blocks": 4, "expanded_words": len(keys)}


def zero_hash():
    e = Engine()
    zero = e.constant(0)
    nonzero = (e.constant(0x0123456789ABCDEF), e.constant(MASK))
    a = represented_multiply(nonzero, (zero, zero), "correct")
    b = represented_multiply((zero, zero), nonzero, "correct")
    require(e.finish(a + b) == (0, 0, 0, 0), "zero-hash-key")
    e.close()
    return 2


def typed_error(cause, action):
    try:
        action()
    except RelationError as error:
        require(error.cause == cause, "unexpected-error-cause")
        return
    raise RelationError("missing-refusal")


def input_refusals(record):
    key, nonce, aad, plaintext, _, _ = record
    cases = (
        ("key-width", (key[:-1], nonce, aad, plaintext)),
        ("key-width", (bytearray(key), nonce, aad, plaintext)),
        ("nonce-width", (key, nonce[:-1], aad, plaintext)),
        ("nonce-width", (key, bytearray(nonce), aad, plaintext)),
        ("aad-bound", (key, nonce, bytes(1790), plaintext)),
        ("aad-bound", (key, nonce, bytearray(aad), plaintext)),
        ("body-bound", (key, nonce, aad, bytes(419))),
        ("body-bound", (key, nonce, aad, bytearray(plaintext))),
    )
    for cause, args in cases:
        typed_error(cause, lambda: gcm_program(Engine(), *args))
    e = Engine()
    typed_error("word-range", lambda: e.constant(-1))
    typed_error("word-range", lambda: e.constant(1 << 64))
    typed_error("word-range", lambda: e.constant(True))
    typed_error("word-range", lambda: e.constant(0) << 64)
    foreign = Engine().constant(1)
    typed_error("foreign-wire", lambda: e.constant(1) ^ foreign)
    typed_error("source-type", lambda: e.source(bytearray(1)))
    e.cursor = MAX_NODES
    typed_error("node-limit", lambda: e.constant(42))
    return len(cases) + 7


def trace_refusals(record):
    output, trace, _ = check_record(record)
    key, nonce, aad, plaintext, ciphertext, tag = record
    require(output == ciphertext + tag, "control-primary")
    count = 0

    def replay():
        reader = Engine(trace)
        try:
            actual = gcm_program(reader, key, nonce, aad, plaintext)
            require(actual == ciphertext + tag, "restored-primary")
        finally:
            reader.close()

    def mutate(array_value, index, replacement, cause):
        nonlocal count
        previous = array_value[index]
        try:
            array_value[index] = replacement
            typed_error(cause, replay)
            count += 1
        finally:
            array_value[index] = previous
        replay()

    source_index = trace.ops.index(INPUT)
    xor_index = trace.ops.index(XOR)
    bit_index = trace.ops.index(BIT)
    partial_index = trace.ops.index(PART)
    sum_index = trace.ops.index(SUM)
    carry_index = sum_index + 1
    mutate(trace.values, source_index, trace.values[source_index] ^ 1, "equation")
    mutate(trace.values, source_index, 256, "byte-range")
    mutate(trace.ops, xor_index, AND, "descriptor")
    mutate(trace.left, xor_index, xor_index, "forward-reference")
    mutate(trace.left, xor_index, 0 if trace.left[xor_index] != 0 else 1, "descriptor")
    mutate(trace.args, xor_index, 1, "descriptor")
    mutate(trace.values, bit_index, 2, "bit-range")
    mutate(trace.values, partial_index, trace.values[partial_index] ^ 1, "equation")
    mutate(trace.values, sum_index, trace.values[sum_index] ^ 1, "sum-equation")
    old_sum, old_carry = trace.values[sum_index], trace.values[carry_index]
    try:
        trace.values[sum_index] ^= 1
        trace.values[carry_index] ^= 1
        typed_error("carry-equation", replay)
        count += 1
    finally:
        trace.values[sum_index], trace.values[carry_index] = old_sum, old_carry
    replay()
    arrays = (trace.values, trace.left, trace.right, trace.ops, trace.args)
    removed = tuple(a.pop() for a in arrays)
    try:
        typed_error("truncated-trace", replay)
        count += 1
    finally:
        for a, value in zip(arrays, removed):
            a.append(value)
    replay()
    for a in arrays:
        a.append(a[-1])
    try:
        typed_error("trailing-trace", replay)
        count += 1
    finally:
        for a in arrays:
            a.pop()
    replay()
    roots = trace.roots
    try:
        trace.roots = roots[:-1] + (roots[0],)
        typed_error("terminal-roots", replay)
        count += 1
    finally:
        trace.roots = roots
    replay()
    return {"typed_refusals": count, "restored_complete_replays": count}


WRONG = ("added-encryption-nots", "omitted-key-nots", "bit-planes", "key-rotation",
         "updated-mix", "counter-little", "counter-one", "hash-plaintext",
         "combined-padding", "byte-lengths", "no-reversal", "stale-reduction",
         "omitted-reduction", "mask-zero")


def main():
    require(sys.version_info[:3] == (3, 14, 5), "runtime-version")
    root = os.path.dirname(os.path.abspath(__file__))
    records = load_records(os.path.join(root, "fixtures", "primary.json"))
    positives = []
    for i, record in enumerate(records):
        output, trace, nodes = check_record(record)
        require(output == record[4] + record[5], "primary-kat")
        positives.append({"record": i, "word_nodes": nodes, "ciphertext_and_tag": output.hex()})
        del trace
    wrong = []
    for variant in WRONG:
        # Nonaligned AAD and body are required to distinguish combined padding.
        # Every other changed operation is present in the complete shorter KAT.
        control_index = 5 if variant == "combined-padding" else 3
        control = records[control_index]
        output, trace, nodes = check_record(control, variant, replay=False)
        require(output != control[4] + control[5], "wrong-alternative-not-detected")
        del trace
        restored, trace, _ = check_record(control, replay=False)
        require(restored == control[4] + control[5], "restored-kat")
        del trace
        wrong.append({"variant": variant, "primary_record": control_index, "word_nodes": nodes})
    ordinary = (bytes(range(32)), bytes(range(12)), bytes((5 * i + 3) & 255 for i in range(1789)),
                bytes((11 * i + 7) & 255 for i in range(418)), b"", b"")
    output, trace, nodes = check_record(ordinary)
    require(len(output) == 434, "ordinary-output-shape")
    require(trace.stats == {"logical_aes_requests": 29, "represented_multiplications": 140},
            "ordinary-action-counts")
    ordinary_result = {"word_nodes": nodes, "logical_aes_requests": trace.stats["logical_aes_requests"],
                       "ghash_message_blocks": trace.stats["represented_multiplications"],
                       "candidate_ciphertext_and_tag": output.hex(), "independent_expected": False}
    del trace
    result = {"format": "kova.gcm-word.reference.v1", "primary_kats": positives,
              "wrong_whole_alternatives": wrong, "fresh_restored_primary_computations": len(wrong),
              "ordinary_synthetic": ordinary_result, "routing_positions": routes(),
              "batch": separation(records[2][0]), "zero_key_multiplications": zero_hash(),
              "typed_input_refusals": input_refusals(records[2]),
              "trace_controls": trace_refusals(records[2]),
              "word_bit_representation": "Canonical host words, vectorized Boolean/fulladder equations",
              "scope": "Public synthetic integer GCM encryption, not RustCrypto execution or private proof"}
    encoded = (json.dumps(result, indent=2) + "\n").encode("utf-8")
    require(len(encoded) <= 65536, "result-bound")
    directory = os.path.join(root, "results")
    os.makedirs(directory, exist_ok=True)
    with open(os.path.join(directory, "result.json"), "xb") as destination:
        destination.write(encoded)
    summary = json.dumps({"primary_kats": len(positives), "wrong_alternatives": len(wrong),
                          "ordinary_word_nodes": nodes, "status": "passed"})
    require(len(summary.encode()) <= 16384, "stdout-bound")
    print(summary)


if __name__ == "__main__":
    main()
