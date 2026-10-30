"""Fixed scalar read families. No AIR, field matrix or proving backend imports."""
from dataclasses import dataclass

HEIGHT = 8192
BANKS = {"key": 2592, "signature": 4627, "note": 418}
FIELDS = [(0, 35), (39, 2), (45, 32), (81, 4), (89, 32), (125, 8),
          (137, 64), (205, 64), (273, 64), (341, 32), (377, 32), (413, 1)]
PURE_CONTEXT = b"Thorum crypto laboratory authorization v1"
NOTE_DOMAIN = b"thorum.relation-lab.note-commitment.v2"
OPENING_DOMAIN = b"thorum.relation-lab.note-opening.v2"


def fixed_note():
    result = {start + j: value for start, size in FIELDS for j, value in enumerate(size.to_bytes(4, "big"))}
    result.update({4 + i: value for i, value in enumerate(OPENING_DOMAIN)})
    result.update({43: 0, 44: 2, 417: 0})
    assert len(result) == 86
    return result


def initial_source(p, byte):
    assert 0 <= p < 69 and 0 <= byte < 168
    if p < 2:
        kind, block, rate = "challenge", p, 136
    elif p < 39:
        kind, block, rate = "owner", p - 2, 72
    elif p < 59:
        kind, block, rate = "tr", p - 39, 136
    elif p < 62:
        kind, block, rate = "mu", p - 59, 136
    else:
        kind, block, rate = "note", p - 62, 72
    offset = block * rate + byte
    if byte >= rate:
        source = ("fixed", 0)
    elif kind == "challenge":
        source = ("signature", byte) if block == 0 and byte < 64 else ("fixed", 31 if block == 0 and byte == 64 else 128 if block == 0 and byte == 135 else 0)
    elif kind in ["owner", "tr"]:
        source = ("key", offset) if offset < 2592 else ("fixed", (6 if kind == "owner" else 31) if offset == 2592 else 128 if byte == rate - 1 else 0)
    elif kind == "mu":
        if offset < 64:
            source = ("TR", offset)
        elif 66 <= offset <= 106:
            source = ("fixed", PURE_CONTEXT[offset - 66])
        elif 107 <= offset <= 302:
            source = ("public", offset - 107)
        else:
            source = ("fixed", {65: 41, 303: 31, 407: 128}.get(offset, 0))
    elif offset < 4:
        source = ("fixed", (38).to_bytes(4, "big")[offset])
    elif offset < 42:
        source = ("fixed", NOTE_DOMAIN[offset - 4])
    elif offset < 46:
        source = ("fixed", (418).to_bytes(4, "big")[offset - 42])
    elif offset <= 463:
        source = ("note", offset - 46)
    else:
        source = ("fixed", {464: 6, 503: 128}.get(offset, 0))
    return kind, block, rate, source


def segments(sources):
    result = []
    index = 0
    while index < len(sources):
        tag, first = sources[index]
        stop = index + 1
        while stop < len(sources) and sources[stop][0] == tag and (tag == "fixed" or sources[stop][1] == first + stop - index):
            stop += 1
        item = dict(target_byte=index, length=stop - index, source=tag)
        if tag == "fixed":
            item["bytes_hex"] = bytes(value for _, value in sources[index:stop]).hex()
        else:
            item["first_byte"] = first
        result.append(item)
        index = stop
    return result


def initial_blocks():
    result = []
    for p in range(69):
        kind, block, rate, _ = initial_source(p, 0)
        result.append(dict(permutation=p, kind=kind, block=block, rate=rate,
                           rows=[6 * p, 6 * p + 6], message=segments([initial_source(p, j)[3] for j in range(168)]),
                           continuation_to_next=block + 1 < dict(challenge=2, owner=37, tr=20, mu=3, note=7)[kind]))
    return result


@dataclass(frozen=True)
class Family:
    name: str
    bank: str
    rows: tuple
    first: int
    count: int
    stride: int
    target: str
    local_range: bool

    def read(self, row):
        if self.rows[0] <= row < self.rows[1]:
            start = self.first + self.stride * (row - self.rows[0])
            return range(start, start + self.count)
        return ()


DIRECT = [
    Family("rho", "key", (0, 1), 0, 32, 0, "next.RHO", False),
    Family("t1", "key", (0, 256), 32, 10, 10, "T1_MESSAGE", True),
    Family("z", "signature", (0, 448), 64, 10, 10, "Z_MESSAGE", True),
    Family("hint", "signature", (0, 75), 4544, 1, 1, "HINT_MESSAGE", True),
    Family("cuts", "signature", (0, HEIGHT), 4619, 8, 0, "CUTS", True),
    Family("note_context", "note", (0, HEIGHT), 49, 32, 0, "public[52..84]", False),
    Family("note_owner", "note", (234, 235), 141, 64, 0, "OWNER", True),
    Family("final_challenge", "signature", (5369, 5370), 0, 64, 0, "OUTPUT", True),
]


def reads(row, blocks, fixed):
    assert 0 <= row < HEIGHT
    result = []
    if row < 414:
        entry = blocks[row // 6]
        for part in entry["message"]:
            if part["source"] in BANKS:
                start = part["first_byte"]
                name = dict(key="hash_" + entry["kind"], signature="hash_challenge", note="hash_note")[part["source"]]
                result.append((name, part["source"], range(start, start + part["length"]), True))
    for family in DIRECT:
        values = family.read(row)
        if values:
            result.append((family.name, family.bank, values, family.local_range))
    result.append(("note_fixed", "note", tuple(sorted(fixed)), True))
    return result
