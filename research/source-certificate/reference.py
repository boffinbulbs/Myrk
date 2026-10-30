"""Independent integer reference for the compressed source-read inventory.

No producer modules are imported.  expected() performs one scalar row sweep;
validate() is pure and reuses that result for later metadata mutation checks.
Narrative metadata is a reviewed, pinned manifest input, not a new derivation.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import stat

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source certificates")

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 512 * 1024
ROWS = 8192
BANK_ORDER = ("key", "signature", "note")
BANK_SIZE = {"key": 2592, "signature": 4627, "note": 418}
METRICS = [
    "read_occurrences", "unique_bytes", "unique_words", "alignment_bytes",
    "virtual_padding_bytes", "locally_ranged_bytes", "unassigned_word_bytes",
    "naive_decomposition_bits",
]
LANDMARKS = {
    0, 5, 6, 11, 12, 233, 234, 255, 256, 353, 354, 371, 372, 413,
    414, 447, 448, 5369, 5370, 8191,
}
FAMILY_NAMES = {
    "hash_challenge", "hash_owner", "hash_tr", "hash_note", "rho", "t1",
    "z", "hint", "cuts", "note_context", "note_owner", "note_fixed",
    "final_challenge",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        require(key not in result, "Duplicate JSON key")
        result[key] = value
    return result


def _bad_constant(_value):
    raise AssertionError("Non-finite JSON number")


def bounded_bytes(path):
    with Path(path).open("rb") as source:
        require(stat.S_ISREG(os.fstat(source.fileno()).st_mode),
                "A regular input file is required")
        raw = source.read(CAP + 1)
    require(len(raw) <= CAP, "Input exceeds the fixed 512 KiB bound")
    return raw


def read_json(path):
    return json.loads(bounded_bytes(path), object_pairs_hook=_unique_object,
                      parse_constant=_bad_constant)


def text_identity(raw):
    normalized = raw.replace(b"\r\n", b"\n")
    return {"bytes": len(normalized),
            "sha256": hashlib.sha256(normalized).hexdigest()}


def _same(actual, wanted, where):
    require(type(actual) is type(wanted), "Type mismatch at " + where)
    if isinstance(wanted, dict):
        require(actual.keys() == wanted.keys(), "Key mismatch at " + where)
        for key in wanted:
            _same(actual[key], wanted[key], where + "." + key)
    elif isinstance(wanted, list):
        require(len(actual) == len(wanted), "Length mismatch at " + where)
        for index, value in enumerate(wanted):
            _same(actual[index], value, where + "[" + str(index) + "]")
    else:
        require(actual == wanted, "Value mismatch at " + where)


def _spans(values):
    """Half-open contiguous spans from an integer set."""
    result = []
    for value in sorted(values):
        if result and value == result[-1][1]:
            result[-1][1] += 1
        else:
            result.append([value, value + 1])
    return result


def _rle(values):
    result = []
    for index, value in enumerate(values):
        if result and result[-1][2] == value:
            result[-1][1] = index + 1
        else:
            result.append([index, index + 1, value])
    return result


def _note_constants():
    # Literal byte frames, independently organized as complete prefix blocks.
    prefixes = {
        0: b"\0\0\0\x23", 39: b"\0\0\0\x02", 45: b"\0\0\0\x20",
        81: b"\0\0\0\x04", 89: b"\0\0\0\x20", 125: b"\0\0\0\x08",
        137: b"\0\0\0\x40", 205: b"\0\0\0\x40",
        273: b"\0\0\0\x40", 341: b"\0\0\0\x20",
        377: b"\0\0\0\x20", 413: b"\0\0\0\x01",
    }
    fixed = {}
    for start, data in prefixes.items():
        for offset, value in enumerate(data):
            require(start + offset not in fixed, "Overlapping note frame")
            fixed[start + offset] = value
    for offset, value in enumerate(b"thorum.relation-lab.note-opening.v2", 4):
        fixed[offset] = value
    fixed[43], fixed[44], fixed[417] = 0, 2, 0
    require(len(fixed) == 86, "Independent fixed-note count")
    return fixed


def _fixed(data):
    return [("fixed", value) for value in data]


def _tagged(bank, count):
    return [(bank, index) for index in range(count)]


def _pad(stream, rate, suffix):
    # Assemble a padded stream before splitting into blocks, rather than
    # classifying each output byte using the producer's offset branches.
    result = list(stream) + [("fixed", suffix)]
    result.extend([("fixed", 0)] * ((-len(result)) % rate))
    tag, value = result[-1]
    require(tag == "fixed", "Padding terminator must be fixed")
    result[-1] = (tag, value | 128)
    return result


def _initial_messages():
    key = _tagged("key", 2592)
    pure = _fixed(b"\0\x29Thorum crypto laboratory authorization v1")
    pure += _tagged("public", 196)
    require(len(pure) == 239, "Independent pure-message length")
    mu = _tagged("TR", 64) + pure
    note = _fixed(b"\0\0\0\x26thorum.relation-lab.note-commitment.v2")
    note += _fixed(b"\0\0\x01\xa2") + _tagged("note", 418)
    require(len(mu) == 303 and len(note) == 464, "Independent preimage lengths")
    challenge = _pad(_tagged("signature", 64), 136, 31)
    groups = [
        ("challenge", 136, challenge + [("fixed", 0)] * 136, 2),
        ("owner", 72, _pad(key, 72, 6), 37),
        ("tr", 136, _pad(key, 136, 31), 20),
        ("mu", 136, _pad(mu, 136, 31), 3),
        ("note", 72, _pad(note, 72, 6), 7),
    ]
    result = []
    for kind, rate, stream, block_count in groups:
        require(len(stream) == rate * block_count, "Independent block count")
        for block in range(block_count):
            permutation = len(result)
            message = stream[block * rate:(block + 1) * rate]
            message = message + [("fixed", 0)] * (168 - rate)
            result.append({
                "permutation": permutation, "kind": kind, "block": block,
                "rate": rate, "rows": [6 * permutation, 6 * permutation + 6],
                "message": message,
                "continuation_to_next": block + 1 < block_count,
            })
    require(len(result) == 69, "Independent initial permutation count")
    return result


def _direct_descriptions():
    # Record descriptors are checked as well as their independently enumerated
    # address effects.  The range booleans are conservative annotations only.
    rows = [
        ("rho", "key", [0, 1], 0, 32, 0, "next.RHO", False),
        ("t1", "key", [0, 256], 32, 10, 10, "T1_MESSAGE", True),
        ("z", "signature", [0, 448], 64, 10, 10, "Z_MESSAGE", True),
        ("hint", "signature", [0, 75], 4544, 1, 1, "HINT_MESSAGE", True),
        ("cuts", "signature", [0, ROWS], 4619, 8, 0, "CUTS", True),
        ("note_context", "note", [0, ROWS], 49, 32, 0, "public[52..84]", False),
        ("note_owner", "note", [234, 235], 141, 64, 0, "OWNER", True),
        ("final_challenge", "signature", [5369, 5370], 0, 64, 0, "OUTPUT", True),
    ]
    keys = ("name", "bank", "rows", "first", "count", "stride", "target",
            "range_annotation")
    return [dict(zip(keys, row)) for row in rows]


def _events(row, fixed_offsets):
    """Explicit physical-row pieces; never derive reads from initial segments."""
    events = []
    if row < 6:
        events.append(("hash_challenge", "signature", range(64), True))
    if 12 <= row < 228:
        first = ((row - 12) // 6) * 72
        events.append(("hash_owner", "key", range(first, first + 72), True))
    if 234 <= row < 354:
        first = ((row - 234) // 6) * 136
        events.append(("hash_tr", "key", range(first, min(first + 136, 2592)), True))
    if 372 <= row < 414:
        start = ((row - 372) // 6) * 72
        first, stop = max(start, 46) - 46, min(start + 72, 464) - 46
        if first < stop:
            events.append(("hash_note", "note", range(first, stop), True))
    if row == 0:
        events.append(("rho", "key", range(32), False))
    if row < 256:
        first = 32 + 10 * row
        events.append(("t1", "key", range(first, first + 10), True))
    if row < 448:
        first = 64 + 10 * row
        events.append(("z", "signature", range(first, first + 10), True))
    if row < 75:
        events.append(("hint", "signature", range(4544 + row, 4545 + row), True))
    events.append(("cuts", "signature", range(4619, 4627), True))
    # Public fields are NOT treated as intrinsically byte-valued.
    events.append(("note_context", "note", range(49, 81), False))
    if row == 234:
        # Known byte expressions from the retained previous OUTPUT producer
        # and holds, not a new local decomposition or a certificate theorem.
        events.append(("note_owner", "note", range(141, 205), True))
    if row == 5369:
        events.append(("final_challenge", "signature", range(64), True))
    events.append(("note_fixed", "note", fixed_offsets, True))
    return events


def _row(row, fixed_offsets):
    raw = {bank: set() for bank in BANK_ORDER}
    known = {bank: set() for bank in BANK_ORDER}
    events = _events(row, fixed_offsets)
    occurrences = 0
    for _name, bank, addresses, has_known_byte_expression in events:
        require(all(0 <= value < BANK_SIZE[bank] for value in addresses),
                "Independent address outside its bank")
        raw[bank].update(addresses)
        if has_known_byte_expression:
            known[bank].update(addresses)
        occurrences += len(addresses)
    words = {bank: {value // 3 for value in raw[bank]} for bank in BANK_ORDER}
    real = {}
    padding = 0
    for bank in BANK_ORDER:
        triplets = {3 * word + offset for word in words[bank] for offset in (0, 1, 2)}
        real[bank] = {value for value in triplets if value < BANK_SIZE[bank]}
        padding += len(triplets) - len(real[bank])
    word_count = sum(len(words[bank]) for bank in BANK_ORDER)
    metrics = [
        occurrences, sum(len(raw[bank]) for bank in BANK_ORDER), word_count,
        sum(len(real[bank] - raw[bank]) for bank in BANK_ORDER), padding,
        sum(len(known[bank]) for bank in BANK_ORDER),
        sum(len(real[bank] - known[bank]) for bank in BANK_ORDER),
        24 * word_count,
    ]
    return raw, words, known, real, metrics, events


def _detail(row, state):
    raw, words, known, real, metrics, events = state
    banks = {}
    for bank in BANK_ORDER:
        banks[bank] = {
            "byte_ranges": _spans(raw[bank]), "word_ranges": _spans(words[bank]),
            "alignment_ranges": _spans(real[bank] - raw[bank]),
            "unassigned_ranges": _spans(real[bank] - known[bank]),
        }
    return {"row": row, "metrics": metrics,
            "families": [event[0] for event in events], "banks": banks}


def _core():
    fixed = _note_constants()
    fixed_offsets = tuple(sorted(fixed))
    first = {bank: [-1] * BANK_SIZE[bank] for bank in BANK_ORDER}
    last = {bank: [-1] * BANK_SIZE[bank] for bank in BANK_ORDER}
    counts = {bank: [0] * BANK_SIZE[bank] for bank in BANK_ORDER}
    word_first = {bank: [-1] * ((BANK_SIZE[bank] + 2) // 3) for bank in BANK_ORDER}
    word_last = {bank: [-1] * ((BANK_SIZE[bank] + 2) // 3) for bank in BANK_ORDER}
    addresses_hash, metrics_hash = hashlib.sha256(), hashlib.sha256()
    runs, totals, maxima, peaks = [], [0] * 8, [-1] * 8, [-1] * 8
    family_counts, details = {}, {}
    for row in range(ROWS):
        state = _row(row, fixed_offsets)
        raw, words, _known, _real, metrics, events = state
        for bank in BANK_ORDER:
            line = str(row) + ":" + bank + ":" + ",".join(str(v) for v in sorted(raw[bank])) + "\n"
            addresses_hash.update(line.encode("ascii"))
            for value in raw[bank]:
                if first[bank][value] == -1:
                    first[bank][value] = row
                last[bank][value] = row
                counts[bank][value] += 1
            for value in words[bank]:
                if word_first[bank][value] == -1:
                    word_first[bank][value] = row
                word_last[bank][value] = row
        metrics_hash.update((json.dumps([row] + metrics, separators=(",", ":")) + "\n").encode("ascii"))
        for index, value in enumerate(metrics):
            totals[index] += value
            if value > maxima[index]:
                maxima[index], peaks[index] = value, row
        if runs and runs[-1][2] == metrics:
            runs[-1][1] = row + 1
        else:
            runs.append([row, row + 1, metrics])
        for name, _bank, values, _known_range in events:
            if name not in family_counts:
                family_counts[name] = {"rows": 0, "read_occurrences": 0}
            family_counts[name]["rows"] += 1
            family_counts[name]["read_occurrences"] += len(values)
        keep = LANDMARKS | set(peaks)
        if row in keep:
            details[row] = _detail(row, state)
        for previous in tuple(details):
            if previous not in keep:
                del details[previous]
    require(set(family_counts) == FAMILY_NAMES, "Independent complete family set")
    require(all(-1 not in first[bank] for bank in BANK_ORDER), "Independent byte coverage gap")
    require(all(-1 not in word_first[bank] for bank in BANK_ORDER), "Independent word coverage gap")
    coverage = {}
    for bank in BANK_ORDER:
        coverage[bank] = {
            "bytes": BANK_SIZE[bank], "words": len(word_first[bank]), "gaps": [],
            "first_rows": _rle(first[bank]), "last_rows": _rle(last[bank]),
            "read_row_counts": _rle(counts[bank]),
            "word_first_rows": _rle(word_first[bank]), "word_last_rows": _rle(word_last[bank]),
        }
    fixed_words = [word for word in range(140)
                   if all(index >= 418 or index in fixed for index in range(3 * word, 3 * word + 3))]
    lower = set()
    for bank, lo, hi in [
        ("key", 0, 135), ("key", 2372, 2381),
        ("signature", 2404, 2413), ("signature", 4619, 4626),
        ("note", 49, 80), ("note", 141, 204),
    ]:
        lower.update((bank, value // 3) for value in range(lo, hi + 1))
    require(len(lower) == 91, "Independent row234 lower bound")
    return {
        "format": "kova.source-certificate.v1",
        "scope": "Fixed scalar source inventory, not AIR evaluation or an integrated layout",
        "rows": ROWS, "retained_width": 45266, "private_banks": dict(BANK_SIZE),
        "held_words": {bank: (BANK_SIZE[bank] + 2) // 3 for bank in BANK_ORDER},
        "hold_invariant": {"current_to_next": True, "transition_rows": [0, 8191],
                           "byte_equations_per_transition": 7637, "decoded_port_demand": False},
        "initial_blocks": _initial_messages(), "direct_families": _direct_descriptions(),
        "fixed_note": [[index, fixed[index]] for index in fixed_offsets],
        "fixed_note_words": fixed_words,
        "virtual_padding": {"signature": [4627, 4628], "note": [418, 419]},
        "family_counts": family_counts, "metric_names": list(METRICS),
        "metric_totals": totals, "metric_maxima": maxima, "metric_peak_rows": peaks,
        "metric_runs": runs, "address_digest": addresses_hash.hexdigest(),
        "metric_digest": metrics_hash.hexdigest(), "coverage": coverage,
        "detailed_rows": [details[row] for row in sorted(LANDMARKS | set(peaks))],
        "row234_lower_bound": 91,
        "analysis_limits": {"symbolic_collections": 0, "native_traces": 0,
                            "backend_proofs": 0, "integrated_layout": False,
                            "net_savings_measured": False,
                            "public_fields_intrinsically_bytes": False, "max_artifact_bytes": CAP},
        "producer_dependencies": [
            ["RHO", 0, 1], ["CHALLENGE_XOF_LOW", 5, 6], ["CHALLENGE_XOF_HIGH", 11, 12],
            ["OWNER", 233, 234], ["TR", 353, 354], ["MU", 371, 372],
            ["NOTE_COMMITMENT", 413, 414], ["T1_LAST", 255, 256], ["Z_LAST", 447, 448],
        ],
    }


def _manifest_inputs(path):
    raw = bounded_bytes(path)
    manifest = json.loads(raw, object_pairs_hook=_unique_object, parse_constant=_bad_constant)
    require(manifest.get("format") == "kova.source-certificate.sources.v1", "Unknown source manifest")
    files = manifest.get("files")
    require(type(files) is dict and len(files) == 23, "Expected 23 pinned source inputs")
    texts, root = {}, ROOT.resolve()
    for name, wanted in files.items():
        require(type(name) is str and "\\" not in name and ":" not in name,
                "Source path must be repository relative")
        parts = PurePosixPath(name)
        require(not parts.is_absolute() and name == parts.as_posix()
                and all(part not in ("", ".", "..") for part in parts.parts), "Unsafe source path")
        source = root.joinpath(*parts.parts)
        require(not source.is_symlink() and source.resolve().is_relative_to(root), "Source path escapes root")
        contents = bounded_bytes(source)
        _same(text_identity(contents), wanted, "sources." + name)
        texts[name] = contents.decode("utf-8")
    anchors = manifest.get("read_family_sources")
    require(type(anchors) is dict and set(anchors) == FAMILY_NAMES, "Expected 13 source-family anchors")
    for name, anchor in anchors.items():
        require(type(anchor) is dict and anchor.get("path") in texts, "Unknown anchor path")
        lines = texts[anchor["path"]].splitlines()
        line = anchor.get("line")
        require(type(line) is int and 1 <= line <= len(lines), "Invalid anchor line")
        require(type(anchor.get("anchor")) is str and anchor["anchor"]
                and anchor["anchor"] in lines[line - 1], "Source anchor mismatch: " + name)
    lexical = {}
    for name, contents in texts.items():
        if name.endswith(".rs"):
            hits = [[index, line.strip()] for index, line in enumerate(contents.splitlines(), 1)
                    if re.search(r"\b(?:KEY|SIGNATURE|NOTE)\b", line)]
            if hits:
                lexical[name] = hits
    # These narratives are shared, source-pinned inputs, not numerical or
    # cryptographic conclusions independently recomputed by this reference.
    metadata = {key: manifest[key] for key in (
        "scratch_ledger", "unchanged_preimages", "read_family_sources",
        "lexical_classification", "unresolved_obligations",
    )}
    classification = metadata["lexical_classification"]
    require(type(classification) is dict and classification.keys() == lexical.keys(),
            "Lexical classification does not cover the pinned accesses")
    for name, hits in lexical.items():
        labels = classification[name]
        require(type(labels) is list and len(labels) == len(hits),
                "Lexical classification length mismatch")
        for label, (number, code) in zip(labels, hits):
            require(type(label) is dict and label.keys() == {"line", "code", "role"},
                    "Invalid lexical classification record")
            _same(label["line"], number, "lexical_classification.line")
            _same(label["code"], code, "lexical_classification.code")
            require(type(label["role"]) is str and label["role"] in
                    {"declaration", "constructor", "invariant", "consumer"},
                    "Unknown reviewed lexical classification role")
    ledger = metadata["scratch_ledger"]
    require(type(ledger) is list and len(ledger) == 11, "Expected 11 reviewed scratch entries")
    require(all(entry.get("occupied") is True and entry.get("reuse_requires_equation_review") is True
                for entry in ledger), "Scratch must remain occupied pending review")
    public = metadata["unchanged_preimages"]["public"]
    require(public.get("fields") == 196 and public.get("intrinsically_bytes") is False,
            "Public fields cannot be assumed intrinsically bytes")
    return text_identity(raw), lexical, metadata


def expected(sources_path=None):
    """Build expected once.  Does not import producer modules or write files."""
    source_id, lexical, metadata = _manifest_inputs(
        HERE / "sources.json" if sources_path is None else Path(sources_path))
    result = _core()
    result["source_manifest"] = source_id
    result["lexical_accesses"] = lexical
    result.update(metadata)
    return result


def _expand_segments(segments):
    require(type(segments) is list and 1 <= len(segments) <= 168, "Invalid message segments")
    message = []
    sizes = dict(BANK_SIZE, TR=64, public=196)
    for segment in segments:
        require(type(segment) is dict, "Segment must be an object")
        tag = segment.get("source")
        require(type(tag) is str and (tag == "fixed" or tag in sizes),
                "Unknown preimage source tag")
        wanted = {"target_byte", "length", "source", "bytes_hex" if tag == "fixed" else "first_byte"}
        require(segment.keys() == wanted, "Invalid segment keys")
        first, count = segment["target_byte"], segment["length"]
        require(type(first) is int and first == len(message)
                and type(count) is int and 1 <= count <= 168 - first,
                "Gap, overlap or invalid segment length")
        if tag == "fixed":
            encoded = segment["bytes_hex"]
            require(type(encoded) is str and re.fullmatch(r"[0-9a-f]*", encoded) is not None
                    and len(encoded) == 2 * count, "Invalid fixed preimage bytes")
            message.extend((tag, value) for value in bytes.fromhex(encoded))
        else:
            address = segment["first_byte"]
            require(type(address) is int and 0 <= address and address + count <= sizes[tag],
                    "Preimage source address outside its domain")
            message.extend((tag, value) for value in range(address, address + count))
    require(len(message) == 168, "Initial message must cover all 168 bytes")
    return message


def validate(record, wanted):
    """Pure assertion checker.  Reuses cached expected and never sweeps rows."""
    require(type(record) is dict and type(wanted) is dict, "Certificate must be an object")
    require(record.keys() == wanted.keys(), "Certificate top-level schema mismatch")
    for key in wanted:
        if key != "initial_blocks":
            _same(record[key], wanted[key], key)
    blocks = record["initial_blocks"]
    require(type(blocks) is list and len(blocks) == 69, "Expected 69 initial blocks")
    for index, target in enumerate(wanted["initial_blocks"]):
        block = blocks[index]
        require(type(block) is dict and block.keys() == target.keys(), "Initial block schema mismatch")
        for key in target:
            if key != "message":
                _same(block[key], target[key], "initial_blocks[" + str(index) + "]." + key)
        require(_expand_segments(block["message"]) == target["message"],
                "Independent expanded initial preimage mismatch at " + str(index))
    return True


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check-file", type=Path, required=True)
    parser.add_argument("--sources", type=Path, default=HERE / "sources.json")
    args = parser.parse_args()
    wanted = expected(args.sources)
    validate(read_json(args.check_file), wanted)
    print(json.dumps({"validated": True, "reference_passes": 1, "rows": ROWS,
                      "metadata_checks_only": True, "native_traces": 0, "backend_proofs": 0}))


if __name__ == "__main__":
    main()
