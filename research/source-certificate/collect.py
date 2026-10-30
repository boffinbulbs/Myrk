"""Bounded scalar inventory of pinned full signature source reads."""
import argparse
import hashlib
import io
import json
from pathlib import Path
import re

if not __debug__:
    raise RuntimeError("Optimized Python cannot check source certificates")
import model
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
CAP = 512 * 1024
METRICS = ["read_occurrences", "unique_bytes", "unique_words", "alignment_bytes", "virtual_padding_bytes", "locally_ranged_bytes", "unassigned_word_bytes", "naive_decomposition_bits"]


def bounded_read(path):
    with path.open("rb") as file:
        data = file.read(CAP + 1)
    assert len(data) <= CAP, "Source input exceeds the fixed artifact bound"
    return data


def identity(path):
    data = bounded_read(path).replace(b"\r\n", b"\n")
    return dict(bytes=len(data), sha256=hashlib.sha256(data).hexdigest())


def verify_sources():
    manifest = json.loads(bounded_read(HERE / "sources.json"))
    assert manifest["format"] == "kova.source-certificate.sources.v1"
    assert len(manifest["files"]) == 23 and len(manifest["read_family_sources"]) == 13
    for path, expected in manifest["files"].items():
        source = ROOT / path
        assert not source.is_symlink() and source.resolve().is_relative_to(ROOT.resolve()), path
        assert identity(source) == expected, path
    return manifest


def ranges(values):
    result = []
    for value in sorted(values):
        if result and result[-1][1] == value:
            result[-1][1] = value + 1
        else:
            result.append([value, value + 1])
    return result


def compress(values):
    result = []
    for index, value in enumerate(values):
        if result and result[-1][2] == value:
            result[-1][1] = index + 1
        else:
            result.append([index, index + 1, value])
    return result


def lexical_accesses(manifest):
    result = {}
    for name in manifest["files"]:
        if not name.endswith(".rs"):
            continue
        hits = [[i, line.strip()] for i, line in enumerate(bounded_read(ROOT / name).decode().splitlines(), 1) if re.search(r"\b(KEY|SIGNATURE|NOTE)\b", line)]
        if hits:
            result[name] = hits
    return result


def row_state(row, blocks, fixed):
    raw = {bank: set() for bank in model.BANKS}
    local = {bank: set() for bank in model.BANKS}
    families = []
    occurrences = 0
    for name, bank, addresses, ranged in model.reads(row, blocks, fixed):
        assert all(0 <= i < model.BANKS[bank] for i in addresses)
        raw[bank].update(addresses)
        if ranged:
            local[bank].update(addresses)
        occurrences += len(addresses)
        families.append(name)
    words = {bank: {i // 3 for i in raw[bank]} for bank in raw}
    expanded = {bank: {3 * word + j for word in words[bank] for j in range(3)} for bank in words}
    real = {bank: {i for i in expanded[bank] if i < model.BANKS[bank]} for bank in words}
    padding = sum(len(expanded[bank] - real[bank]) for bank in words)
    metrics = [occurrences, sum(map(len, raw.values())), sum(map(len, words.values())),
               sum(len(real[b] - raw[b]) for b in raw), padding, sum(map(len, local.values())),
               sum(len(real[b] - local[b]) for b in raw), 24 * sum(map(len, words.values()))]
    return raw, words, local, real, metrics, families


def detail(row, blocks, fixed):
    raw, words, local, real, metrics, families = row_state(row, blocks, fixed)
    return dict(row=row, metrics=metrics, families=families, banks={bank: dict(byte_ranges=ranges(raw[bank]),
        word_ranges=ranges(words[bank]), alignment_ranges=ranges(real[bank] - raw[bank]),
        unassigned_ranges=ranges(real[bank] - local[bank])) for bank in model.BANKS})


def build():
    manifest = verify_sources()
    blocks = model.initial_blocks()
    fixed = model.fixed_note()
    first = {b: [-1] * size for b, size in model.BANKS.items()}
    last = {b: [-1] * size for b, size in model.BANKS.items()}
    counts = {b: [0] * size for b, size in model.BANKS.items()}
    first_word = {b: [-1] * ((size + 2) // 3) for b, size in model.BANKS.items()}
    last_word = {b: [-1] * ((size + 2) // 3) for b, size in model.BANKS.items()}
    digest = hashlib.sha256()
    metric_digest = hashlib.sha256()
    runs, total, family_counts = [], [0] * len(METRICS), {}
    maxima, peak_rows = [-1] * len(METRICS), [-1] * len(METRICS)
    for row in range(model.HEIGHT):
        raw, words, local, real, metrics, families = row_state(row, blocks, fixed)
        for bank in model.BANKS:
            digest.update(f"{row}:{bank}:".encode() + ",".join(map(str, sorted(raw[bank]))).encode() + b"\n")
            for byte in raw[bank]:
                if first[bank][byte] < 0:
                    first[bank][byte] = row
                last[bank][byte] = row
                counts[bank][byte] += 1
            for word in words[bank]:
                if first_word[bank][word] < 0:
                    first_word[bank][word] = row
                last_word[bank][word] = row
        metric_digest.update((json.dumps([row] + metrics, separators=(",", ":")) + "\n").encode())
        for index, value in enumerate(metrics):
            total[index] += value
            if value > maxima[index]:
                maxima[index], peak_rows[index] = value, row
        if runs and runs[-1][2] == metrics:
            runs[-1][1] = row + 1
        else:
            runs.append([row, row + 1, metrics])
        for name, _, addresses, _ in model.reads(row, blocks, fixed):
            entry = family_counts.setdefault(name, dict(rows=0, read_occurrences=0))
            entry["rows"] += 1
            entry["read_occurrences"] += len(addresses)
    assert set(family_counts) == {"hash_owner", "hash_tr", "hash_challenge", "hash_note", "rho", "t1", "z", "hint", "cuts", "note_context", "note_owner", "note_fixed", "final_challenge"}
    assert all(-1 not in first[bank] for bank in model.BANKS)
    fixed_words = []
    for word in range(140):
        indices = range(word * 3, word * 3 + 3)
        if all(i >= 418 or i in fixed for i in indices):
            fixed_words.append(word)
    lower_bound_families = {"hash_tr", "t1", "z", "cuts", "note_context", "note_owner"}
    lower_bound_words = {(bank, i // 3) for name, bank, indices, _ in model.reads(234, blocks, fixed)
                         if name in lower_bound_families for i in indices}
    row234_lower_bound = len(lower_bound_words)
    assert row234_lower_bound == 91
    coverage = {b: dict(bytes=model.BANKS[b], words=len(first_word[b]), gaps=[], first_rows=compress(first[b]),
        last_rows=compress(last[b]), read_row_counts=compress(counts[b]), word_first_rows=compress(first_word[b]), word_last_rows=compress(last_word[b])) for b in model.BANKS}
    selected = sorted(set([0, 5, 6, 11, 12, 233, 234, 255, 256, 353, 354, 371, 372, 413, 414, 447, 448, 5369, 5370, 8191] + peak_rows))
    return dict(format="kova.source-certificate.v1", source_manifest=identity(HERE / "sources.json"),
        scope="Fixed scalar source inventory, not AIR evaluation or an integrated layout", rows=8192, retained_width=45266,
        private_banks=model.BANKS, held_words={b: (n + 2) // 3 for b, n in model.BANKS.items()},
        hold_invariant=dict(current_to_next=True, transition_rows=[0, 8191], byte_equations_per_transition=7637, decoded_port_demand=False),
        initial_blocks=blocks, direct_families=[dict(name=f.name, bank=f.bank, rows=list(f.rows), first=f.first, count=f.count,
            stride=f.stride, target=f.target, range_annotation=f.local_range) for f in model.DIRECT],
        fixed_note=sorted(fixed.items()), fixed_note_words=fixed_words,
        virtual_padding={"signature": [4627, 4628], "note": [418, 419]}, family_counts=family_counts,
        metric_names=METRICS, metric_totals=total, metric_maxima=maxima, metric_peak_rows=peak_rows, metric_runs=runs,
        address_digest=digest.hexdigest(), metric_digest=metric_digest.hexdigest(), coverage=coverage,
        detailed_rows=[detail(row, blocks, fixed) for row in selected], row234_lower_bound=row234_lower_bound,
        lexical_accesses=lexical_accesses(manifest), lexical_classification=manifest["lexical_classification"],
        analysis_limits=dict(symbolic_collections=0, native_traces=0, backend_proofs=0, integrated_layout=False,
            net_savings_measured=False, public_fields_intrinsically_bytes=False, max_artifact_bytes=CAP),
        producer_dependencies=[["RHO", 0, 1], ["CHALLENGE_XOF_LOW", 5, 6], ["CHALLENGE_XOF_HIGH", 11, 12],
            ["OWNER", 233, 234], ["TR", 353, 354], ["MU", 371, 372], ["NOTE_COMMITMENT", 413, 414],
            ["T1_LAST", 255, 256], ["Z_LAST", 447, 448]],
        scratch_ledger=manifest["scratch_ledger"], unchanged_preimages=manifest["unchanged_preimages"],
        read_family_sources=manifest["read_family_sources"], unresolved_obligations=manifest["unresolved_obligations"])


def bounded_encode(record):
    result = io.BytesIO()
    for part in json.JSONEncoder(sort_keys=True, separators=(",", ":"), ensure_ascii=True).iterencode(record):
        data = part.encode()
        if result.tell() + len(data) + 1 > CAP:
            raise ValueError("Source certificate exceeds its fixed artifact cap")
        result.write(data)
    result.write(b"\n")
    return result.getvalue()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    assert not args.output.exists(), "A certificate output already exists"
    raw = bounded_encode(build())
    args.output.parent.mkdir(exist_ok=True)
    with args.output.open("xb") as file:
        file.write(raw)
    print(json.dumps(dict(certificate_bytes=len(raw), rows=8192, generator_passes=1, native_traces=0, backend_proofs=0)))


if __name__ == "__main__":
    main()
