"""Summarize retained conservation proof samples and render the research figure."""

import argparse
import csv
import hashlib
import io
import json
import math
from collections import defaultdict
from pathlib import Path


HERE = Path(__file__).resolve().parent
FIELDS = ["sample", "class", "operation", "elapsed_ns", "proof_bytes"]
SUMMARY_FIELDS = ["class", "operation", "n", "min_ns", "p50_ns", "p95_ns", "max_ns",
                  "min_proof_bytes", "max_proof_bytes"]


def median(values):
    ordered = sorted(values)
    a, b = ordered[(len(ordered) - 1) // 2], ordered[len(ordered) // 2]
    return str((a + b) // 2) + (".5" if (a + b) % 2 else "")


def load():
    raw = (HERE / "results/raw.csv").read_bytes()
    metadata = json.loads((HERE / "results/metadata.json").read_bytes())
    if hashlib.sha256(raw).hexdigest() != metadata["raw_csv_sha256"]:
        raise ValueError("Raw sample hash differs from the measurement record.")
    groups = defaultdict(dict)
    reader = csv.DictReader(io.StringIO(raw.decode("ascii")))
    if reader.fieldnames != FIELDS:
        raise ValueError("Unexpected raw CSV fields.")
    for row in reader:
        key = (row["class"], row["operation"])
        if key not in {(c, op) for c in ("A", "B") for op in ("prove", "verify")}:
            raise ValueError("Unexpected experiment class or operation.")
        sample, elapsed, size = (int(row[k]) for k in ("sample", "elapsed_ns", "proof_bytes"))
        if not 1 <= sample <= 20 or elapsed <= 0 or not 0 < size <= 2 * 1024 * 1024:
            raise ValueError("Invalid sample index, duration or proof length.")
        if sample in groups[key]:
            raise ValueError("Duplicate sample.")
        groups[key][sample] = (elapsed, size)
    if len(groups) != 4 or any(sorted(g) != list(range(1, 21)) for g in groups.values()):
        raise ValueError("Expected twenty samples in each of four groups.")
    for c in ("A", "B"):
        for sample in range(1, 21):
            if groups[c, "prove"][sample][1] != groups[c, "verify"][sample][1]:
                raise ValueError("Proving and verification lengths do not refer to the same proof.")
    if metadata["raw_sample_rows"] != 80 or metadata["proof_count"] != 40:
        raise ValueError("Metadata count differs from the fixed workload.")
    rows = []
    for (c, op), samples in sorted(groups.items()):
        elapsed = sorted(v[0] for v in samples.values())
        sizes = [v[1] for v in samples.values()]
        rows.append(dict(zip(SUMMARY_FIELDS, [c, op, len(elapsed), elapsed[0], median(elapsed),
                                              elapsed[18], elapsed[-1], min(sizes), max(sizes)])))
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, SUMMARY_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return groups, rows, stream.getvalue().encode("ascii"), metadata


def figure(groups, rows, metadata):
    import reportlab
    from reportlab.graphics import renderSVG
    from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String
    from reportlab.lib import colors

    if reportlab.Version != "4.4.9":
        raise RuntimeError("Figure reproduction requires ReportLab 4.4.9.")
    ink, gray, grid = (colors.HexColor(c) for c in ("#172A3A", "#657585", "#DFE5EA"))
    blue, orange = colors.HexColor("#225EA8"), colors.HexColor("#B75C22")
    d = Drawing(1120, 800)
    d.add(Rect(0, 0, 1120, 800, fillColor=colors.white, strokeColor=None))

    def text(x, y, value, size=11, color=ink, anchor="start", bold=False):
        d.add(String(x, y, value, fontName="Helvetica-Bold" if bold else "Helvetica",
                     fontSize=size, fillColor=color, textAnchor=anchor))

    text(55, 758, "Hiding conservation proof experiment", 25, bold=True)
    text(55, 732, "20 proof constructions per witness class. Same public fee and context. Serial release build.", color=gray)
    host = f'{metadata["cpu"]["model"]} | {metadata["os"]["name"]} build {metadata["os"]["build"]} | Rust 1.94.1'
    text(55, 710, host, 10, gray)
    text(55, 674, "A   Proving and verification latency", 16, bold=True)
    x0, x1 = 280, 805
    times = [v[0] / 1e6 for values in groups.values() for v in values.values()]
    lo, hi = math.floor(math.log10(min(times))), math.ceil(math.log10(max(times)))
    if hi == lo:
        hi += 1

    def tx(v):
        return x0 + (math.log10(v) - lo) / (hi - lo) * (x1 - x0)

    for exponent in range(lo, hi + 1):
        x = tx(10 ** exponent)
        d.add(Line(x, 432, x, 645, strokeColor=grid, strokeWidth=.8))
        text(x, 410, f"{10 ** exponent:g}", 10, gray, "middle")
    text(850, 645, "Median / p95 (ms)", 10, gray)
    for i, (op, c) in enumerate((op, c) for op in ("prove", "verify") for c in ("A", "B")):
        y = 615 - 50 * i
        row = next(r for r in rows if (r["class"], r["operation"]) == (c, op))
        p50, p95 = float(row["p50_ns"]) / 1e6, row["p95_ns"] / 1e6
        text(55, y - 4, f"{op.capitalize()}   class {c}", 12)
        d.add(Line(tx(row["min_ns"] / 1e6), y, tx(row["max_ns"] / 1e6), y,
                   strokeColor=grid, strokeWidth=2))
        for j, (elapsed, _) in sorted(groups[c, op].items()):
            d.add(Circle(tx(elapsed / 1e6), y + ((j % 5) - 2) * 2.2, 1.8,
                         fillColor=gray, strokeColor=None))
        d.add(Circle(tx(p50), y, 5, fillColor=blue, strokeColor=None))
        d.add(Line(tx(p95), y - 7, tx(p95), y + 7, strokeColor=orange, strokeWidth=2))
        text(850, y - 4, f"{p50:.4g} / {p95:.4g}")
    text((x0 + x1) / 2, 383, "Elapsed milliseconds, logarithmic scale", anchor="middle")
    text(55, 351, "B   Canonical JSON proof size", 16, bold=True)
    sizes = [v[1] / 1024 for c in ("A", "B") for v in groups[c, "prove"].values()]
    low, high = math.floor(min(sizes) / 10) * 10, math.ceil(max(sizes) / 10) * 10
    if low == high:
        high += 10

    def sx(v):
        return x0 + (v - low) / (high - low) * (x1 - x0)

    for i in range(5):
        v = low + i * (high - low) / 4
        x = sx(v)
        d.add(Line(x, 218, x, 322, strokeColor=grid, strokeWidth=.8))
        text(x, 198, f"{v:g}", 10, gray, "middle")
    text(850, 322, "Minimum / maximum (KiB)", 10, gray)
    for i, c in enumerate(("A", "B")):
        y = 295 - 50 * i
        values = [v[1] for v in groups[c, "prove"].values()]
        text(55, y - 4, f"Witness class {c}", 12)
        d.add(Line(sx(min(values) / 1024), y, sx(max(values) / 1024), y, strokeColor=gray))
        for j, size in enumerate(values):
            d.add(Circle(sx(size / 1024), y + ((j % 5) - 2) * 2.2, 2, fillColor=gray, strokeColor=None))
        d.add(Circle(sx(float(median(values)) / 1024), y, 5, fillColor=blue, strokeColor=None))
        text(850, y - 4, f"{min(values)/1024:.3f} / {max(values)/1024:.3f}")
    text((x0 + x1) / 2, 174, "Proof bytes / 1024. Horizontal axis shows the observed range.", anchor="middle")
    d.add(Circle(58, 139, 4.5, fillColor=blue, strokeColor=None))
    text(71, 135, "Median", 10)
    d.add(Line(158, 132, 158, 146, strokeColor=orange, strokeWidth=2))
    text(170, 135, "p95, nearest rank", 10)
    text(340, 135, "Small dots are individual samples. Ranges are not confidence intervals.", 10, gray)
    text(55, 106, "One host and one run. Proving includes local checks, OS entropy and encoding. Verification includes decoding.", 10, gray)
    text(55, 85, "Amounts are not bound to ledger notes. This is not a full private payment or transaction throughput measurement.", 10, gray)
    text(55, 64, "Timing and size observations do not establish witness indistinguishability, constant time behavior or quantum security.", 10, gray)
    text(55, 37, f'Source {metadata["source_revision"][:12]} | raw samples and source hashes retained in results/metadata.json', 10, gray)
    return renderSVG.drawToString(d).encode("utf-8")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--summary-only", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    groups, rows, summary, metadata = load()
    files = {"results/summary.csv": summary}
    if not args.summary_only:
        svg = figure(groups, rows, metadata)
        files["charts/conservation_proof.svg"] = svg
        manifest = {"renderer": "ReportLab graphics shapes and SVG", "reportlab_version": "4.4.9",
                    "raw_sha256": metadata["raw_csv_sha256"], "summary_sha256": hashlib.sha256(summary).hexdigest(),
                    "svg_sha256": hashlib.sha256(svg).hexdigest(), "p50": "Exact sample median",
                    "p95": "Nearest rank ceil(0.95*n)", "interval_meaning": "Sample range, not a confidence interval"}
        files["charts/manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode("ascii")
    for name, data in files.items():
        path = HERE / name
        if args.check:
            if not path.exists() or path.read_bytes() != data:
                parser.exit(1, f"Proof research artifact differs: {name}\n")
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(data)
    print("Proof measurement artifacts match" if args.check else "Proof measurement artifacts generated")


if __name__ == "__main__":
    main()
