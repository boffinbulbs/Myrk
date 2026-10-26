"""Summarize raw primitive samples and render reproducible research figures.

The summary uses only the Python standard library. Figure generation requires
ReportLab 4.4.9. Measurements describe one host and do not measure a network,
private proof construction, consensus, or transaction throughput.
"""

import argparse
import csv
import hashlib
import io
import json
import math
from collections import defaultdict
from fractions import Fraction
from pathlib import Path


HERE = Path(__file__).resolve().parent
RAW = HERE / "results" / "raw.csv"
SUMMARY = HERE / "results" / "summary.csv"
CHARTS = HERE / "charts"
RAW_FIELDS = ["operation", "input_bytes", "output_bytes", "sample", "elapsed_ns"]
SUMMARY_FIELDS = ["operation", "input_bytes", "output_bytes", "n", "min_ns", "p50_ns", "p95_ns", "max_ns"]
PRIMITIVES = [
    ("mldsa87_keygen_os", "ML-DSA-87 key generation"),
    ("mldsa87_sign_os", "ML-DSA-87 signing"),
    ("mldsa87_verify", "ML-DSA-87 verification"),
    ("mlkem1024_keygen_os", "ML-KEM-1024 key generation"),
    ("mlkem1024_encaps_os", "ML-KEM-1024 encapsulation"),
    ("mlkem1024_decaps", "ML-KEM-1024 decapsulation"),
    ("sha3_512_digest", "SHA3-512 digest"),
]
PAYLOADS = [0, 256, 1024, 16384]
WIDTH, HEIGHT = 1120, 650
HOST = "Intel Core i9-13900H | Windows 11 Home build 26300 | Rust 1.94.1 | release with thin LTO"


def load_samples(path):
    grouped = defaultdict(dict)
    with path.open(encoding="ascii", newline="") as source:
        reader = csv.DictReader(source)
        if reader.fieldnames != RAW_FIELDS:
            raise ValueError("Raw CSV columns do not match the measurement executable.")
        for row in reader:
            operation = row["operation"]
            if not operation or not all(character.isalnum() or character == "_" for character in operation):
                raise ValueError("Unexpected operation identifier.")
            values = [int(row[field]) for field in RAW_FIELDS[1:]]
            if any(value < 0 for value in values) or values[-1] == 0:
                raise ValueError("Byte sizes and sample indices must be nonnegative. Duration must be positive.")
            input_bytes, output_bytes, sample, elapsed = values
            key = (operation, input_bytes, output_bytes)
            if sample in grouped[key]:
                raise ValueError("Duplicate sample within a measurement group.")
            grouped[key][sample] = elapsed
    if not grouped:
        raise ValueError("No raw measurement samples found.")
    for samples in grouped.values():
        if sorted(samples) != list(range(len(samples))):
            raise ValueError("Every measurement group requires consecutive sample indices from zero.")
    return grouped


def exact_median(values):
    midpoint = len(values) // 2
    if len(values) % 2:
        return Fraction(values[midpoint])
    return Fraction(values[midpoint - 1] + values[midpoint], 2)


def half_integer_text(value):
    if value.denominator == 1:
        return str(value.numerator)
    return f"{value.numerator // 2}.5"


def summarize(grouped):
    summaries = []
    for (operation, input_bytes, output_bytes), samples in sorted(grouped.items()):
        values = sorted(samples.values())
        count = len(values)
        summaries.append({
            "operation": operation,
            "input_bytes": input_bytes,
            "output_bytes": output_bytes,
            "n": count,
            "min_ns": values[0],
            "p50_ns": half_integer_text(exact_median(values)),
            "p95_ns": values[(95 * count + 99) // 100 - 1],
            "max_ns": values[-1],
        })
    return summaries


def summary_bytes(summaries):
    destination = io.StringIO(newline="")
    writer = csv.DictWriter(destination, fieldnames=SUMMARY_FIELDS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(summaries)
    return destination.getvalue().encode("ascii")


def load_renderer():
    try:
        import reportlab
        from reportlab.graphics import renderSVG
        from reportlab.graphics.shapes import Circle, Drawing, Line, Rect, String
        from reportlab.lib import colors
    except ImportError as error:
        raise RuntimeError("SVG rendering requires optional ReportLab 4.4.9. Use --summary-only for standard library output.") from error
    if reportlab.Version != "4.4.9":
        raise RuntimeError("Reproducible SVG rendering requires ReportLab 4.4.9.")
    return reportlab, renderSVG, Circle, Drawing, Line, Rect, String, colors


def render_figures(summaries):
    reportlab, renderSVG, Circle, Drawing, Line, Rect, String, colors = load_renderer()
    ink = colors.HexColor("#172A3A")
    gray = colors.HexColor("#657585")
    grid = colors.HexColor("#DFE5EA")
    blue = colors.HexColor("#225EA8")
    green = colors.HexColor("#238564")
    orange = colors.HexColor("#B75C22")

    def text(drawing, x, y, value, size=11, color=ink, bold=False, anchor="start"):
        drawing.add(String(x, y, value, fontName="Helvetica-Bold" if bold else "Helvetica",
                           fontSize=size, fillColor=color, textAnchor=anchor))

    def canvas(title, subtitle):
        drawing = Drawing(WIDTH, HEIGHT)
        drawing.add(Rect(0, 0, WIDTH, HEIGHT, fillColor=colors.white, strokeColor=None))
        text(drawing, 55, 610, title, size=24, bold=True)
        text(drawing, 55, 584, subtitle, color=gray)
        text(drawing, 55, 563, HOST, size=10, color=gray)
        return drawing

    def footer(drawing, middle):
        text(drawing, 55, 64, middle, size=10, color=gray)
        text(drawing, 55, 43, "One host observation. Operations ending in _os include operating system entropy access.", size=10, color=gray)
        text(drawing, 55, 22, "Three partial warmup iterations. No network, private proof, or transaction throughput is measured.", size=10, color=gray)

    def one(operation, input_bytes=None):
        rows = [row for row in summaries if row["operation"] == operation and
                (input_bytes is None or row["input_bytes"] == input_bytes)]
        if len(rows) != 1:
            raise ValueError(f"Expected exactly one figure group for {operation} and input {input_bytes}.")
        return rows[0]

    primitive_rows = [(one(operation), label) for operation, label in PRIMITIVES]
    counts = {row["n"] for row, _ in primitive_rows}
    if len(counts) != 1:
        raise ValueError("Primitive plot requires the same sample count per operation.")
    count = counts.pop()
    drawing = canvas("Primitive operation latency", f"Median and p95 of {count} recorded samples per operation. Logarithmic time axis.")
    x0, x1 = 330, 805
    y0, y1 = 155, 525
    minimum = min(float(row["p50_ns"]) / 1_000_000 for row, _ in primitive_rows)
    maximum = max(row["p95_ns"] / 1_000_000 for row, _ in primitive_rows)
    log_min = math.floor(math.log10(minimum))
    log_max = math.ceil(math.log10(maximum))
    if log_max <= log_min:
        log_max = log_min + 1

    def primitive_x(value):
        return x0 + (math.log10(value) - log_min) / (log_max - log_min) * (x1 - x0)

    for exponent in range(log_min, log_max + 1):
        value = 10 ** exponent
        x = primitive_x(value)
        drawing.add(Line(x, y0, x, y1, strokeColor=grid, strokeWidth=.7))
        text(drawing, x, y0 - 22, f"{value:g}", size=10, color=gray, anchor="middle")
    text(drawing, (x0 + x1) / 2, 105, "Elapsed milliseconds, logarithmic scale", anchor="middle")
    text(drawing, 850, 529, "Median / p95 (ms)", size=10, color=gray)
    for index, (row, label) in enumerate(primitive_rows):
        y = y1 - 28 - index * 49
        median = float(row["p50_ns"]) / 1_000_000
        percentile = row["p95_ns"] / 1_000_000
        left, right = primitive_x(median), primitive_x(percentile)
        text(drawing, 55, y - 4, label, size=12)
        drawing.add(Line(left, y, right, y, strokeColor=gray, strokeWidth=1.4))
        drawing.add(Circle(left, y, 4.8, fillColor=blue, strokeColor=None))
        drawing.add(Line(right, y - 6, right, y + 6, strokeColor=orange, strokeWidth=2.2))
        text(drawing, 850, y - 4, f"{median:.4g} / {percentile:.4g}", size=11)
    drawing.add(Circle(360, 86, 4.5, fillColor=blue, strokeColor=None))
    text(drawing, 373, 82, "Median", size=10)
    drawing.add(Line(468, 80, 468, 92, strokeColor=orange, strokeWidth=2.2))
    text(drawing, 481, 82, "p95 sample percentile", size=10)
    footer(drawing, "p95 uses nearest rank. Markers describe the recorded distribution and are not confidence intervals.")
    files = {"primitive_latency.svg": renderSVG.drawToString(drawing).encode("utf-8")}

    envelope_rows = []
    for payload in PAYLOADS:
        sealing = one("envelope_seal_os", payload)
        opening = one("envelope_open", sealing["output_bytes"])
        if opening["output_bytes"] != payload or opening["n"] != sealing["n"]:
            raise ValueError("Envelope measurements do not match the same payload and sample count.")
        envelope_rows.append((payload, sealing, opening))
    envelope_counts = {row["n"] for _, sealing, opening in envelope_rows for row in (sealing, opening)}
    if len(envelope_counts) != 1:
        raise ValueError("Envelope plot requires the same sample count per group.")
    count = envelope_counts.pop()
    drawing = canvas("Recipient envelope latency by payload size", f"Complete experimental envelope sealing and opening. {count} recorded samples per group.")
    x0, x1, y0, y1 = 105, 1055, 160, 510
    maximum = max(row["p95_ns"] / 1_000_000 for _, sealing, opening in envelope_rows for row in (sealing, opening))
    rough_step = maximum / 5
    magnitude = 10 ** math.floor(math.log10(rough_step))
    step = next(value * magnitude for value in (1, 2, 5, 10) if value * magnitude >= rough_step)
    y_max = math.ceil(maximum * 1.12 / step) * step

    def envelope_y(value):
        return y0 + value / y_max * (y1 - y0)

    for index in range(round(y_max / step) + 1):
        value = index * step
        y = envelope_y(value)
        drawing.add(Line(x0, y, x1, y, strokeColor=grid, strokeWidth=.7))
        text(drawing, x0 - 15, y - 4, f"{value:g}", size=10, color=gray, anchor="end")
    text(drawing, x0, y1 + 17, "Elapsed milliseconds", size=11)
    group_width = (x1 - x0) / len(PAYLOADS)
    for index, (payload, sealing, opening) in enumerate(envelope_rows):
        center = x0 + (index + .5) * group_width
        for offset, row, color in [(-39, sealing, blue), (7, opening, green)]:
            x = center + offset
            median = float(row["p50_ns"]) / 1_000_000
            percentile = row["p95_ns"] / 1_000_000
            top = envelope_y(median)
            p95_top = envelope_y(percentile)
            drawing.add(Rect(x, y0, 32, top - y0, fillColor=color, strokeColor=None))
            drawing.add(Line(x + 16, top, x + 16, p95_top, strokeColor=ink, strokeWidth=1))
            drawing.add(Line(x + 8, p95_top, x + 24, p95_top, strokeColor=ink, strokeWidth=1.7))
            text(drawing, x + 16, p95_top + 10, f"{percentile:.3g}", size=9, color=gray, anchor="middle")
        text(drawing, center, y0 - 25, f"{payload:,}", anchor="middle")
    text(drawing, (x0 + x1) / 2, 108, "Plaintext payload bytes, categorical groups", anchor="middle")
    drawing.add(Rect(345, 83, 16, 10, fillColor=blue, strokeColor=None))
    text(drawing, 370, 83, "Seal with OS entropy", size=10)
    drawing.add(Rect(530, 83, 16, 10, fillColor=green, strokeColor=None))
    text(drawing, 555, 83, "Open", size=10)
    drawing.add(Line(650, 88, 668, 88, strokeColor=ink, strokeWidth=1.7))
    text(drawing, 677, 83, "p95", size=10)
    footer(drawing, "Bars show medians. Caps and numeric labels show p95. Payload groups use equal spacing.")
    files["envelope_latency.svg"] = renderSVG.drawToString(drawing).encode("utf-8")
    return files, reportlab.Version


def compare_or_write(path, data, check, mismatches):
    if check:
        if not path.exists() or path.read_bytes() != data:
            mismatches.append(path.relative_to(HERE).as_posix())
    else:
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare generated artifacts without writing")
    parser.add_argument("--summary-only", action="store_true", help="use only the standard library and check or generate summary.csv")
    args = parser.parse_args()
    try:
        summaries = summarize(load_samples(RAW))
        summary = summary_bytes(summaries)
        mismatches = []
        compare_or_write(SUMMARY, summary, args.check, mismatches)
        if not args.summary_only:
            files, renderer_version = render_figures(summaries)
            manifest = {
                "renderer": "ReportLab graphics shapes and SVG",
                "reportlab_version": renderer_version,
                "raw_sha256": hashlib.sha256(RAW.read_bytes()).hexdigest(),
                "summary_sha256": hashlib.sha256(summary).hexdigest(),
                "p50": "Exact median. An even count averages the two central integer durations.",
                "p95": "Nearest rank at ceil(0.95 * n), counted from one.",
                "svg_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
            }
            files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode("ascii")
            for name, data in files.items():
                compare_or_write(CHARTS / name, data, args.check, mismatches)
        if mismatches:
            parser.exit(1, "Research artifacts differ: " + ", ".join(mismatches) + "\n")
    except (OSError, ValueError, RuntimeError) as error:
        parser.exit(1, str(error) + "\n")
    print("Crypto research artifacts match." if args.check else "Generated crypto research summaries and requested figures.")


if __name__ == "__main__":
    main()
