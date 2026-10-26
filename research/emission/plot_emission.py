"""Render emission charts from data with optional ReportLab 4.4.9.

The monetary generator and its tests require only the Python standard library.
This separate renderer reads frozen CSVs and writes deterministic SVG charts.
"""

import argparse
import csv
import hashlib
import json
from pathlib import Path

try:
    import reportlab
    from reportlab.graphics import renderSVG
    from reportlab.graphics.charts.lineplots import LinePlot
    from reportlab.graphics.shapes import Drawing, Line, Rect, String
    from reportlab.lib import colors
except ImportError as error:
    raise SystemExit("Chart rendering requires the optional reportlab package (validated with 4.4.9). "
                     "The emission.py generator and tests remain usable without it.") from error

HERE = Path(__file__).resolve().parent
BLUE = colors.HexColor("#225EA8")
GREEN = colors.HexColor("#238564")
ORANGE = colors.HexColor("#B75C22")
INK = colors.HexColor("#172A3A")
GRAY = colors.HexColor("#657585")
GRID = colors.HexColor("#DFE5EA")
WIDTH, HEIGHT = 960, 530
SOURCES = ["schedule.csv", "projection_annual.csv", "projection_monthly.csv", "metadata.json"]


def load_csv(name):
    with (HERE / name).open(encoding="ascii", newline="") as source:
        return list(csv.DictReader(source))


def chart(title, subtitle, datasets, labels, palette, x_max, x_step,
          y_max, y_step, y_label, footer, x_min=0, y_suffix=""):
    drawing = Drawing(WIDTH, HEIGHT)
    drawing.add(Rect(0, 0, WIDTH, HEIGHT, fillColor=colors.white, strokeColor=None))
    drawing.add(String(64, 492, title, fontName="Helvetica-Bold", fontSize=22, fillColor=INK))
    drawing.add(String(64, 467, subtitle, fontName="Helvetica", fontSize=11, fillColor=GRAY))
    plot = LinePlot()
    plot.x, plot.y, plot.width, plot.height = 95, 135, 800, 284
    plot.data = datasets
    plot.joinedLines = 1
    plot.xValueAxis.valueMin, plot.xValueAxis.valueMax = x_min, x_max
    plot.xValueAxis.valueStep = x_step
    plot.yValueAxis.valueMin, plot.yValueAxis.valueMax = 0, y_max
    plot.yValueAxis.valueStep = y_step
    for axis in [plot.xValueAxis, plot.yValueAxis]:
        axis.strokeColor = GRAY
        axis.strokeWidth = 0.6
        axis.labels.fontName = "Helvetica"
        axis.labels.fontSize = 10
        axis.labels.fillColor = GRAY
    plot.xValueAxis.labels.boxAnchor = "n"
    plot.xValueAxis.labels.dy = -8
    plot.yValueAxis.labels.boxAnchor = "e"
    plot.yValueAxis.labels.dx = -8
    plot.yValueAxis.labelTextFormat = lambda value: f"{value:g}{y_suffix}"
    plot.yValueAxis.visibleGrid = 1
    plot.yValueAxis.gridStrokeColor = GRID
    plot.yValueAxis.gridStrokeWidth = 0.6
    for index, color in enumerate(palette):
        plot.lines[index].strokeColor = color
        plot.lines[index].strokeWidth = 2.4 if index == 0 else 1.8
        plot.lines[index].symbol = None
    drawing.add(plot)
    drawing.add(String(495, 67, "Elapsed model years (365 days)", textAnchor="middle",
                       fontName="Helvetica", fontSize=11, fillColor=INK))
    drawing.add(String(95, 434, y_label, fontName="Helvetica", fontSize=11, fillColor=INK))
    left = 95
    for label, color in zip(labels, palette):
        drawing.add(Line(left, 91, left + 24, 91, strokeColor=color, strokeWidth=2.4))
        drawing.add(String(left + 32, 87, label, fontName="Helvetica", fontSize=10, fillColor=INK))
        left += max(180, 32 + len(label) * 6)
    drawing.add(String(64, 35, footer, fontName="Helvetica", fontSize=10, fillColor=GRAY))
    drawing.add(String(64, 18, "Development parameters. Monetary reference only. Target spacing does not guarantee elapsed calendar time.",
                       fontName="Helvetica", fontSize=9, fillColor=GRAY))
    return renderSVG.drawToString(drawing).encode("utf-8")


def generated_charts():
    schedule = load_csv("schedule.csv")
    annual = load_csv("projection_annual.csv")
    monthly = load_csv("projection_monthly.csv")
    metadata = json.loads((HERE / "metadata.json").read_text(encoding="ascii"))
    # Duplicate each period endpoint to make monthly steps explicit.
    reward, miner, staking = [], [], []
    for row in schedule:
        period = int(row["period"])
        amount = int(row["reward_atoms"])
        for series, atomic in [(reward, amount), (miner, amount * 7 // 10),
                               (staking, amount - amount * 7 // 10)]:
            series.extend([(period / 12, atomic / 1e8), ((period + 1) / 12, atomic / 1e8)])
    for series, amount in [(reward, .5), (miner, .35), (staking, .15)]:
        series.extend([(20, amount), (24, amount)])
    supply = [(float(row["model_years"]), int(row["cumulative_issued_atoms"]) / 1e14) for row in monthly]
    cap_year = float(metadata["cap_exhaustion"]["target_model_years"])
    supply.append((cap_year, 63.0))
    supply.sort()
    annual_issuance = []
    for row in annual:
        year = float(row["model_years"])
        amount = int(row["next_year_issued_atoms"]) / 1e14
        if year < 50:
            annual_issuance.extend([(year, amount), (year + 1, amount)])
    inflation = [(float(row["model_years"]), float(row["next_year_gross_issuance_percent"]))
                 for row in monthly if row["next_year_gross_issuance_percent"] and
                 1 <= float(row["model_years"]) <= 50]
    assumptions = "Fully earned budgets. No burns, premine, or timing adjustment for bootstrap or omitted budgets."
    return {
        "reward_schedule.svg": chart(
            "Scheduled reward and budget split", "240 monthly reward periods, followed by a long reward of 0.5 coins until the cap binds.",
            [reward, miner, staking], ["Scheduled reward", "Miner budget", "Staking budget"],
            [BLUE, GREEN, ORANGE], 24, 4, 16, 4, "Coins per paid block", assumptions),
        "issued_supply.svg": chart(
            "Cumulative issued supply", "The limit of 63 million coins applies to cumulative issuance. Burns cannot reopen minting capacity.",
            [supply, [(0, 63), (330, 63)]], ["Fully earned issuance", "Cumulative issuance cap"],
            [BLUE, ORANGE], 330, 50, 70, 10, "Million coins",
            f"Cap reached at height 83,902,342 (about {cap_year:.6f} target model years). " +
            "No burns. All budgets earned."),
        "annual_issuance.svg": chart(
            "Annual newly issued coins", "Each step is the issuance during the following complete model year of 365 days.",
            [annual_issuance], ["Fully earned annual issuance"], [BLUE],
            50, 10, 4, 1, "Million coins per model year", assumptions),
        "gross_issuance_rate.svg": chart(
            "Forward annual gross issuance rate", "New coins issued in the next year divided by cumulative issued coins at the observation height.",
            [inflation], ["Forward annual gross rate"], [BLUE],
            50, 10, 100, 20, "Percent of cumulative issued supply",
            "Shown from year 1. The rate at genesis is undefined because cumulative issued supply is zero.",
            y_suffix="%"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare frozen SVGs and manifest without writing")
    args = parser.parse_args()
    files = generated_charts()
    manifest = {
        "renderer": "ReportLab graphics.charts.lineplots.LinePlot",
        "reportlab_version": reportlab.Version,
        "units": "chart labels specify coins or percent. Source amounts are integer atomic units",
        "source_sha256": {name: hashlib.sha256((HERE / name).read_bytes()).hexdigest() for name in SOURCES},
        "svg_sha256": {name: hashlib.sha256(data).hexdigest() for name, data in files.items()},
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode("ascii")
    directory = HERE / "charts"
    if not args.check:
        directory.mkdir(exist_ok=True)
    mismatches = []
    for name, data in files.items():
        destination = directory / name
        if args.check:
            if not destination.exists() or destination.read_bytes() != data:
                mismatches.append(name)
        else:
            destination.write_bytes(data)
    if mismatches:
        parser.exit(1, "Chart artifacts differ: " + ", ".join(mismatches) + "\n")
    print("Chart artifacts match." if args.check else "Generated four SVG charts from data and source manifest.")


if __name__ == "__main__":
    main()
