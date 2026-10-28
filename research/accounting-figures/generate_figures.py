"""Reproduce the native accounting and funding authority diagrams.

SVG generation, fixed reference data and --check use only the standard library.
Optional transparent PNG previews use an existing Pillow and explicit font files.
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import math
from pathlib import Path
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)
FONT_FAMILY = "Arial, Helvetica, sans-serif"
PALETTES = {
    "light": {
        "ink": "#152b43", "muted": "#52657b", "border": "#cbd5e1",
        "blue": "#245ca5", "green": "#237458", "amber": "#a75322",
        "panel": "#ffffff", "blue_fill": "#eaf1fc", "green_fill": "#eaf5ef",
        "amber_fill": "#fff2e8", "neutral_fill": "#f7f9fc",
    },
    "dark": {
        "ink": "#e6edf3", "muted": "#a8b8cd", "border": "#344258",
        "blue": "#7bb3ff", "green": "#65d2ab", "amber": "#ffa66b",
        "panel": "#161e2b", "blue_fill": "#16263c", "green_fill": "#152d28",
        "amber_fill": "#33251e", "neutral_fill": "#151c27",
    },
}
DATA = {
    "format": "thorum.accounting-figures.v1",
    "scope": "Implemented integer accounting and separate future funding authority requirements",
    "production_parameter_status": "Development references, subject to change before production",
    "units": "Nonnegative integer atomic units",
    "subsidy_formulas": {
        "capped_subsidy": "S = min(R(h), C - I)",
        "miner_floor": "m0 = floor(6S / 10)",
        "staking_budget": "K = floor(2S / 10)",
        "protocol_pool": "P = floor(S / 10)",
        "development": "D = floor(S / 10)",
        "remainder": "r = S - m0 - K - P - D",
        "miner": "M = m0 + r",
        "budget_conservation": "M + K + P + D = S",
        "earned_staking": "0 <= e <= K",
        "actual_issuance": "A = M + P + D + e",
        "next_issued": "I' = I + A <= C",
        "unearned": "K - e remains unissued",
        "supply_invariant": "0 <= B <= I <= C",
        "outstanding": "Outstanding = I - B",
        "remaining": "Remaining allowance = C - I",
        "burn": "B' = B + b, I' = I",
        "burn_range": "0 <= b <= I - B",
    },
    "allocation_vectors_atomic": [
        {"S": 0, "M": 0, "K": 0, "P": 0, "D": 0},
        {"S": 1, "M": 1, "K": 0, "P": 0, "D": 0},
        {"S": 9, "M": 8, "K": 1, "P": 0, "D": 0},
        {"S": 10, "M": 6, "K": 2, "P": 1, "D": 1},
        {"S": 1600000000, "M": 960000000, "K": 320000000,
         "P": 160000000, "D": 160000000},
    ],
    "worked_case_atomic": {"S": 9, "earned_staking": 0, "actual_issued": 8,
                            "unearned_staking": 1},
    "implemented": ["Cap clipping", "Integer allocation and miner remainder",
                    "Earned staking amount range", "Issued and burned supply counters"],
    "unimplemented": ["Payout notes", "Staking duty proofs", "Destination authorization",
                      "Persistent ledger and atomic rollback", "Pool governance",
                      "External trading and burn automation"],
    "authority_domains": [
        {"name": "Native protocol pool", "funding": "P", "authority": "Future eligible stake governance",
         "balance_and_governance_implemented": False},
        {"name": "Development maintenance", "funding": "D", "authority": "Designated project developer",
         "destination_authorization_implemented": False},
        {"name": "Operator external treasury", "funding": "Eligible confirmed external receipts",
         "authority": "Operator custody under separate policy", "execution_implemented": False},
        {"name": "Mining pool worker liabilities", "funding": "Amounts owed to workers",
         "authority": "Existing worker claims", "available_as_operator_budget": False},
    ],
    "external_budget": "max(0, eligible receipts - execution costs - published maintenance budget - reserve top-up)",
    "external_receipt_allocation_ratio": None,
    "native_payouts_depend_on_external_trading": False,
    "retirement": {
        "mechanism": "Future consensus hard fork", "automatic_sunset": False,
        "scope": "Future development allocation redistributed to mining and staking",
        "existing_earned_credits_affected": False,
        "unresolved": ["Completion criteria", "Handover process", "Activation height", "Successor split"],
    },
    "figures": {
        "subsidy-and-supply": {"width": 1560, "height": 1380},
        "funding-authorities": {"width": 1560, "height": 1420},
    },
}


def tag(name):
    return f"{{{NS}}}{name}"


class Figure:
    def __init__(self, name, title, description):
        self.name = name
        self.width = DATA["figures"][name]["width"]
        self.height = DATA["figures"][name]["height"]
        self.title = title
        self.description = description
        self.elements = []

    def rect(self, x, y, width, height, fill="panel", stroke="border", radius=10):
        self.elements.append({"kind": "rect", "x": x, "y": y, "width": width,
                              "height": height, "fill": fill, "stroke": stroke, "radius": radius})

    def text(self, x, y, lines, size=21, color="ink", weight=400,
             anchor="start", line_height=30, max_width=None):
        if isinstance(lines, str):
            lines = [lines]
        self.elements.append({"kind": "text", "x": x, "y": y, "lines": list(lines),
                              "size": size, "color": color, "weight": weight, "anchor": anchor,
                              "line_height": line_height, "max_width": max_width})

    def line(self, points, color="blue", width=2.5, arrow=False):
        self.elements.append({"kind": "line", "points": points, "color": color,
                              "width": width, "arrow": arrow})

    def header(self, title, subtitle):
        self.text(60, 60, title, size=33, weight=700, max_width=1440)
        self.text(60, 99, subtitle, size=21, color="muted", max_width=1440)

    def card(self, x, y, width, height, title, lines, fill="panel", color="ink"):
        self.rect(x, y, width, height, fill)
        self.text(x + 22, y + 39, title, size=23, color=color, weight=700, max_width=width - 44)
        self.text(x + 22, y + 80, lines, size=21, max_width=width - 44)

    def validate(self):
        assert self.elements
        for element in self.elements:
            kind = element["kind"]
            if kind == "rect":
                assert element["width"] > 0 and element["height"] > 0
                assert not (element["x"] == element["y"] == 0
                            and element["width"] == self.width and element["height"] == self.height)
                points = [(element["x"], element["y"]),
                          (element["x"] + element["width"], element["y"] + element["height"])]
            elif kind == "line":
                points = element["points"]
                assert len(points) >= 2 and points[-1] != points[-2]
            else:
                assert element["lines"] and all(element["lines"])
                assert element["size"] >= 19 and element["max_width"] is not None
                left = {"start": element["x"], "middle": element["x"] - element["max_width"] / 2,
                        "end": element["x"] - element["max_width"]}[element["anchor"]]
                bottom = element["y"] + (len(element["lines"]) - 1) * element["line_height"] + 7
                points = [(left, element["y"] - element["size"]),
                          (left + element["max_width"], bottom)]
            for x, y in points:
                assert math.isfinite(x) and math.isfinite(y)
                assert 0 <= x <= self.width and 0 <= y <= self.height, element

    def svg(self, theme):
        self.validate()
        colors = PALETTES[theme]
        root = ET.Element(tag("svg"), {"width": str(self.width), "height": str(self.height),
                          "viewBox": f"0 0 {self.width} {self.height}", "role": "img",
                          "aria-labelledby": "figure-title figure-description"})
        ET.SubElement(root, tag("title"), {"id": "figure-title"}).text = self.title
        ET.SubElement(root, tag("desc"), {"id": "figure-description"}).text = self.description
        defs = ET.SubElement(root, tag("defs"))
        marker = ET.SubElement(defs, tag("marker"), {"id": "arrow", "viewBox": "0 0 10 8",
                               "refX": "9", "refY": "4", "markerWidth": "8",
                               "markerHeight": "7", "orient": "auto-start-reverse"})
        ET.SubElement(marker, tag("path"), {"d": "M 0 0 L 10 4 L 0 8 Z", "fill": colors["blue"]})
        group = ET.SubElement(root, tag("g"), {"font-family": FONT_FAMILY})
        for element in self.elements:
            kind = element["kind"]
            if kind == "rect":
                ET.SubElement(group, tag("rect"), {"x": str(element["x"]), "y": str(element["y"]),
                              "width": str(element["width"]), "height": str(element["height"]),
                              "rx": str(element["radius"]), "fill": colors[element["fill"]],
                              "stroke": colors[element["stroke"]], "stroke-width": "1.5"})
            elif kind == "line":
                attributes = {"points": " ".join(f"{x},{y}" for x, y in element["points"]),
                              "fill": "none", "stroke": colors[element["color"]],
                              "stroke-width": str(element["width"]), "stroke-linejoin": "round"}
                if element["arrow"]:
                    attributes["marker-end"] = "url(#arrow)"
                ET.SubElement(group, tag("polyline"), attributes)
            else:
                node = ET.SubElement(group, tag("text"), {"x": str(element["x"]), "y": str(element["y"]),
                                     "font-size": str(element["size"]), "font-weight": str(element["weight"]),
                                     "fill": colors[element["color"]], "text-anchor": element["anchor"]})
                for index, line in enumerate(element["lines"]):
                    ET.SubElement(node, tag("tspan"), {"x": str(element["x"]),
                                  "y": str(element["y"] + index * element["line_height"])}).text = line
        ET.indent(root, space="  ")
        raw = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
        parsed = ET.fromstring(raw)
        assert parsed.attrib["viewBox"] == f"0 0 {self.width} {self.height}"
        assert parsed.find(tag("title")).text and parsed.find(tag("desc")).text
        assert not any(n.tag.rsplit("}", 1)[-1] in {"script", "image", "use", "foreignObject"}
                       for n in parsed.iter())
        assert b"<!DOCTYPE" not in raw and b"https://" not in raw and b"http://" not in raw.replace(NS.encode(), b"")
        return raw

    def png(self, theme, font_directory):
        from PIL import Image, ImageDraw, ImageFont

        colors = PALETTES[theme]
        canvas = Image.new("RGBA", (self.width, self.height), (0, 0, 0, 0))
        draw = ImageDraw.Draw(canvas)
        fonts = {}
        for element in self.elements:
            kind = element["kind"]
            if kind == "rect":
                box = (element["x"], element["y"], element["x"] + element["width"], element["y"] + element["height"])
                draw.rounded_rectangle(box, radius=element["radius"], fill=colors[element["fill"]],
                                       outline=colors[element["stroke"]], width=2)
            elif kind == "line":
                points = element["points"]
                draw.line(points, fill=colors[element["color"]], width=3, joint="curve")
                if element["arrow"]:
                    (x0, y0), (x1, y1) = points[-2:]
                    length = math.hypot(x1 - x0, y1 - y0)
                    dx, dy = (x1 - x0) / length, (y1 - y0) / length
                    draw.polygon([(x1, y1), (x1 - 13 * dx + 5 * dy, y1 - 13 * dy - 5 * dx),
                                  (x1 - 13 * dx - 5 * dy, y1 - 13 * dy + 5 * dx)], fill=colors[element["color"]])
            else:
                key = (element["size"], element["weight"])
                if key not in fonts:
                    filename = "arialbd.ttf" if element["weight"] >= 700 else "arial.ttf"
                    fonts[key] = ImageFont.truetype(str(font_directory / filename), element["size"])
                font = fonts[key]
                anchor = {"start": "ls", "middle": "ms", "end": "rs"}[element["anchor"]]
                for index, line in enumerate(element["lines"]):
                    assert draw.textlength(line, font=font) <= element["max_width"], (line, element["max_width"])
                    draw.text((element["x"], element["y"] + index * element["line_height"]), line,
                              font=font, fill=colors[element["color"]], anchor=anchor)
        assert canvas.getpixel((0, 0))[3] == 0 and canvas.getpixel((self.width - 1, self.height - 1))[3] == 0
        output = io.BytesIO()
        canvas.save(output, format="PNG", optimize=False, compress_level=9)
        return output.getvalue()


def subsidy_and_supply():
    f = DATA["subsidy_formulas"]
    figure = Figure("subsidy-and-supply", "Thorum native subsidy and supply accounting",
                    "Implemented atomic integer allocation clips nominal subsidy to unused cumulative issuance capacity. "
                    "All floor remainders go to miners. Only earned staking is issued. Burns reduce outstanding supply "
                    "without restoring issuance capacity. Payout notes, duty proofs and persistent ledger integration are unimplemented.")
    figure.header("Native subsidy and supply accounting",
                  "Development accounting reference")
    figure.text(60, 138, "R(h): nominal subsidy    C: issuance ceiling    I: cumulative issued    B: cumulative burned",
                size=21, color="muted", max_width=1440)
    figure.rect(60, 174, 1440, 134, "blue_fill")
    figure.text(84, 215, "1. Capped subsidy", size=25, weight=700, max_width=670)
    figure.text(84, 267, f["capped_subsidy"], size=29, color="blue", weight=700, max_width=670)
    figure.text(824, 215, f["supply_invariant"], size=25, weight=700, max_width=650)
    figure.text(824, 260, "All amounts are integer atomic units.", size=22, max_width=650)
    figure.line([(780, 308), (780, 351)], arrow=True)
    figure.text(60, 385, "2. Budget floors and exact remainder", size=25, weight=700, max_width=1440)
    items = [(60, "Miner floor", f["miner_floor"]), (430, "Staking budget", f["staking_budget"]),
             (800, "Protocol pool", f["protocol_pool"]), (1170, "Development", f["development"])]
    for x, title, formula in items:
        figure.card(x, 412, 330, 125, title, [formula])
    figure.rect(60, 559, 1440, 119, "blue_fill")
    figure.text(84, 600, f["remainder"], size=25, weight=700, max_width=790)
    figure.text(1030, 600, f["miner"], size=26, color="blue", weight=700, max_width=440)
    figure.text(84, 647, "Every remaining atom goes to the miner.", size=21, max_width=790)
    figure.text(1030, 647, f["budget_conservation"], size=21, max_width=440)
    figure.line([(780, 678), (780, 720)], arrow=True)
    figure.rect(60, 720, 1440, 182, "green_fill")
    figure.text(84, 761, "3. Earned staking and actual issuance", size=25, weight=700, max_width=900)
    figure.text(84, 810, f["earned_staking"], size=25, color="green", weight=700, max_width=410)
    figure.text(545, 810, f["actual_issuance"], size=25, color="green", weight=700, max_width=480)
    figure.text(1090, 810, f["next_issued"], size=25, color="green", weight=700, max_width=380)
    figure.text(84, 862, "K - e remains unissued. It creates no reserve, debt or automatic catch up.", size=21, max_width=1370)
    figure.text(60, 942, "P and D count as issued in this transition, including while unspent.",
                size=21, color="muted", max_width=1440)
    figure.rect(60, 976, 700, 190, "neutral_fill")
    figure.text(84, 1017, "4. Every accepted supply state", size=24, weight=700, max_width=650)
    figure.text(84, 1067, f["outstanding"], size=25, weight=700, max_width=650)
    figure.text(84, 1112, f["remaining"], size=23, max_width=650)
    figure.rect(800, 976, 700, 190, "neutral_fill")
    figure.text(824, 1017, "A separate authorized burn b", size=24, weight=700, max_width=650)
    figure.text(824, 1067, f["burn"], size=25, weight=700, max_width=650)
    figure.text(824, 1108, f["burn_range"], size=22, max_width=650)
    figure.text(824, 1141, "Outstanding falls by b. The cap does not reopen.", size=22, max_width=650)
    figure.rect(60, 1182, 1440, 111, "neutral_fill")
    figure.text(84, 1221, "Rounding example in atoms", size=23, weight=700, max_width=1370)
    figure.text(84, 1263, "S = 9 gives M = 8, K = 1, P = D = 0. With e = 0, A = 8 and one atom stays unissued.",
                size=22, max_width=1370)
    figure.text(60, 1341, "Arithmetic implemented. Payout notes, duty proofs and persistence unimplemented.",
                size=21, color="muted", max_width=1440)
    return figure


def funding_authorities():
    figure = Figure("funding-authorities", "Thorum separate funding and authority domains",
                    "Native protocol pool allocation, temporary developer allocation, operator external receipts and unpaid worker "
                    "liabilities have separate accounting and authority boundaries. Pool governance and external execution are unimplemented. "
                    "A grant or transfer moves existing value. A purchase does not destroy value. Only authorized actual destruction is a burn. "
                    "Retiring future developer allocation requires a future consensus hard fork.")
    figure.header("Funding sources and authority boundaries",
                  "Development accounting reference")
    figure.rect(60, 150, 940, 92, "blue_fill")
    figure.text(84, 189, "Native capped subsidy S", size=25, weight=700, color="blue", max_width=890)
    figure.text(84, 224, "P and D are included once in cumulative issued supply.", size=21, max_width=890)
    figure.rect(1060, 150, 440, 92, "amber_fill")
    figure.text(1082, 189, "External mining receipts", size=24, weight=700, color="amber", max_width=396)
    figure.text(1082, 224, "Confirmed and eligible funds only", size=20, max_width=396)
    for x in (280, 780, 1280):
        figure.line([(x, 242), (x, 294)], arrow=True)
    figure.card(60, 294, 440, 434, "Native protocol pool P", [
        "Future eligible stake governance",
        "Authenticated pool balance",
        "Atomic grant reservations",
        "Bounded recipient authorization",
    ], fill="blue_fill", color="blue")
    figure.text(82, 534, ["Grants transfer existing THM.", "They do not mint another copy."], size=21, max_width=396)
    figure.text(82, 652, ["Pool state and governance", "unimplemented."], size=21, color="muted", max_width=396)
    figure.card(560, 294, 440, 434, "Development maintenance D", [
        "Designated project developer",
        "Temporary native allocation",
        "Destination authority still open",
    ], fill="green_fill", color="green")
    figure.text(582, 504, ["Future consensus hard fork", "retires future D into mining", "and staking allocations."], size=21, max_width=396)
    figure.text(582, 622, ["Existing credits remain unaffected.", "No automatic sunset.",
                          "Activation and split remain open."], size=21, color="muted", max_width=396)
    figure.card(1060, 294, 440, 434, "Operator external treasury", [
        "Operator custody",
        "Separate receipt policy",
        "Durable reconciliation",
        "Published execution limits",
    ], fill="amber_fill", color="amber")
    figure.text(1082, 534, ["Native payouts do not depend", "on successful external trading."], size=21, max_width=396)
    figure.text(1082, 652, ["External execution unimplemented."], size=21, color="muted", max_width=396)
    figure.rect(60, 762, 1440, 107, "neutral_fill")
    figure.text(84, 800, "Separate authority domains", size=24, weight=700, max_width=1370)
    figure.text(84, 843, "Pool ballots do not authorize developer spending or external treasury keys. No shared key control is implied.",
                size=21, max_width=1370)
    figure.card(60, 902, 440, 198, "Worker liabilities", [
        "Unpaid balances remain owed.",
        "They cannot fund maintenance,",
        "purchases or protocol grants.",
    ])
    figure.rect(560, 902, 940, 198, "neutral_fill")
    figure.text(584, 941, "External execution budget", size=24, weight=700, max_width=890)
    figure.text(584, 986, ["max(0, eligible receipts - execution costs",
                          "        - published maintenance budget - reserve top-up)"],
                size=23, line_height=33, max_width=890)
    figure.text(584, 1066, "Worker liabilities are excluded. No external allocation ratio is defined.",
                size=20, color="muted", max_width=890)
    figure.text(60, 1146, "Future execution semantics", size=25, weight=700, max_width=1440)
    semantics = [
        (60, "Grant", ["Pool value to recipient.", "Existing issued THM.", "No new mint."], "blue_fill"),
        (430, "Purchase", ["External asset to THM.", "Existing issued THM.", "No mint or automatic burn."], "amber_fill"),
        (800, "Transfer", ["Owned THM to recipient.", "Conservation required.", "No new mint."], "neutral_fill"),
        (1170, "Burn", ["Authorized destruction.", "Outstanding decreases.", "Issued I is unchanged."], "green_fill"),
    ]
    for x, title, lines, fill in semantics:
        figure.card(x, 1172, 330, 181, title, lines, fill=fill)
    figure.text(60, 1393, "Allocation arithmetic implemented. Authority and execution systems unimplemented.",
                size=21, color="muted", max_width=1440)
    return figure


def geometry(raw):
    result = []
    for node in ET.fromstring(raw).iter():
        attrs = {k: v for k, v in node.attrib.items() if k not in {"fill", "stroke"}}
        result.append([node.tag, sorted(attrs.items()), node.text, node.tail])
    return result


def contrast(first, second):
    def luminance(color):
        values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
        linear = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values]
        return sum(a * b for a, b in zip(linear, (0.2126, 0.7152, 0.0722)))

    high, low = sorted([luminance(first), luminance(second)], reverse=True)
    return (high + 0.05) / (low + 0.05)


def validate_contrast():
    minimum = {}
    for theme, canvas in (("light", "#ffffff"), ("dark", "#0d1117")):
        colors = PALETTES[theme]
        ratios = [contrast(colors[text], background)
                  for text in ("ink", "muted")
                  for background in [canvas] + [value for key, value in colors.items()
                                               if key == "panel" or key.endswith("_fill")]]
        ratios += [contrast(colors[accent], colors[f"{accent}_fill"])
                   for accent in ("blue", "green", "amber")]
        minimum[theme] = min(ratios)
        assert minimum[theme] >= 4.5, (theme, minimum[theme])
    return minimum


def validate_data():
    for vector in DATA["allocation_vectors_atomic"]:
        s = vector["S"]
        m0, k, p, d = 6 * s // 10, 2 * s // 10, s // 10, s // 10
        m = m0 + s - m0 - k - p - d
        assert vector == {"S": s, "M": m, "K": k, "P": p, "D": d}
        assert m + k + p + d == s
    example = DATA["worked_case_atomic"]
    vector = next(v for v in DATA["allocation_vectors_atomic"] if v["S"] == example["S"])
    e = example["earned_staking"]
    assert 0 <= e <= vector["K"]
    assert example["actual_issued"] == vector["M"] + vector["P"] + vector["D"] + e
    assert example["unearned_staking"] == vector["K"] - e
    assert example["actual_issued"] == vector["S"] - example["unearned_staking"]
    assert DATA["external_receipt_allocation_ratio"] is None
    assert not DATA["native_payouts_depend_on_external_trading"]
    assert not DATA["retirement"]["automatic_sunset"]
    assert not DATA["retirement"]["existing_earned_credits_affected"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare exact generated bytes without writes")
    parser.add_argument("--png-directory", type=Path, help="Optional directory for transparent Pillow previews")
    parser.add_argument("--font-directory", type=Path, help="Existing directory with arial.ttf and arialbd.ttf")
    args = parser.parse_args()
    if args.png_directory and not args.font_directory:
        parser.error("--png-directory requires explicit --font-directory")
    validate_data()
    minimum_contrast = validate_contrast()
    generated = {HERE / "figure-data.json": (json.dumps(DATA, indent=2) + "\n").encode()}
    for figure in (subsidy_and_supply(), funding_authorities()):
        light = figure.svg("light")
        dark = figure.svg("dark")
        assert geometry(light) == geometry(dark), "Theme variants differ in geometry or content"
        for theme, raw in (("light", light), ("dark", dark)):
            stem = figure.name + ("-dark" if theme == "dark" else "")
            generated[HERE / "figures" / f"{stem}.svg"] = raw
            if args.png_directory:
                generated[args.png_directory / f"{stem}.png"] = figure.png(theme, args.font_directory)
    for path, content in generated.items():
        if args.check:
            assert path.read_bytes() == content, f"Generated artifact differs: {path.name}"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    print(json.dumps({"status": "exact comparison passed" if args.check else "generated",
                      "scope": DATA["scope"], "svg_xml_and_geometry_checked": True,
                      "theme_geometry_and_text_identical": True, "transparent_canvas_checked": True,
                      "minimum_text_contrast_on_reference_canvases": minimum_contrast,
                      "png_text_widths_checked": bool(args.png_directory),
                      "files": {path.name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                                for path, raw in generated.items()}}, indent=2))


if __name__ == "__main__":
    main()
