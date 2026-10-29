"""Reproduce the later Aegis design figures using the Python standard library.

The optional --png preview uses an already installed Pillow and explicit fonts.
SVG and fixed data reproduction never require Pillow or a network connection.
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
SVG_NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVG_NS)
INK = "#152b43"
MUTED = "#52657b"
BLUE = "#245ca5"
GREEN = "#237458"
BORDER = "#cbd5e1"
BACKGROUND = "#f7f9fc"
WHITE = "#ffffff"
BLUE_TINT = "#eaf1fc"
GREEN_TINT = "#eaf5ef"
THEMES = {
    "light": {},
    "dark": {
        INK: "#e2e8f0", MUTED: "#b3c3d8", BLUE: "#80b4ff", GREEN: "#7ed0a5",
        BORDER: "#42546b", BACKGROUND: "#0d1117", WHITE: "#172231",
        BLUE_TINT: "#172e4b", GREEN_TINT: "#16372d",
    },
}

DATA = {
    "format": "kova.aegis.design-figures.v1",
    "status": "Later protocol design",
    "scope": "Planned protocol ordering and analytical state cursor examples only",
    "implemented_performance": False,
    "elapsed_time_scale": False,
    "changes_current_base_scope": False,
    "base_onward_spending": "After checkpoint finality",
    "svg_canvas": "transparent",
    "themes": ["light", "dark"],
    "png_preview_canvas": "Explicit theme composite",
    "pow_chains": 1,
    "certified_states_and_logs": 1,
    "participants": {
        "C": "Sending wallet", "Y": "Intermediate wallet", "Z": "Receiving wallet",
        "S": "Stakers", "M": "Miner", "N": "Regular validator",
    },
    "definitions": {
        "q": "Highest final stake certified sequence in the single transaction log",
        "k": "Contiguous certified sequence prefix recorded by the single PoW chain",
        "S_q": "Certified private state at sequence q",
        "ordering_invariant": "0 <= k <= q",
        "recording_rule": "A block records each sequence k+1 through k_next once, with 0 <= k <= k_next <= q",
    },
    "state_examples": [
        {"event": "Initial state", "q": 0, "k": 0, "newly_recorded": []},
        {"event": "C payment certified for Y", "q": 1, "k": 0, "newly_recorded": []},
        {"event": "Y onward payment certified for Z", "q": 2, "k": 0, "newly_recorded": []},
        {"event": "One PoW block records the certified prefix", "q": 2, "k": 2,
         "newly_recorded": [1, 2]},
    ],
    "privacy_boundary": "Arrows denote protocol messages or local steps, not public note input links",
    "requirements": [
        "Complete private proof verification before certification",
        "Global spent right validation before final stake commit",
        "Private note recovery and membership checks before onward construction",
        "Contiguous exactly once recording in a single PoW chain",
        "Independent verification of certificates, transitions and PoW records",
    ],
    "figures": {
        "aegis-architecture": {"width": 1560, "height": 1230},
        "aegis-certification-order": {"width": 1560, "height": 1270},
    },
}


def tag(name):
    return f"{{{SVG_NS}}}{name}"


def validate_theme(theme):
    palette = THEMES[theme]

    def luminance(color):
        channels = [int(color[index:index + 2], 16) / 255 for index in (1, 3, 5)]
        linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4
                  for value in channels]
        return sum(value * weight for value, weight in zip(linear, (0.2126, 0.7152, 0.0722)))

    for foreground in (INK, MUTED):
        for background in (BACKGROUND, WHITE, BLUE_TINT, GREEN_TINT):
            values = sorted((luminance(palette.get(foreground, foreground)),
                             luminance(palette.get(background, background))))
            assert (values[1] + 0.05) / (values[0] + 0.05) >= 4.5


class Figure:
    def __init__(self, name, title, description, dimensions=None):
        dimensions = dimensions or DATA["figures"][name]
        self.name = name
        self.width = dimensions["width"]
        self.height = dimensions["height"]
        self.title = title
        self.description = description
        self.elements = []

    def rect(self, x, y, width, height, fill=WHITE, stroke=BORDER, radius=10):
        self.elements.append({"kind": "rect", "x": x, "y": y, "width": width,
                              "height": height, "fill": fill, "stroke": stroke,
                              "radius": radius})

    def text(self, x, y, lines, size=20, color=INK, weight=400, anchor="start",
             line_height=29, max_width=None):
        if isinstance(lines, str):
            lines = [lines]
        self.elements.append({"kind": "text", "x": x, "y": y, "lines": list(lines),
                              "size": size, "color": color, "weight": weight,
                              "anchor": anchor, "line_height": line_height,
                              "max_width": max_width})

    def line(self, points, color=BLUE, width=2.5, arrow=False, dashed=False):
        self.elements.append({"kind": "line", "points": points, "color": color,
                              "width": width, "arrow": arrow, "dashed": dashed})

    def card(self, x, y, width, height, title, lines, fill=WHITE):
        self.rect(x, y, width, height, fill)
        self.text(x + 22, y + 35, title, size=23, weight=700, max_width=width - 44)
        self.text(x + 22, y + 75, lines, size=19, line_height=29, max_width=width - 44)

    def header(self, title, subtitle):
        self.text(60, 58, title, size=31, weight=700, max_width=1440)
        self.text(60, 94, subtitle, size=20, color=MUTED, max_width=1440)

    def validate(self):
        for element in self.elements:
            if element["kind"] == "rect":
                assert element["width"] > 0 and element["height"] > 0
                points = [(element["x"], element["y"]),
                          (element["x"] + element["width"], element["y"] + element["height"])]
            elif element["kind"] == "line":
                points = element["points"]
                assert len(points) >= 2
                assert points[-1] != points[-2]
            else:
                assert element["lines"] and all(element["lines"])
                y_last = element["y"] + (len(element["lines"]) - 1) * element["line_height"]
                points = [(element["x"], element["y"] - element["size"]),
                          (element["x"], y_last + 7)]
            for x, y in points:
                assert math.isfinite(x) and math.isfinite(y)
                assert 0 <= x <= self.width and 0 <= y <= self.height, element

    def svg(self, theme="light"):
        self.validate()
        assert theme in THEMES
        validate_theme(theme)
        root = ET.Element(tag("svg"), {
            "width": str(self.width), "height": str(self.height),
            "viewBox": f"0 0 {self.width} {self.height}",
            "role": "img", "aria-labelledby": "figure-title figure-description",
            "data-theme": theme, "data-canvas": "transparent",
        })
        ET.SubElement(root, tag("title"), {"id": "figure-title"}).text = self.title
        ET.SubElement(root, tag("desc"), {"id": "figure-description"}).text = self.description
        definitions = ET.SubElement(root, tag("defs"))
        marker = ET.SubElement(definitions, tag("marker"), {
            "id": "arrow", "viewBox": "0 0 10 8", "refX": "9", "refY": "4",
            "markerWidth": "8", "markerHeight": "7", "orient": "auto-start-reverse",
        })
        ET.SubElement(marker, tag("path"), {"d": "M 0 0 L 10 4 L 0 8 Z", "fill": BLUE})
        group = ET.SubElement(root, tag("g"), {"font-family": "Arial, Helvetica, sans-serif"})
        for element in self.elements:
            if element["kind"] == "rect":
                ET.SubElement(group, tag("rect"), {
                    "x": str(element["x"]), "y": str(element["y"]),
                    "width": str(element["width"]), "height": str(element["height"]),
                    "rx": str(element["radius"]), "fill": element["fill"],
                    "stroke": element["stroke"] or "none", "stroke-width": "1.5",
                })
            elif element["kind"] == "line":
                attributes = {"points": " ".join(f"{x},{y}" for x, y in element["points"]),
                              "fill": "none", "stroke": element["color"],
                              "stroke-width": str(element["width"])}
                if element["arrow"]:
                    attributes["marker-end"] = "url(#arrow)"
                if element["dashed"]:
                    attributes["stroke-dasharray"] = "7 7"
                ET.SubElement(group, tag("polyline"), attributes)
            else:
                text = ET.SubElement(group, tag("text"), {
                    "x": str(element["x"]), "y": str(element["y"]),
                    "font-size": str(element["size"]), "font-weight": str(element["weight"]),
                    "fill": element["color"], "text-anchor": element["anchor"],
                })
                for index, line in enumerate(element["lines"]):
                    ET.SubElement(text, tag("tspan"), {
                        "x": str(element["x"]),
                        "y": str(element["y"] + index * element["line_height"]),
                    }).text = line
        for element in root.iter():
            for attribute in ("fill", "stroke"):
                if attribute in element.attrib:
                    element.attrib[attribute] = THEMES[theme].get(element.attrib[attribute], element.attrib[attribute])
        assert not any(e.tag == tag("rect") and e.get("x") == "0" and e.get("y") == "0"
                       and e.get("width") == str(self.width) and e.get("height") == str(self.height)
                       for e in root.iter())
        ET.indent(root, space="  ")
        content = ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"
        parsed = ET.fromstring(content)
        assert parsed.attrib["viewBox"] == f"0 0 {self.width} {self.height}"
        assert parsed.find(tag("title")) is not None and parsed.find(tag("desc")) is not None
        return content

    def png(self, font_directory, theme="light"):
        from PIL import Image, ImageDraw, ImageFont

        color = lambda value: THEMES[theme].get(value, value)
        image = Image.new("RGB", (self.width, self.height), color(BACKGROUND))
        draw = ImageDraw.Draw(image)
        fonts = {}
        for element in self.elements:
            if element["kind"] == "rect":
                bounds = (element["x"], element["y"], element["x"] + element["width"],
                          element["y"] + element["height"])
                draw.rounded_rectangle(bounds, radius=element["radius"], fill=color(element["fill"]),
                                       outline=color(element["stroke"]), width=2)
            elif element["kind"] == "line":
                points = element["points"]
                width = max(1, round(element["width"]))
                if element["dashed"]:
                    for start, end in zip(points, points[1:]):
                        length = math.dist(start, end)
                        for offset in range(0, math.ceil(length), 14):
                            first, last = offset / length, min(offset + 7, length) / length
                            segment = [(start[0] + (end[0] - start[0]) * t,
                                        start[1] + (end[1] - start[1]) * t) for t in (first, last)]
                            draw.line(segment, fill=color(element["color"]), width=width)
                else:
                    draw.line(points, fill=color(element["color"]), width=width)
                if element["arrow"]:
                    start, tip = points[-2:]
                    length = math.dist(start, tip)
                    dx, dy = (tip[0] - start[0]) / length, (tip[1] - start[1]) / length
                    base = (tip[0] - 13 * dx, tip[1] - 13 * dy)
                    draw.polygon([tip, (base[0] + 5 * dy, base[1] - 5 * dx),
                                  (base[0] - 5 * dy, base[1] + 5 * dx)], fill=color(BLUE))
            else:
                key = (element["size"], element["weight"])
                if key not in fonts:
                    filename = "arialbd.ttf" if element["weight"] >= 700 else "arial.ttf"
                    fonts[key] = ImageFont.truetype(str(font_directory / filename), element["size"])
                font = fonts[key]
                anchor = {"start": "ls", "middle": "ms", "end": "rs"}[element["anchor"]]
                for index, line in enumerate(element["lines"]):
                    if element["max_width"] is not None:
                        assert draw.textlength(line, font=font) <= element["max_width"], line
                    at = (element["x"], element["y"] + index * element["line_height"])
                    draw.text(at, line, font=font, fill=color(element["color"]), anchor=anchor)
        output = io.BytesIO()
        image.save(output, format="PNG", optimize=False, compress_level=9)
        return output.getvalue()


def architecture():
    figure = Figure("aegis-architecture", "Kova Aegis later protocol architecture",
                    "Later design for one globally certified private state and one PoW recording chain. "
                    "C pays Y, Y recovers and spends from certified state to Z before later PoW recording. "
                    "Regular validator N independently verifies certificates and records. No timing claim.")
    figure.header("Kova Aegis private payment flow",
                  "Later protocol design. Private onward spending follows a final stake commit.")
    figure.card(60, 155, 320, 185, "Wallet C", [
        "Constructs the private proof", "Encrypts delivery for Y", "Submits the payment",
    ])
    figure.card(620, 155, 320, 185, "Stakers S", [
        "Validate the complete proof", "Check global spent rights", "Final stake commit of S_q",
    ], BLUE_TINT)
    figure.card(1180, 155, 320, 185, "Wallet Y", [
        "Recovers the note privately", "Checks membership in S_q", "Confirms certified availability",
    ])
    figure.line([(380, 248), (620, 248)], arrow=True)
    figure.text(500, 211, ["Private proof", "+ encrypted delivery"], size=18, anchor="middle",
                line_height=24, max_width=220)
    figure.line([(940, 248), (1180, 248)], arrow=True)
    figure.text(1060, 211, ["Final certificate", "+ encrypted delivery"], size=18, anchor="middle",
                line_height=24, max_width=220)
    figure.card(1180, 435, 320, 185, "Wallet Y", [
        "Constructs a spend from S_q", "Keeps its input witness private", "Encrypts delivery for Z",
    ])
    figure.line([(1340, 340), (1340, 435)], arrow=True)
    figure.text(1315, 389, "Local construction", size=17, anchor="end", max_width=240)
    figure.card(620, 435, 320, 185, "Stakers S", [
        "Validate proof and spent rights", "Commit S_(q+1)", "Extend the same ordered log",
    ], BLUE_TINT)
    figure.card(60, 435, 320, 185, "Wallet Z", [
        "Recovers the note privately", "Checks membership in S_(q+1)", "Funds become available",
    ], GREEN_TINT)
    figure.line([(1180, 528), (940, 528)], arrow=True)
    figure.text(1060, 491, ["Y spend proof", "+ encrypted delivery"], size=18, anchor="middle",
                line_height=24, max_width=220)
    figure.line([(620, 528), (380, 528)], arrow=True)
    figure.text(500, 491, ["Final certificate", "+ encrypted delivery"], size=18, anchor="middle",
                line_height=24, max_width=220)
    figure.line([(780, 620), (780, 705)], arrow=True)
    figure.text(805, 669, "One global transition order", size=18, max_width=450)
    figure.rect(60, 705, 1440, 160, BLUE_TINT)
    figure.text(88, 742, "One certified private state and transaction log", size=24, weight=700,
                max_width=1380)
    figure.text(88, 782, [
        "S_(q+1) = Apply(S_q, tx). Every final certificate extends the same spent right state.",
        "PoW records the next contiguous batches. Recording advances k without reapplying payments.",
    ], size=21, line_height=34, max_width=1380)
    figure.line([(385, 865), (385, 955)], arrow=True)
    figure.text(410, 916, "Certified batches", size=18, max_width=280)
    figure.line([(1180, 865), (1180, 955)], arrow=True)
    figure.text(1205, 916, "Independent validation", size=18, max_width=280)
    figure.card(60, 955, 640, 170, "Miner M", [
        "A later PoW block records each certified batch once.",
        "One PoW chain anchors the contiguous recorded prefix.",
        "Recording advances k without replaying the state change.",
    ])
    figure.card(860, 955, 640, 170, "Regular validator N", [
        "Verifies complete proofs, spent rights and certificates.",
        "Verifies batch order, the recording cursor and PoW.",
        "Checks the certified state and recorded chain independently.",
    ])
    figure.line([(700, 1040), (860, 1040)], arrow=True)
    figure.text(780, 1002, ["PoW record", "+ certificates"], size=17, anchor="middle",
                line_height=24, max_width=145)
    figure.text(60, 1185, "Later protocol design.",
                size=19, color=MUTED, max_width=1440)
    return figure


def certification_order():
    figure = Figure("aegis-certification-order", "Kova Aegis planned certification ordering",
                    "Illustrative later protocol ordering with certified sequences zero, one and two. "
                    "The PoW recording cursor remains zero until one block records sequences one and two. "
                    "Vertical spacing is not an elapsed time scale and no performance is measured.")
    figure.header("Kova Aegis certification and PoW recording",
                  "Planned ordering for a later protocol upgrade.")
    figure.text(60, 132, "S validates the complete proof and global spent rights before every final commit.",
                size=19, color=MUTED, max_width=1440)
    lanes = [(160, "Wallet C"), (390, "Stakers S"), (620, "Wallet Y"),
             (850, "Wallet Z"), (1080, "Miner M"), (1310, "Validator N")]
    for x, title in lanes:
        figure.text(x, 192, title, size=22, weight=700, anchor="middle", max_width=200)
        figure.line([(x, 215), (x, 1168)], color=BORDER, width=1.5, dashed=True)

    def state(y, title, explanation, fill=BLUE_TINT):
        figure.rect(60, y, 1440, 69, fill)
        figure.text(82, y + 27, title, size=21, weight=700, max_width=1380)
        figure.text(82, y + 54, explanation, size=18, max_width=1380)

    def message(start, end, y, lines):
        figure.line([(start, y), (end, y)], arrow=True)
        figure.text((start + end) / 2, y - 37, lines, size=17, anchor="middle",
                    line_height=23, max_width=max(215, abs(end - start) - 20))

    state(230, "Initial state: q = 0, k = 0", "Certified state S_0 and recorded prefix agree.")
    message(160, 390, 365, ["Private payment proof", "+ delivery for Y"])
    state(395, "Final stake commit: q = 1, k = 0", "S_1 is certified. No new PoW block has recorded sequence 1.")
    message(390, 620, 523, ["Certificate q = 1", "+ private delivery"])
    figure.rect(494, 550, 252, 66)
    figure.text(620, 576, ["Y recovers privately", "Checks membership in S_1"], size=17,
                anchor="middle", line_height=25, max_width=236)
    message(620, 390, 684, ["Spend from S_1", "+ delivery for Z"])
    state(713, "Final stake commit: q = 2, k = 0", "S_2 is certified. Both certified sequences are still unrecorded by PoW.")
    message(390, 850, 840, ["Certificate q = 2 + private delivery"])
    figure.rect(724, 867, 252, 66, GREEN_TINT)
    figure.text(850, 893, ["Z recovers privately", "Checks membership in S_2"], size=17,
                anchor="middle", line_height=25, max_width=236)
    message(390, 1080, 1001, ["Contiguous certified batches 1 and 2"])
    state(1031, "PoW recording: q = 2, k = 2", "One block records sequences 1 and 2 once. The certified state transition is not replayed.", GREEN_TINT)
    message(1080, 1310, 1160, ["PoW block + certificates", "Independent N checks both"])
    figure.text(60, 1211, "0 <= k <= q. One certified state and log. One PoW chain.",
                size=19, color=MUTED, max_width=1440)
    figure.text(60, 1241, "Later protocol design.",
                size=19, color=MUTED, max_width=1440)
    return figure


def validate_data():
    previous_q = previous_k = 0
    recorded = []
    for event in DATA["state_examples"]:
        q, k = event["q"], event["k"]
        assert 0 <= previous_q <= q and 0 <= previous_k <= k <= q
        assert event["newly_recorded"] == list(range(previous_k + 1, k + 1))
        recorded += event["newly_recorded"]
        previous_q, previous_k = q, k
    assert recorded == [1, 2]
    assert DATA["pow_chains"] == DATA["certified_states_and_logs"] == 1
    assert not DATA["implemented_performance"] and not DATA["changes_current_base_scope"]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare deterministic generated bytes without writes")
    parser.add_argument("--png", action="store_true", help="Also render or check optional installed-Pillow previews")
    parser.add_argument("--font-directory", type=Path, default=Path("C:/Windows/Fonts"))
    arguments = parser.parse_args()
    validate_data()
    outputs = {HERE / "figure-data.json": (json.dumps(DATA, indent=2) + "\n").encode()}
    for figure in (architecture(), certification_order()):
        for theme in THEMES:
            suffix = "" if theme == "light" else "-dark"
            outputs[HERE / "figures" / f"{figure.name}{suffix}.svg"] = figure.svg(theme)
            if arguments.png:
                outputs[HERE / "figures" / f"{figure.name}{suffix}.png"] = figure.png(arguments.font_directory, theme)
    for path, content in outputs.items():
        if arguments.check:
            assert path.read_bytes() == content, f"Generated figure differs: {path.name}"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    print(json.dumps({
        "status": "deterministic byte comparison passed" if arguments.check else "figures generated",
        "scope": DATA["scope"],
        "svg_xml_and_numeric_geometry_checked": True,
        "png_text_fit_checked": arguments.png,
        "files": {str(path.relative_to(HERE)): {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                  for path, content in outputs.items()},
    }, indent=2))


if __name__ == "__main__":
    main()
