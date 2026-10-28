"""Deterministic transparent SVGs for the public authorization research boundary.

Uses only the Python standard library. Original diagram geometry and content.
This generator reads no private prototype, witness, measured data or profile.
"""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import xml.etree.ElementTree as ET

BASE = Path(__file__).resolve().parent
SVG = "http://www.w3.org/2000/svg"
ET.register_namespace("", SVG)
THEMES = {
    "light": {"text": "#24364b", "title": "#12283f", "muted": "#53657a", "component": "#246391", "required": "#835300", "native": "#63758b", "canvas": "#ffffff"},
    "dark": {"text": "#dbe7f5", "title": "#f0f6ff", "muted": "#b1c0d1", "component": "#81baff", "required": "#f1c87b", "native": "#9fb3cc", "canvas": "#0d1117"},
}


def add(parent, tag, **attributes):
    return ET.SubElement(parent, "{" + SVG + "}" + tag, {key.replace("_", "-"): str(value) for key, value in attributes.items()})


def text(parent, x, y, value, color, size=18, weight="normal", anchor="start"):
    node = add(parent, "text", x=x, y=y, fill=color, font_size=size, font_weight=weight, text_anchor=anchor)
    node.text = value
    return node


def lines(parent, x, y, values, color, size=18, gap=29, weight="normal", anchor="start"):
    for i, value in enumerate(values):
        text(parent, x, y + gap * i, value, color, size, weight, anchor)


def rect(parent, x, y, width, height, color, dashed=False, opacity="0.035"):
    attrs = {"x": x, "y": y, "width": width, "height": height, "rx": 12,
             "fill": color, "fill_opacity": opacity, "stroke": color, "stroke_width": 2}
    if dashed:
        attrs["stroke_dasharray"] = "8 7"
    return add(parent, "rect", **attrs)


def required_arrow(parent, x1, y1, x2, y2, color):
    return add(parent, "path", d=f"M {x1} {y1} L {x2} {y2}", fill="none", stroke=color,
               stroke_width=2.3, stroke_dasharray="8 7", marker_end="url(#required-arrow)")


def luminance(color):
    values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    linear = [value / 12.92 if value <= 0.04045 else ((value + 0.055) / 1.055) ** 2.4 for value in values]
    return sum(a * b for a, b in zip(linear, [0.2126, 0.7152, 0.0722], strict=True))


def contrast(a, b):
    low, high = sorted([luminance(a), luminance(b)])
    return (high + 0.05) / (low + 0.05)


def render(data, theme):
    palette = THEMES[theme]
    for role in ["text", "title", "muted", "component", "required", "native"]:
        assert contrast(palette[role], palette["canvas"]) >= 4.5
    root = ET.Element("{" + SVG + "}svg", {
        "width": str(data["width"]), "height": str(data["height"]),
        "viewBox": f"0 0 {data['width']} {data['height']}", "role": "img",
        "aria-labelledby": "figure-title figure-description",
        "font-family": "Arial, Helvetica, sans-serif",
    })
    add(root, "title", id="figure-title").text = "Private authorization: implemented components and required joins"
    add(root, "desc", id="figure-description").text = (
        "Four separate public component proof relations feed dashed, unfinished same-witness authorization joins. "
        "Native public transaction preprocessing does not complete those joins. Recipient delivery, ledger state "
        "and composition security remain separate integration gates. The outer canvas is transparent."
    )
    defs = add(root, "defs")
    marker = add(defs, "marker", id="required-arrow", viewBox="0 0 10 10", refX=9, refY=5,
                 markerWidth=7, markerHeight=7, orient="auto-start-reverse")
    add(marker, "path", d="M 0 0 L 10 5 L 0 10 z", fill=palette["required"])
    text(root, 44, 54, "Private authorization: components and required joins", palette["title"], 31, "bold")
    text(root, 44, 90, "Public research components and the same-witness joins still required", palette["muted"], 20)
    add(root, "line", x1=44, y1=123, x2=94, y2=123, stroke=palette["component"], stroke_width=2.5)
    text(root, 108, 129, "Solid component boundary", palette["text"], 17)
    add(root, "line", x1=430, y1=123, x2=480, y2=123, stroke=palette["required"], stroke_width=2.5, stroke_dasharray="8 7")
    text(root, 494, 129, "Dashed: required join or integration gate", palette["text"], 17)
    text(root, 1040, 129, "Private values unless labeled public", palette["muted"], 17)

    for index, component in enumerate(data["components"]):
        x, y, w, h = 44 + index * 434, 170, 410, 360
        group = add(root, "g", id=component["id"])
        rect(group, x, y, w, h, palette["component"])
        text(group, x + 20, y + 30, "IMPLEMENTED COMPONENT PROOF", palette["component"], 12, "bold")
        text(group, x + 20, y + 64, component["title"], palette["title"], 22, "bold")
        lines(group, x + 20, y + 106, component["body"], palette["text"], 17, 30)
        add(group, "line", x1=x + 20, y1=y + 278, x2=x + w - 20, y2=y + 278,
            stroke=palette["component"], stroke_width=1, stroke_opacity="0.5")
        lines(group, x + 20, y + 308, component["boundary"], palette["muted"], 16, 25)
        center = x + w / 2
        required_arrow(root, center, y + h, center, 650, palette["required"])
        lines(root, center + 20, 576, component["join_label"], palette["required"], 16, 24)

    rect(root, 44, 650, 1712, 378, palette["required"], dashed=True, opacity="0.025")
    text(root, 70, 692, "REQUIRED COMPLETE AUTHORIZATION", palette["required"], 22, "bold")
    text(root, 1726, 691, "UNFINISHED", palette["required"], 15, "bold", "end")
    native = data["public_transaction"]
    rect(root, 70, 751, 320, 177, palette["native"], opacity="0.025")
    text(root, 88, 780, "NATIVE PUBLIC PREPROCESSING", palette["native"], 12, "bold")
    text(root, 88, 815, native["title"], palette["title"], 21, "bold")
    lines(root, 88, 852, native["body"], palette["text"], 16, 25)
    required_arrow(root, 390, 840, 442, 840, palette["required"])
    lines(root, 466, 758, data["required_authorization"], palette["text"], 20, 40)
    text(root, 70, 988, "Same private values, constrained across every component", palette["required"], 19)

    for index, gate in enumerate(data["additional_gates"]):
        x = 44 + index * 581
        required_arrow(root, x + 275, 1028, x + 275, 1138, palette["required"])
        rect(root, x, 1140, 550, 148, palette["required"], dashed=True, opacity="0.025")
        text(root, x + 20, 1178, gate["title"], palette["title"], 22, "bold")
        lines(root, x + 20, 1219, gate["body"], palette["text"], 18, 28)
    text(root, 44, 1340, data["root_status"], palette["title"], 20, "bold")
    text(root, 44, 1375, data["footer"], palette["muted"], 18)
    ET.indent(root, space="  ")
    return ET.tostring(root, encoding="utf-8", xml_declaration=True) + b"\n"


def verify(raw, data):
    root = ET.fromstring(raw)
    assert root.attrib["viewBox"] == f"0 0 {data['width']} {data['height']}"
    assert len(root.findall(".//{" + SVG + "}text")) > 50
    labels = ["".join(node.itertext()) for node in root.findall(".//{" + SVG + "}text")]
    for required in [data["root_status"], data["footer"], *data["required_authorization"]]:
        assert required in labels
    assert not any(node.tag.rsplit("}", 1)[-1] in {"script", "foreignObject", "image", "use"} for node in root.iter())
    for node in root.iter():
        for attribute in ["x", "y", "x1", "y1", "x2", "y2"]:
            if attribute in node.attrib:
                assert 0 <= float(node.attrib[attribute]) <= max(data["width"], data["height"])
        if node.tag.endswith("rect"):
            assert not (node.attrib.get("x") == "0" and node.attrib.get("y") == "0"
                        and node.attrib.get("width") == str(data["width"]) and node.attrib.get("height") == str(data["height"]))
    for component in data["components"]:
        assert component["title"] in labels
    return {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}


def geometry_text_hash(raw):
    root = ET.fromstring(raw)
    for node in root.iter():
        for attribute in ["fill", "stroke"]:
            node.attrib.pop(attribute, None)
    return hashlib.sha256(ET.tostring(root, encoding="utf-8")).hexdigest()


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    data = json.loads((BASE / "figure-data.json").read_text())
    assert data["only_public_repository_components"] and not data["complete_private_authorization_implemented"]
    assert not data["performance_or_security_measurement"]
    assert len(data["components"]) == 4 and len(data["required_authorization"]) == 5
    outputs = {}
    geometry = set()
    for theme in ["light", "dark"]:
        raw = render(data, theme)
        path = BASE / "figures" / f"private-authorization-gates-{theme}.svg"
        outputs[path.name] = verify(raw, data)
        geometry.add(geometry_text_hash(raw))
        if args.check:
            assert path.read_bytes() == raw, path.name
        else:
            path.parent.mkdir(exist_ok=True)
            path.write_bytes(raw)
    assert len(geometry) == 1, "Theme geometry and text differ"
    print(json.dumps({"checked" if args.check else "generated": outputs,
                      "geometry_text_sha256": geometry.pop(), "actual_proofs": 0}))


if __name__ == "__main__":
    main()
