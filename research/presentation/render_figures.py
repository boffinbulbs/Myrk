"""Reproduce transparent display variants without changing research geometry.

Canonical charts, source data and historical manifests remain unchanged.
Paint and typography may differ. Detailed footer notes move into the manifest
and accompanying research text, with a concise scope label on the display.
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
from pathlib import Path
import re
import xml.etree.ElementTree as ET


HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", NS)
ET.register_namespace("xlink", "http://www.w3.org/1999/xlink")
INPUTS = [
    ("emission-reward-schedule", "research/emission/charts/reward_schedule.svg", "Scheduled reward and allocation", "Analytical monetary reference"),
    ("emission-issued-supply", "research/emission/charts/issued_supply.svg", "Cumulative issued supply", "Analytical monetary reference"),
    ("emission-annual-issuance", "research/emission/charts/annual_issuance.svg", "Annual newly issued coins", "Analytical monetary reference"),
    ("emission-gross-issuance-rate", "research/emission/charts/gross_issuance_rate.svg", "Forward annual gross issuance rate", "Analytical monetary reference"),
    ("crypto-primitive-latency", "research/crypto/charts/primitive_latency.svg", "Primitive operation latency", "Historical recorded primitive experiment"),
    ("crypto-envelope-latency", "research/crypto/charts/envelope_latency.svg", "Envelope latency by payload size", "Historical recorded primitive experiment"),
    ("proof-conservation", "research/proofs/charts/conservation_proof.svg", "Hiding conservation proof experiment", "Historical unbound conservation proof experiment"),
]
COLORS = [
    "rgb(9%,16%,22%)", "rgb(39%,45%,52%)", "rgb(87%,89%,91%)",
    "rgb(13%,36%,65%)", "rgb(71%,36%,13%)", "rgb(13%,52%,39%)",
    "rgb(46%,33%,63%)",
]
PALETTES = {
    "light": dict(zip(COLORS, ["#152b43", "#52657b", "#cbd5e1", "#245ca5", "#a75322", "#237458", "#7257a5"])),
    "dark": dict(zip(COLORS, ["#e6edf3", "#a8b8cd", "#344258", "#7bb3ff", "#ffa66b", "#65d2ab", "#c4a2ff"])),
}
PRESENTATION_STYLE = {"fill", "stroke", "font-family", "font-weight"}


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def style(value: str) -> dict[str, str]:
    result = {}
    for item in value.split(";"):
        if item.strip():
            key, val = item.split(":", 1)
            assert key.strip() not in result, "duplicate style declaration"
            result[key.strip()] = val.strip()
    return result


def geometry(root: ET.Element) -> list:
    result = []
    for node in root.iter():
        if local(node.tag) in {"title", "desc"} or node.get("id") == "presentation-scope-note":
            continue
        attrs = dict(node.attrib)
        attrs.pop("role", None)
        parsed = style(attrs.pop("style", ""))
        for key in PRESENTATION_STYLE:
            parsed.pop(key, None)
        result.append([local(node.tag), sorted(attrs.items()), sorted(parsed.items()),
                       "".join(node.itertext()) if local(node.tag) == "text" else None])
    return result


def move_notes(source: ET.Element, relative: str) -> tuple[ET.Element, list, ET.Element, str]:
    cleaned = copy.deepcopy(source)
    if "/emission/" in relative:
        x, positions = "64", {35.0, 18.0}
        label = "Development accounting reference. Production parameters remain open."
    elif "/crypto/" in relative:
        x, positions = "55", {64.0, 43.0, 22.0}
        label = "Recorded primitive experiment. Workload and assumptions: research record."
    else:
        x, positions = "55", {106.0, 85.0, 64.0, 37.0}
        label = "Recorded conservation component. Source 71bd256d404c."
    parents = {child: parent for parent in cleaned.iter() for child in parent}
    notes = [node for node in cleaned.iter(f"{{{NS}}}text")
             if node.get("x") == x and float(node.get("y", "nan")) in positions]
    assert len(notes) == len(positions), relative
    assert {float(node.get("y")) for node in notes} == positions
    records = [{"original_text": "".join(node.itertext()), "original_y": node.get("y")}
               for node in notes]
    scope_note = copy.deepcopy(min(notes, key=lambda node: float(node.get("y"))))
    scope_note.set("id", "presentation-scope-note")
    scope_note.text = label
    parent = parents[notes[0]]
    assert all(parents[node] is parent for node in notes)
    for node in notes:
        parent.remove(node)
    return cleaned, records, scope_note, label


def luminance(color: str) -> float:
    values = [int(color[i:i + 2], 16) / 255 for i in (1, 3, 5)]
    values = [v / 12.92 if v <= 0.04045 else ((v + 0.055) / 1.055) ** 2.4 for v in values]
    return sum(a * b for a, b in zip(values, (0.2126, 0.7152, 0.0722)))


def contrast(a: str, b: str) -> float:
    high, low = sorted([luminance(a), luminance(b)], reverse=True)
    return (high + 0.05) / (low + 0.05)


def display(source: ET.Element, theme: str, title: str, scope: str, scope_note: ET.Element) -> tuple[bytes, dict]:
    output = copy.deepcopy(source)
    content = next(node for node in output.iter() if node.get("transform") == "")
    content.append(copy.deepcopy(scope_note))
    assert local(output.tag) == "svg"
    assert not any(local(n.tag) in {"script", "foreignObject", "image", "use"} for n in output.iter())
    width, height = output.attrib["width"], output.attrib["height"]
    changed_backgrounds = 0
    for node in output.iter():
        parsed = style(node.attrib.get("style", ""))
        is_background = (local(node.tag) == "rect" and node.attrib.get("x") == "0"
                         and node.attrib.get("y") == "0" and node.attrib.get("width") == width
                         and node.attrib.get("height") == height
                         and parsed.get("fill") == "rgb(100%,100%,100%)")
        if is_background:
            parsed["fill"] = "none"
            changed_backgrounds += 1
        for key in ("fill", "stroke"):
            color = parsed.get(key)
            if color == "None":
                parsed[key] = "none"
                color = "none"
            if color and color not in {"none", "black"}:
                assert color in PALETTES[theme], (key, color)
                parsed[key] = PALETTES[theme][color]
        font = parsed.get("font-family")
        if font:
            assert font in {"Helvetica", "Helvetica-Bold"}, font
            parsed["font-family"] = "Arial, Helvetica, sans-serif"
            if font == "Helvetica-Bold":
                parsed["font-weight"] = "bold"
        if parsed:
            node.set("style", "; ".join(f"{k}: {v}" for k, v in parsed.items()) + ";")
    assert changed_backgrounds == 1
    output.set("role", "img")
    output.find(f"{{{NS}}}title").text = title
    output.find(f"{{{NS}}}desc").text = f"{scope}. Transparent {theme} display variant. Plot geometry and data labels are retained. Detailed scope notes accompany the research record."
    assert geometry(source) == geometry(output), "research geometry or rendered labels changed"
    raw = ET.tostring(output, encoding="utf-8", xml_declaration=True) + b"\n"
    parsed_output = ET.fromstring(raw)
    assert geometry(source) == geometry(parsed_output)
    assert b"<!DOCTYPE" not in raw
    assert not re.search(rb"(?:href|src)=[\"']https?://", raw)
    return raw, {"transparent_canvas": True, "unchanged_plot_geometry_and_data_labels": True,
                 "geometry_sha256": sha(json.dumps(geometry(source), separators=(",", ":")).encode()),
                 "source_canvas_rectangles_made_transparent": changed_backgrounds}


def generate() -> dict[Path, bytes]:
    generated = {}
    records = []
    for stem, relative, title, scope in INPUTS:
        raw = (ROOT / relative).read_bytes()
        source, moved, note, label = move_notes(ET.fromstring(raw), relative)
        variants = {}
        for theme in PALETTES:
            image, checks = display(source, theme, title, scope, note)
            path = Path("figures") / f"{stem}-{theme}.svg"
            generated[path] = image
            variants[theme] = {"path": path.as_posix(), "bytes": len(image), "sha256": sha(image), **checks}
        records.append({"canonical_source": relative, "source_sha256": sha(raw), "scope": scope,
                        "display_scope_label": label, "detailed_notes_moved_to_research_record": moved,
                        "variants": variants})
    ratios = {}
    for theme, background in [("light", "#ffffff"), ("dark", "#0d1117")]:
        ratios[theme] = {"body": contrast(PALETTES[theme][COLORS[1]], background),
                         "heading": contrast(PALETTES[theme][COLORS[0]], background)}
        assert min(ratios[theme].values()) >= 4.5
    manifest = {"format": "thorum.research.figure-presentation.v1", "renderer": "Python standard library SVG paint transformation",
                "generator_sha256": sha(Path(__file__).read_bytes()), "canonical_inputs_modified": False,
                "measurements_recomputed": False, "plot_numerical_or_coordinate_changes": False,
                "footer_presentation_revised": True, "original_notes_preserved_in_manifest": True,
                "text_contrast_against_reference_canvas": ratios, "figures": records}
    generated[Path("manifest.json")] = (json.dumps(manifest, indent=2) + "\n").encode()
    return generated


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    files = generate()
    for relative, expected in files.items():
        target = HERE / relative
        if args.check:
            assert target.read_bytes() == expected, relative
        else:
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(expected)
    print(f"{'Verified' if args.check else 'Generated'} 14 transparent SVG display variants from seven unchanged canonical charts.")


if __name__ == "__main__":
    main()
