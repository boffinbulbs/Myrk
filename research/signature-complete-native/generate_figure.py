"""Render the native relation dependency graph as transparent SVG files."""
import argparse
from pathlib import Path
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
STAGES = (
    ("Source binding", "Witness key, signature, note", "Public A(T), 196 fields"),
    ("Forward transforms", "Seven z, one c, eight t1", "Scaled t1 uses 8192"),
    ("Matrix arithmetic", "56 bounded matrix streams", "Eight corrected rows"),
    ("Inverse and hints", "Eight normalized inverses", "1024 packed w1 bytes"),
    ("Challenge equality", "SHAKE256(mu || w1)", "All 64 seed bytes equal"),
)


def render(dark):
    foreground, accent, muted = ("#e5e7eb", "#67e8d3", "#b5bfcb") if dark else ("#203040", "#0b7a78", "#586274")
    svg = ET.Element("svg", {"xmlns": "http://www.w3.org/2000/svg", "viewBox": "0 0 1280 364", "role": "img", "aria-labelledby": "title description"})
    ET.SubElement(svg, "title", {"id": "title"}).text = "Private signature and ownership constraints"
    ET.SubElement(svg, "desc", {"id": "description"}).text = "Logical constraint dependencies. Proof and ledger integration have a separate gate. The diagram is not an execution schedule."
    defs = ET.SubElement(svg, "defs")
    marker = ET.SubElement(defs, "marker", {"id": "arrow", "viewBox": "0 0 10 10", "refX": "9", "refY": "5", "markerWidth": "7", "markerHeight": "7", "orient": "auto"})
    ET.SubElement(marker, "path", {"d": "M 0 0 L 10 5 L 0 10 z", "fill": accent})

    def text(x, y, value, size=14, bold=False, center=False, color=None):
        attrs = {"x": str(x), "y": str(y), "font-family": "Arial, Helvetica, sans-serif", "font-size": str(size), "fill": color or foreground}
        if bold:
            attrs["font-weight"] = "600"
        if center:
            attrs["text-anchor"] = "middle"
        ET.SubElement(svg, "text", attrs).text = value

    text(40, 35, "Private signature and ownership constraints", 23, True)
    for index, (title, first, second) in enumerate(STAGES):
        x = 40 + 244 * index
        ET.SubElement(svg, "rect", {"x": str(x), "y": "72", "width": "208", "height": "98", "rx": "10", "fill": "none", "stroke": accent, "stroke-width": "1.8"})
        text(x + 104, 99, title, 17, True, True)
        text(x + 104, 128, first, 13, center=True)
        text(x + 104, 150, second, 13, center=True, color=muted)
        if index < len(STAGES) - 1:
            ET.SubElement(svg, "path", {"d": f"M {x + 208} 120 H {x + 242}", "stroke": accent, "stroke-width": "1.8", "fill": "none", "marker-end": "url(#arrow)"})
    ET.SubElement(svg, "path", {"d": "M 1120 170 V 241", "stroke": accent, "stroke-width": "1.8", "fill": "none", "marker-end": "url(#arrow)"})
    ET.SubElement(svg, "rect", {"x": "40", "y": "244", "width": "1184", "height": "70", "rx": "10", "fill": "none", "stroke": muted, "stroke-width": "1.5", "stroke-dasharray": "8 6"})
    text(632, 271, "Hiding proof and ledger integration", 17, True, True)
    text(632, 295, "Separate implementation and security gates", 14, center=True, color=muted)
    text(40, 345, "Public input A(T). Note commitment and signature intermediates remain witness values.", 13, color=muted)
    ET.indent(svg, space="  ")
    return ET.tostring(svg, encoding="unicode") + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    for dark in (False, True):
        path = ROOT / ("constraints-dark.svg" if dark else "constraints.svg")
        content = render(dark)
        if args.check:
            if path.read_text(encoding="utf-8") != content:
                raise ValueError("Dependency figure differs: " + path.name)
        else:
            path.write_text(content, encoding="utf-8", newline="\n")
    print("Transparent native constraint figures match." if args.check else "Transparent native constraint figures saved.")


if __name__ == "__main__":
    main()
