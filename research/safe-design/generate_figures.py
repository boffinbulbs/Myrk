"""Reproduce the later Private Safe authority and state diagram.

SVG generation and --check use only the standard library and the pinned original
Thorum drawing helper. Optional previews use already installed Pillow and fonts.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys
import xml.etree.ElementTree as ET

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[1]
SHARED = HERE.parent / "aegis/generate_figures.py"
SHARED_SHA256 = "08a29659344c2e17601a4c6410cf042f5b70126caffbfb428e7212c288be4430"
sys.dont_write_bytecode = True
assert hashlib.sha256(SHARED.read_bytes()).hexdigest() == SHARED_SHA256, "Drawing helper changed"
SPEC = importlib.util.spec_from_file_location("thorum_safe_drawing", SHARED)
DRAW = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRAW)

DATA = {
    "format": "thorum.private-safe.design-figure.v1",
    "scope": "Later chain and Qt wallet architecture. No runtime or performance measurement.",
    "implemented_safe": False,
    "initial_chain_prerequisite": False,
    "svg_canvas": "transparent",
    "themes": ["light", "dark"],
    "receiving_types": ["Spending", "Safe"],
    "receiving_default_affects": "New authenticated typed requests only",
    "existing_ordinary_notes": "An accepted private deposit transition is required",
    "authority_roles": [
        {"role": "Everyday Spending", "permission": "Ordinary private spending", "seed": "Independent everyday backup"},
        {"role": "Safe withdrawal", "permission": "Request fixed delayed withdrawal", "seed": "Independent withdrawal backup"},
        {"role": "Safe recovery", "permission": "Cancel selected pending right to fixed protected Safe", "seed": "Independent recovery backup"},
    ],
    "seed_storage_independence": "Wallet setup property, not proved by consensus",
    "local_encryption": {
        "default": "Wallet password with an independent Safe key",
        "optional_extra": "Separate Safe password and independent lock state",
        "unencrypted": "Separate explicit storage decision",
        "rotation_changes_chain_policy": False,
    },
    "clock": "Consensus authenticated finalized mined height H_f",
    "origin": "h0 = H_f of first finalized request state",
    "unlock": "H_u = h0 + D",
    "delay": {"positive": True, "user_selected_supported_value": True, "production_min": None, "production_max": None},
    "cancel": "H_f < H_u",
    "complete": "H_f >= H_u",
    "shared_pending_nullifier": True,
    "recovery_destination": "Fixed protected Safe with independently controlled withdrawal authority",
    "old_withdrawal_authority_valid_at_recovery_safe": False,
    "cancel_scope": "Selected pending right only",
    "remaining_safe_recovery": "Additional transition and construction remain open",
    "public_stable_safe_id_required": False,
    "figure": {"width": 1560, "height": 1380},
}


def diagram():
    value = DRAW.Figure("private-safe", "Private Safe authority and withdrawal policy",
                       "Later design with one Qt app and three independent authorities. Safe receiving binds a private policy. "
                       "A finalized request starts the chosen delay under finalized mined height. Recovery before unlock "
                       "and authorized completion afterward consume the same pending right. Recovery returns only to a fixed "
                       "protected Safe where the old withdrawal authority is invalid. No performance is measured.", DATA["figure"])
    value.header("Private Safe authorities and withdrawal policy", "Later chain and Qt wallet architecture")
    value.rect(60, 135, 1440, 240, DRAW.BLUE_TINT)
    value.text(84, 174, "One Qt wallet. Separate seeds, capabilities and backups.", size=24, weight=700, max_width=1370)
    for x, title, lines in [
        (84, "Everyday Spending", ["Ordinary private payments", "Everyday backup", "Local unlock to sign"]),
        (568, "Safe withdrawal", ["Request a delayed withdrawal", "Independent Safe backup", "Unlock the selected signer"]),
        (1052, "Safe recovery", ["Cancel a pending right", "Fixed protected destination", "Independent recovery backup"]),
    ]:
        value.card(x, 202, 424, 150, title, lines)
    value.rect(60, 404, 1440, 92)
    value.text(84, 439, "Local key protection", size=23, weight=700, max_width=1370)
    value.text(84, 474, "Wallet password by default. Optional separate Safe password. Unencrypted storage is a separate choice.",
               size=21, max_width=1370)
    value.text(60, 539, "Receiving choice: Spending or Private Safe", size=23, weight=700, max_width=1440)
    value.card(60, 572, 430, 192, "Protected Safe", [
        "Authenticated private receiving policy", "Existing funds need a private deposit",
        "Choose a supported delay D > 0", "New receiving requests retain that type",
    ], DRAW.GREEN_TINT)
    value.card(565, 572, 430, 192, "Finalized withdrawal request", [
        "Fix the requested value and destination", "Finalized origin h0 = H_f",
        "Unlock height H_u = h0 + D", "Retain one pending spending right",
    ], DRAW.BLUE_TINT)
    value.line([(490, 668), (565, 668)], arrow=True)
    value.card(1070, 572, 430, 192, "Policy clock H_f", [
        "Finalized mined height only", "A chain halt stops the countdown",
        "Certification rounds do not advance it", "Calendar duration remains an estimate",
    ])
    value.line([(1070, 668), (995, 668)], arrow=True)
    value.line([(780, 764), (780, 835)])
    value.line([(365, 835), (1195, 835)])
    value.line([(365, 835), (365, 947)], arrow=True)
    value.line([(1195, 835), (1195, 947)], arrow=True)
    value.text(365, 813, "Recovery authority", size=22, weight=700, anchor="middle", max_width=500)
    value.text(1195, 813, "Authorized completion", size=22, weight=700, anchor="middle", max_width=500)
    value.rect(60, 947, 610, 217, DRAW.GREEN_TINT)
    value.text(84, 987, "Recovery cancellation", size=25, weight=700, max_width=560)
    value.text(84, 1032, "H_f < H_u", size=27, weight=700, max_width=560)
    value.text(84, 1077, ["Only the fixed protected Safe receives value.",
                         "The old withdrawal authority is invalid there.",
                         "Cancellation covers the selected pending right."], size=21, max_width=560)
    value.rect(890, 947, 610, 217, DRAW.BLUE_TINT)
    value.text(914, 987, "Withdrawal completion", size=25, weight=700, max_width=560)
    value.text(914, 1032, "H_f >= H_u", size=27, weight=700, max_width=560)
    value.text(914, 1077, ["Complete the fixed authorized payment.",
                          "The same pending nullifier is consumed.",
                          "Only one branch may enter finalized history."], size=21, max_width=560)
    value.rect(60, 1206, 1440, 90, DRAW.BLUE_TINT)
    value.text(84, 1242, "Protection follows the right", size=24, weight=700, max_width=1370)
    value.text(84, 1277, "Contracts, Aegis and cryptographic migration retain delay, recovery and consumption restrictions.",
               size=21, max_width=1370)
    value.text(60, 1340, "Later design. Finalized height controls the countdown. Calendar time is an estimate.",
               size=21, color=DRAW.MUTED, max_width=1440)
    return value


def structure(raw):
    result = []
    for element in ET.fromstring(raw).iter():
        attributes = {k: v for k, v in element.attrib.items() if k not in {"fill", "stroke", "data-theme"}}
        result.append([element.tag, sorted(attributes.items()), element.text, element.tail])
    return result


def outputs():
    assert not DATA["implemented_safe"] and not DATA["initial_chain_prerequisite"]
    assert DATA["shared_pending_nullifier"] and DATA["delay"]["positive"]
    assert DATA["delay"]["production_min"] is DATA["delay"]["production_max"] is None
    figure = diagram()
    light, dark = figure.svg("light"), figure.svg("dark")
    assert structure(light) == structure(dark), "Theme structure or labels differ"
    generated = {
        "figure-data.json": (json.dumps(DATA, indent=2) + "\n").encode(),
        "figures/private-safe.svg": light,
        "figures/private-safe-dark.svg": dark,
    }
    sources = {"research/safe-design/generate_figures.py": Path(__file__).resolve(),
               "research/aegis/generate_figures.py": SHARED,
               "docs/private-safe.md": ROOT / "docs/private-safe.md",
               "research/safe-design/README.md": HERE / "README.md"}
    record = {
        "format": "thorum.private-safe.figure-source.v1", "scope": DATA["scope"],
        "original_project_source": True, "runtime_or_consensus_change": False,
        "source_sha256": {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in sources.items()},
        "shared_renderer_expected_sha256": SHARED_SHA256,
        "outputs_sha256": {name: hashlib.sha256(raw).hexdigest() for name, raw in generated.items()},
        "checks": {"svg_xml": True, "finite_bounded_coordinates": True,
                   "transparent_svg_canvas": True, "matching_theme_structure_and_text": True,
                   "reference_canvas_text_contrast": "Existing pinned renderer checks at least 4.5 to 1"},
        "font_family": "Arial, Helvetica, sans-serif", "license": "MIT. Original Thorum source.",
    }
    generated["source_record.json"] = (json.dumps(record, indent=2) + "\n").encode()
    return generated, figure


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Compare deterministic bytes without writes")
    parser.add_argument("--png-directory", type=Path, help="Optional preview directory using installed Pillow")
    parser.add_argument("--font-directory", type=Path, help="Existing directory with Arial font files")
    args = parser.parse_args()
    if args.png_directory and not args.font_directory:
        parser.error("Optional previews require an explicit font directory")
    generated, figure = outputs()
    for relative, raw in generated.items():
        path = HERE / relative
        if args.check:
            assert path.read_bytes() == raw, relative
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(raw)
    if args.png_directory:
        for theme in DRAW.THEMES:
            suffix = "" if theme == "light" else "-dark"
            path = args.png_directory / f"private-safe{suffix}.png"
            raw = figure.png(args.font_directory, theme)
            if args.check:
                assert path.read_bytes() == raw, path.name
            else:
                path.parent.mkdir(parents=True, exist_ok=True)
                path.write_bytes(raw)
    print(json.dumps({"status": "exact comparison passed" if args.check else "generated",
                      "scope": DATA["scope"], "png_text_fit_checked": bool(args.png_directory),
                      "files": {name: {"bytes": len(raw), "sha256": hashlib.sha256(raw).hexdigest()}
                                for name, raw in generated.items()}}, indent=2))


if __name__ == "__main__":
    main()
