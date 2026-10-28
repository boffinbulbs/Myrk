"""Reproduce planned protocol diagrams with the standard library SVG renderer.

Optional PNG previews require an existing Pillow and explicit local font files.
The shared renderer is the original adjacent aegis/generate_figures.py source.
"""
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import json
from pathlib import Path
import sys


HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
SHARED = HERE.parent / "aegis/generate_figures.py"
SPEC = importlib.util.spec_from_file_location("thorum_figure_renderer", SHARED)
DRAWING = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(DRAWING)
Figure = DRAWING.Figure
MUTED, BLUE_TINT, GREEN_TINT = DRAWING.MUTED, DRAWING.BLUE_TINT, DRAWING.GREEN_TINT

DATA = {
    "format": "thorum.protocol-design-figures.v1",
    "scope": "Protocol architecture and development order, not performance measurements",
    "runtime_integration": "Pending",
    "svg_canvas": "transparent",
    "themes": ["light", "dark"],
    "png_preview_canvas": "Explicit theme composite",
    "public_owner_or_key_tag": False,
    "base_onward_spending": "After valid checkpoint finality",
    "implemented_labs": "Independent component constraints and bounded proof profiles",
    "integration_gates": ["Complete private payment relation", "Confidential stake feasibility"],
    "base_development_order": [
        "Private payment and confidential stake gates", "Kernel, work and checkpoint rules",
        "Independent isolated server tests", "Private wallet",
    ],
    "later_branches": ["Private contracts", "Wallet Safe", "Aegis"],
    "safe_policy": {
        "enforcement": "Chain rules", "withdrawal_delay": "Policy parameter remains to be specified",
        "recovery_authority": "Cancel to predetermined protected destination",
        "pending_right": "Consumed exactly once by release or cancellation",
    },
    "rpc_boundary": {
        "public": "Chain status, commitments, nullifiers and encrypted delivery data",
        "wallet_scoped": "Locally recovered notes and own balances with restricted authority",
    },
    "figures": {
        "base-architecture": {"width": 1560, "height": 1040, "status": "Planned base runtime"},
        "private-payment-flow": {"width": 1560, "height": 1040, "status": "Planned base protocol"},
        "work-checkpoint-flow": {"width": 1560, "height": 1000, "status": "Planned base consensus"},
        "wallet-safe-lifecycle": {"width": 1560, "height": 1010, "status": "Later contract and wallet policy"},
        "development-stages": {"width": 1560, "height": 1020, "status": "Development order"},
    },
}


def figure(name, title, subtitle):
    meta = DATA["figures"][name]
    value = Figure(name, title, meta["status"] + ". " + DATA["scope"], meta)
    value.header(title, subtitle)
    return value


def arrow(value, start, end, via=()):
    value.line([start, *via, end], arrow=True)


def footer(value, text):
    value.text(60, value.height - 35, text, size=19, color=MUTED, max_width=1440)


def base_architecture():
    value = figure("base-architecture", "Thorum base protocol architecture",
                   "Planned runtime with private payment and confidential stake integration gates.")
    value.card(60, 165, 430, 205, "Private wallet", [
        "Local keys and note recovery", "Private proof construction",
        "Encrypted note delivery", "Scoped wallet services",
    ])
    value.card(565, 165, 430, 205, "Private proof integration", [
        "Membership and stable nullifiers", "Same witness ownership and signature",
        "Value conservation and delivery binding", "Payment and confidential stake gates",
    ], BLUE_TINT)
    value.card(1070, 165, 430, 205, "Node kernel", [
        "Proof admission and spent state", "Commitment roots and resource limits",
        "Maturity and ledger transitions", "Public chain and ciphertext RPC",
    ])
    arrow(value, (490, 265), (565, 265))
    arrow(value, (995, 265), (1070, 265))
    value.rect(60, 455, 1440, 140, BLUE_TINT)
    value.text(88, 493, "Executable research labs", size=24, weight=700, max_width=1380)
    value.text(88, 532, [
        "Accounting, note relations, source constraints, arithmetic and bounded proof profiles.",
        "Component evidence feeds complete authorization integration.",
    ], size=21, line_height=32, max_width=1380)
    arrow(value, (780, 455), (780, 370))
    value.text(805, 417, "Integration", size=18, max_width=200)
    value.card(1070, 705, 430, 205, "One PoW chain", [
        "Equihash work and block ordering", "Merged mining integration",
        "Block validation and reward maturity", "Work selection rules",
    ])
    value.card(565, 705, 430, 205, "Stake checkpoints", [
        "Stake weighted checkpoint votes", "Certificate validation and finality",
        "Confidential stake participation", "Onward spending after finality",
    ], BLUE_TINT)
    value.card(60, 705, 430, 205, "Independent validator", [
        "Verifies private proofs and chain rules", "Checks work and certificates",
        "Maintains spent state and note roots", "Serves public chain data",
    ])
    arrow(value, (1285, 370), (1285, 705), ((1530, 370), (1530, 655), (1285, 655)))
    arrow(value, (1070, 808), (995, 808))
    arrow(value, (565, 808), (490, 808))
    footer(value, "Base protocol architecture. Runtime integration pending.")
    return value


def private_payment_flow():
    value = figure("private-payment-flow", "Ordinary private payment lifecycle",
                   "Planned base protocol. Onward spending follows checkpoint finality.")
    value.card(60, 170, 430, 205, "Wallet C constructs", [
        "Select private notes and witnesses", "Construct the complete private proof",
        "Bind the exact public transaction", "Encrypt recipient delivery",
    ])
    value.card(565, 170, 430, 205, "Validator admission", [
        "Verify the complete proof", "Check spent rights and accepted roots",
        "Enforce conservation and delivery", "Apply maturity and resource rules",
    ], BLUE_TINT)
    value.card(1070, 170, 430, 205, "PoW inclusion", [
        "Include the accepted transaction", "Verify the candidate work block",
        "Advance the ordered ledger state", "Await a valid checkpoint certificate",
    ])
    arrow(value, (490, 272), (565, 272))
    arrow(value, (995, 272), (1070, 272))
    value.card(1070, 495, 430, 205, "Checkpoint finality", [
        "Validate eligible stake votes", "Verify the checkpoint certificate",
        "Finalize the covered state", "Expose finality to independent nodes",
    ], BLUE_TINT)
    value.card(565, 495, 430, 205, "Wallet Y recovers", [
        "Recover and authenticate delivery", "Check note membership and finality",
        "Track the locally owned balance", "Construct onward spend after finality",
    ])
    value.card(60, 495, 430, 205, "Next private payment", [
        "Y constructs a new proof for Z", "Keep its input witness hidden",
        "Derive the note's stable nullifier", "Repeat the base acceptance lifecycle",
    ])
    arrow(value, (1285, 375), (1285, 495))
    arrow(value, (1070, 597), (995, 597))
    arrow(value, (565, 597), (490, 597))
    value.card(60, 805, 700, 140, "Public chain data", [
        "Nullifiers, commitments, ciphertexts and fees",
        "Independent validation and explorer access",
    ], BLUE_TINT)
    value.card(820, 805, 680, 140, "Wallet scoped data", [
        "Recovered notes and own balances",
        "Restricted services with local spending authority",
    ], GREEN_TINT)
    footer(value, "Planned base protocol. Payment and wallet integration pending.")
    return value


def work_checkpoint_flow():
    value = figure("work-checkpoint-flow", "Work ordering and stake checkpoint roles",
                   "Planned base consensus separates block work from certificate finality.")
    value.card(60, 165, 430, 205, "PoW miners", [
        "Construct candidate blocks", "Solve compatible Equihash work",
        "Submit blocks for full validation", "Earn the mining reward allocation",
    ])
    value.card(565, 165, 430, 205, "Ordered work chain", [
        "Validate blocks and ledger rules", "Apply the work selection rule",
        "Track reorganizations before finality", "Define checkpoint opportunities",
    ], BLUE_TINT)
    value.card(1070, 165, 430, 205, "Stakers", [
        "Validate the candidate checkpoint", "Vote under stake eligibility rules",
        "Enforce conflicting vote rules", "Assemble a finality certificate",
    ])
    arrow(value, (490, 267), (565, 267))
    arrow(value, (995, 267), (1070, 267))
    value.card(1070, 495, 430, 205, "Certificate verification", [
        "Authenticate the stake certificate", "Check threshold and target state",
        "Enforce finality and recovery rules", "Certificate validity establishes finality",
    ], BLUE_TINT)
    value.card(565, 495, 430, 205, "Finalized private state", [
        "Protect finalized ledger transitions", "Preserve note and spent right state",
        "Expose the finalized checkpoint", "Retain private proof requirements",
    ])
    value.card(60, 495, 430, 205, "Wallet onward spending", [
        "Recover locally owned notes", "Verify inclusion and finality",
        "Spend finalized ordinary payments", "Apply separate reward maturity rules",
    ], GREEN_TINT)
    arrow(value, (1285, 370), (1285, 495))
    arrow(value, (1070, 597), (995, 597))
    arrow(value, (565, 597), (490, 597))
    value.rect(60, 800, 1440, 110, BLUE_TINT)
    value.text(88, 840, "Independent regular validators", size=24, weight=700, max_width=1380)
    value.text(88, 877, "Verify complete private proofs, PoW blocks, stake certificates and ledger transitions.",
               size=21, max_width=1380)
    footer(value, "Base consensus design. Runtime integration pending.")
    return value


def wallet_safe_lifecycle():
    value = figure("wallet-safe-lifecycle", "Private wallet Safe policy lifecycle",
                   "Later contract and wallet policy. Chain rules enforce the protection.")
    value.card(60, 175, 430, 180, "Protected balance", [
        "Private notes under the Safe policy", "Withdrawal and recovery authorities",
        "Predetermined protected destination",
    ])
    value.card(565, 175, 430, 180, "Withdrawal request", [
        "Authorize a pending withdrawal", "Fix the withdrawal destination",
        "Start the configured policy delay",
    ])
    value.card(1070, 175, 430, 180, "Pending withdrawal", [
        "Retain one pending spending right", "Enforce the release condition",
        "Allow the restricted recovery path",
    ], BLUE_TINT)
    arrow(value, (490, 265), (565, 265))
    arrow(value, (995, 265), (1070, 265))
    value.card(565, 555, 430, 180, "Recovery cancellation", [
        "Separate recovery authorization", "Return to the protected destination",
        "Consume the pending right once",
    ], GREEN_TINT)
    value.card(1070, 555, 430, 180, "Withdrawal release", [
        "Original withdrawal authorization", "Release condition satisfied",
        "Consume the pending right once",
    ])
    value.card(60, 555, 430, 180, "Protected destination", [
        "Receive the cancelled funds", "Retain the selected protection policy",
        "Recovery authority has a fixed target",
    ], GREEN_TINT)
    arrow(value, (1285, 355), (780, 555), ((1285, 435), (780, 435)))
    value.text(930, 414, "Recovery before unlock", size=19, max_width=350)
    arrow(value, (1285, 435), (1285, 555))
    value.text(1310, 500, "Delay satisfied", size=18, max_width=180)
    arrow(value, (565, 645), (490, 645))
    value.rect(60, 835, 1440, 90, BLUE_TINT)
    value.text(88, 871, "Chain enforced policy", size=23, weight=700, max_width=1380)
    value.text(88, 904, "Authorization, delay, fixed recovery destination and exactly one consumption.",
               size=21, max_width=1380)
    footer(value, "Later contract and wallet policy.")
    return value


def development_stages():
    value = figure("development-stages", "Protocol development stages",
                   "Component evidence feeds integration gates and executable chain tests.")
    value.rect(60, 145, 1440, 120, BLUE_TINT)
    value.text(88, 183, "Executable research components", size=24, weight=700, max_width=1380)
    value.text(88, 222, "Accounting, note relations, source constraints, arithmetic and bounded proof profiles.",
               size=21, max_width=1380)
    stages = [
        (60, ["Private relation", "feasibility gates"], ["Complete private payments", "Confidential stake", "Same witness authorization", "Measured resource bounds"]),
        (430, ["Kernel and", "consensus"], ["Ledger kernel", "Work and checkpoint rules", "Mining integration", "Resource enforcement"]),
        (800, ["Independent", "server tests"], ["Isolated development network", "Adversarial and recovery cases", "Independent verification", "Measured network behavior"]),
        (1170, ["Private", "desktop wallet"], ["Private note recovery", "Payments and staking", "Scoped local services", "User controlled viewing"]),
    ]
    for x, title, lines in stages:
        value.rect(x, 365, 330, 250)
        value.text(x + 22, 403, title, size=23, weight=700, line_height=29, max_width=286)
        value.text(x + 22, 483, lines, size=19, line_height=29, max_width=286)
    arrow(value, (225, 265), (225, 365))
    for x in (390, 760, 1130):
        arrow(value, (x, 490), (x + 40, 490))
    value.text(60, 706, "Later feature branches", size=24, weight=700, max_width=1440)
    for x, title, lines in [
        (60, "Private contracts", ["Private escrow and confidential assets", "Private application state"]),
        (565, "Wallet Safe", ["Chain enforced delayed withdrawals", "Restricted recovery authority"]),
        (1070, "Aegis", ["Certified private spending state", "Later PoW recording integration"]),
    ]:
        value.card(x, 775, 430, 155, title, lines, GREEN_TINT)
    footer(value, "Development order. Later feature branches remain separate from initial chain tests.")
    return value


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--png", action="store_true")
    parser.add_argument("--font-directory", type=Path, default=Path("C:/Windows/Fonts"))
    arguments = parser.parse_args()
    assert DATA["base_development_order"][0] == "Private payment and confidential stake gates"
    outputs = {HERE / "figure-data.json": (json.dumps(DATA, indent=2) + "\n").encode()}
    figures = (base_architecture(), private_payment_flow(), work_checkpoint_flow(),
               wallet_safe_lifecycle(), development_stages())
    for value in figures:
        for theme in DRAWING.THEMES:
            suffix = "" if theme == "light" else "-dark"
            outputs[HERE / "figures" / f"{value.name}{suffix}.svg"] = value.svg(theme)
            if arguments.png:
                outputs[HERE / "figures" / f"{value.name}{suffix}.png"] = value.png(arguments.font_directory, theme)
    for path, content in outputs.items():
        if arguments.check:
            assert path.read_bytes() == content, f"Generated figure differs: {path.name}"
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(content)
    print(json.dumps({
        "status": "deterministic byte comparison passed" if arguments.check else "figures generated",
        "scope": DATA["scope"], "svg_xml_geometry_theme_transparency_checked": True,
        "png_text_fit_checked": arguments.png,
        "shared_renderer_sha256": hashlib.sha256(SHARED.read_bytes()).hexdigest(),
        "files": {path.relative_to(HERE).as_posix(): {"bytes": len(content), "sha256": hashlib.sha256(content).hexdigest()}
                  for path, content in outputs.items()},
    }, indent=2))


if __name__ == "__main__":
    main()
