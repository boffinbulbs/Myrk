"""Require the exact ignored row proof tests before their serial CI execution."""

import os
from pathlib import Path
import subprocess
import sys


ROOT = Path(__file__).resolve().parents[2]
LIBRARY_TESTS = {
    "reconstructed_row::proof::tests::one_honest_private_reconstructed_row_proof",
    "reconstructed_row::proof::tests::corpus_tests::three_fresh_private_rows_public_mutations_and_transport",
    "reconstructed_row::proof::tests::corpus_tests::sixteen_raw_false_row_proofs_reject_backend_and_wrapper",
}
API_TESTS = {"conditional_row_external_api_and_separate_profiles"}


def command(arguments):
    environment = dict(os.environ, CARGO_TERM_COLOR="never")
    result = subprocess.run(
        arguments, cwd=ROOT, env=environment, text=True, capture_output=True
    )
    if result.returncode:
        sys.stderr.write(result.stderr)
        raise SystemExit(result.returncode)
    return result.stdout


def require_inventory(selector, expected):
    output = command(
        [
            "cargo", "test", "-p", "thorum-hash-proof-lab", "--release",
            "--locked", "--offline", *selector, "--", "--list", "--ignored",
        ]
    )
    names = [line.removesuffix(": test") for line in output.splitlines()
             if line.endswith(": test")]
    if len(names) != len(set(names)) or set(names) != expected:
        raise SystemExit(
            f"Ignored proof inventory mismatch. Expected {sorted(expected)}, got {names}"
        )
    if any(line.endswith(": benchmark") for line in output.splitlines()):
        raise SystemExit("Unexpected benchmark in ignored proof inventory")
    print(f"Verified {len(names)} ignored proof tests for {selector}")


def main():
    version = command(["rustc", "--version"]).split()
    if len(version) < 2 or version[1] != "1.94.1":
        raise SystemExit("The row proof inventory requires Rust 1.94.1")
    require_inventory(["--lib", "reconstructed_row::"], LIBRARY_TESTS)
    require_inventory(["--test", "reconstructed_row"], API_TESTS)


if __name__ == "__main__":
    main()
