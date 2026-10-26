"""Extract a small, pinned subset of published NIST ACVP sample cases.

This script uses only the Python standard library. It does not generate keys,
signatures, ciphertexts, or expected secrets. All cryptographic values are copied
from the pinned NIST inputs and answers. Published secret fields are test data.
"""

import argparse
from concurrent.futures import ThreadPoolExecutor
from hashlib import sha256, shake_256
import json
from pathlib import Path
import urllib.request


DIRECTORY = Path(__file__).resolve().parent
COMMIT = "975de31eb83d87039ec88934fdc47d8c312b892d"
REPOSITORY = "https://github.com/usnistgov/ACVP-Server"
RAW_BASE = f"https://raw.githubusercontent.com/usnistgov/ACVP-Server/{COMMIT}/"
PREFIX = "gen-val/json-files/"
ALGORITHMS = (
    "ML-DSA-keyGen-FIPS204",
    "ML-DSA-sigGen-FIPS204",
    "ML-DSA-sigVer-FIPS204",
    "ML-KEM-keyGen-FIPS203",
    "ML-KEM-encapDecap-FIPS203",
)
SOURCE_PATHS = (
    "README.md",
    *(PREFIX + algorithm + "/" + name + ".json"
      for algorithm in ALGORITHMS for name in ("prompt", "expectedResults")),
    PREFIX + "ML-KEM-encapDecap-FIPS203/internalProjection.json",
)
# Fixed case identities, not a search for cases that happen to pass a backend.
SELECTIONS = (
    ("ml_dsa_87_keygen", "ML-DSA-keyGen-FIPS204", 3, 51),
    ("ml_dsa_87_sign_external_pure", "ML-DSA-sigGen-FIPS204", 5, 61),
    ("ml_dsa_87_verify_invalid", "ML-DSA-sigVer-FIPS204", 5, 61),
    ("ml_dsa_87_verify_valid", "ML-DSA-sigVer-FIPS204", 5, 63),
    ("ml_kem_1024_keygen", "ML-KEM-keyGen-FIPS203", 3, 51),
    ("ml_kem_1024_encapsulate", "ML-KEM-encapDecap-FIPS203", 3, 51),
    ("ml_kem_1024_decapsulate_implicit_rejection", "ML-KEM-encapDecap-FIPS203", 6, 96),
    ("ml_kem_1024_decapsulate_valid", "ML-KEM-encapDecap-FIPS203", 6, 97),
)


def json_bytes(value):
    return (json.dumps(value, indent=2, sort_keys=True) + "\n").encode("ascii")


def load_sources(source_dir):
    frozen_path = DIRECTORY / "sources.json"
    frozen = json.loads(frozen_path.read_text(encoding="ascii")) if frozen_path.exists() else None
    if frozen is not None and frozen["upstream_commit"] != COMMIT:
        raise ValueError("source manifest and extractor commits differ")

    def load(path):
        if source_dir is not None:
            raw = (source_dir / path).read_bytes()
        else:
            request = urllib.request.Request(
                RAW_BASE + path, headers={"User-Agent": "Thorum-ACVP-fixture-extractor/1"}
            )
            with urllib.request.urlopen(request, timeout=60) as response:
                raw = response.read()
        digest = sha256(raw).hexdigest()
        if frozen is not None and digest != frozen["sources"][path]["sha256"]:
            raise ValueError(f"pinned source byte hash changed: {path}")
        return path, raw

    with ThreadPoolExecutor(max_workers=4) as pool:
        return dict(pool.map(load, SOURCE_PATHS))


def group_and_case(document, group_id, case_id):
    group = next(group for group in document["testGroups"] if group["tgId"] == group_id)
    case = next(case for case in group["tests"] if case["tcId"] == case_id)
    return group, case


def extract(sources):
    cases = []
    for identifier, algorithm, group_id, case_id in SELECTIONS:
        prompt_path = PREFIX + algorithm + "/prompt.json"
        answer_path = PREFIX + algorithm + "/expectedResults.json"
        prompt = json.loads(sources[prompt_path])
        answer = json.loads(sources[answer_path])
        group, inputs = group_and_case(prompt, group_id, case_id)
        _, expected = group_and_case(answer, group_id, case_id)
        parameter = "ML-DSA-87" if algorithm.startswith("ML-DSA") else "ML-KEM-1024"
        if group["parameterSet"] != parameter:
            raise ValueError(f"wrong parameter set for {identifier}")
        case = {
            "id": identifier,
            "source_directory": PREFIX + algorithm,
            "source_files": [prompt_path, answer_path],
            "tgId": group_id,
            "tcId": case_id,
            "group": {key: value for key, value in group.items() if key != "tests"},
            "input": {key: value for key, value in inputs.items() if key != "tcId"},
            "expected": {key: value for key, value in expected.items() if key != "tcId"},
        }
        if identifier.startswith("ml_kem_1024_decapsulate_"):
            projection_path = PREFIX + algorithm + "/internalProjection.json"
            _, projection = group_and_case(json.loads(sources[projection_path]), group_id, case_id)
            if any(inputs[key] != projection[key] for key in ("dk", "c")):
                raise ValueError(f"projection inputs differ for {identifier}")
            if expected["k"] != projection["k"]:
                raise ValueError(f"projection answer differs for {identifier}")
            reason = projection["reason"]
            required_reason = (
                "modified ciphertext" if identifier.endswith("implicit_rejection")
                else "valid decapsulation"
            )
            if reason != required_reason:
                raise ValueError(f"unexpected decapsulation annotation for {identifier}")
            if reason == "modified ciphertext":
                # Confirm the official answer is the FIPS 203 implicit fallback.
                # The retained expected value still comes from expectedResults.
                expanded_key = bytes.fromhex(inputs["dk"])
                ciphertext = bytes.fromhex(inputs["c"])
                fallback = shake_256(expanded_key[-32:] + ciphertext).digest(32)
                if fallback != bytes.fromhex(expected["k"]):
                    raise ValueError(f"published answer is not the fallback for {identifier}")
            case["annotations"] = {"reason": reason}
            case["source_files"].append(projection_path)
        cases.append(case)

    fixture = {
        "format_version": 1,
        "scope": "eight selected NIST ACVP samples, not full ACVP coverage or validation",
        "upstream_commit": COMMIT,
        "cases": cases,
    }
    fixture_raw = json_bytes(fixture)
    readme = sources["README.md"].decode("utf-8")
    license_text = readme.split("## License \n", 1)[1].split("\n## Contributions", 1)[0].strip()
    notice_raw = (
        "NIST ACVP sample source attribution\n\n"
        "Source: " + REPOSITORY + "/blob/" + COMMIT + "/README.md#license\n"
        "National Institute of Standards and Technology (NIST) is the source of the sample data.\n"
        "Extraction on 2026-10-26 selected eight cases, joined published prompts with\n"
        "their published answers, retained group/case identifiers and annotations,\n"
        "and normalized JSON formatting. Cryptographic field values are unchanged.\n\n"
        "The complete upstream notice follows.\n\n" + license_text + "\n"
    ).encode("utf-8")
    manifest = {
        "format_version": 1,
        "upstream_repository": REPOSITORY,
        "upstream_commit": COMMIT,
        "source_byte_hashes": "SHA-256 of exact HTTP response body or supplied local source bytes",
        "sources": {
            path: {"url": RAW_BASE + path, "bytes": len(raw), "sha256": sha256(raw).hexdigest()}
            for path, raw in sources.items()
        },
        "selected_case_count": len(cases),
        "selected_json_sha256": sha256(fixture_raw).hexdigest(),
        "upstream_notice_sha256": sha256(notice_raw).hexdigest(),
    }
    return {
        "selected.json": fixture_raw,
        "sources.json": json_bytes(manifest),
        "UPSTREAM-NOTICE.txt": notice_raw,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="compare bytes without rewriting outputs")
    parser.add_argument("--source-dir", type=Path, help="read a local pinned upstream source tree")
    args = parser.parse_args()
    outputs = extract(load_sources(args.source_dir))
    if args.check:
        changed = [name for name, raw in outputs.items() if (DIRECTORY / name).read_bytes() != raw]
        if changed:
            raise SystemExit("frozen output mismatch: " + ", ".join(changed))
        print("Verified 12 pinned source hashes and eight selected ACVP cases byte for byte.")
    else:
        for name, raw in outputs.items():
            (DIRECTORY / name).write_bytes(raw)
        print("Extracted eight published ACVP cases from 12 pinned source files.")


if __name__ == "__main__":
    main()
