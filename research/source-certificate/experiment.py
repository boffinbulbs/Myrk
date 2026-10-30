"""One finite source inventory and independent scalar comparison."""
import copy
import json
from pathlib import Path
import sys

if not __debug__:
    raise RuntimeError("Optimized Python cannot validate source inventories")
HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
import collect
import reference


def save(path, record):
    raw = collect.bounded_encode(record)
    with path.open("xb") as file:
        file.write(raw)


def main():
    directory = HERE / "results"
    directory.mkdir(exist_ok=True)
    assert not (directory / "certificate.json").exists()
    assert not (directory / "validation.json").exists()
    assert not (directory / "observations.jsonl").exists()
    certificate = collect.build()
    save(directory / "certificate.json", certificate)
    certificate = reference.read_json(directory / "certificate.json")
    expected = reference.expected()
    reference.validate(certificate, expected)
    mutations = [
        ("address_digest", ["address_digest"], "0" * 64),
        ("metric_digest", ["metric_digest"], "0" * 64),
        ("cut_lifetime", ["family_counts", "cuts", "rows"], 75),
        ("missing_prefix", ["coverage", "signature", "gaps"], [[0, 64]]),
        ("real_byte_as_padding", ["virtual_padding", "note"], [417, 418, 419]),
        ("early_owner", ["producer_dependencies", 3], ["OWNER", 232, 233]),
        ("shifted_signature_prefix", ["initial_blocks", 0, "message", 0, "first_byte"], 1),
        ("intrinsic_public_byte", ["analysis_limits", "public_fields_intrinsically_bytes"], True),
    ]
    rejections = []
    with (directory / "observations.jsonl").open("x") as observations:
        for name, path, changed in mutations:
            target = certificate
            for key in path[:-1]:
                target = target[key]
            old = copy.deepcopy(target[path[-1]])
            target[path[-1]] = changed
            rejected = False
            try:
                reference.validate(certificate, expected)
            except AssertionError:
                rejected = True
            observations.write(json.dumps(dict(name=name, rejected=rejected)) + "\n")
            observations.flush()
            assert rejected, name
            target[path[-1]] = old
            reference.validate(certificate, expected)
            rejections.append(name)
    save(directory / "validation.json", dict(generator_passes=1, reference_passes=1, rows_per_pass=8192,
        tampered_reports_rejected=rejections, restoration_accepts=8, positive_validations=9, validation_calls=17, native_traces=0,
        symbolic_collections=0, backend_proofs=0, max_certificate_bytes=524288))
    print(json.dumps(dict(generator_passes=1, reference_passes=1, rejected_reports=len(rejections),
        restoration_accepts=8, certificate_bytes=(directory / "certificate.json").stat().st_size,
        native_traces=0, backend_proofs=0)))


if __name__ == "__main__":
    main()
