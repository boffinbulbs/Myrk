# Selected NIST ACVP sample vectors

This directory preserves eight selected published sample cases from the National Institute of Standards and Technology ACVP server repository at commit `975de31eb83d87039ec88934fdc47d8c312b892d`. The source is [NIST ACVP sample JSON](https://github.com/usnistgov/ACVP-Server/tree/975de31eb83d87039ec88934fdc47d8c312b892d/gen-val/json-files). These fixtures are a small known answer regression corpus. They are not the complete ACVP suite, an ACVP validation session, a certification, an audit or evidence of a complete private protocol.

| Sample directory | Group | Case | Comparison |
|---|---:|---:|---|
| ML-DSA-keyGen-FIPS204 | 3 | 51 | ML-DSA-87 public key and expanded secret key bytes |
| ML-DSA-sigGen-FIPS204 | 5 | 61 | ML-DSA-87 deterministic external pure signature bytes |
| ML-DSA-sigVer-FIPS204 | 5 | 61 | External pure verification returns the published false answer |
| ML-DSA-sigVer-FIPS204 | 5 | 63 | External pure verification returns the published true answer |
| ML-KEM-keyGen-FIPS203 | 3 | 51 | ML-KEM-1024 encapsulation and expanded decapsulation key bytes |
| ML-KEM-encapDecap-FIPS203 | 3 | 51 | ML-KEM-1024 encapsulation ciphertext and shared secret bytes |
| ML-KEM-encapDecap-FIPS203 | 6 | 96 | Published implicit rejection secret for a modified ciphertext |
| ML-KEM-encapDecap-FIPS203 | 6 | 97 | Published valid decapsulation secret |

The [Rust integration tests](../../../crates/thorum-crypto-lab/tests/acvp.rs) compare actual primitive outputs with these expected bytes and verification results. Fixed known answer seeds and randomness are used only in the vector test path. All secret fields are public synthetic test data and must never be used as operational keys or entropy. Official expanded key formats require narrowly scoped deprecated imports in this integration test. They are not imports of untrusted operational keys.

## Provenance and extraction

1. `selected.json` retains the exact cryptographic field values, parameter sets, input fields, expected answer fields, source directory, source filenames, group IDs and case IDs. Prompt inputs are joined with `expectedResults.json` answers by group and case identity. No expected cryptographic output is generated locally.
2. `sources.json` records the immutable source URLs, byte lengths and SHA-256 hashes of all 12 complete upstream source files. The hashes cover the exact downloaded bytes before JSON parsing. It also records the generated fixture and notice hashes. Source files are fetched in memory and are not included in full.
3. For the two decapsulation cases, `internalProjection.json` supplies the explicit `modified ciphertext` and `valid decapsulation` annotations. The extractor verifies that its input and expected secret match the prompt and answer files. It also independently checks the implicit rejection answer against the specified `SHAKE256(z || ciphertext, 32)` fallback using Python's standard library. The Rust test compares actual decapsulation with the published answer. A correctly sized modified ciphertext yields a secret, not an exposed rejection flag.
4. `extract.py` uses only the Python standard library and fixed case identities. It verifies downloaded source bytes against the frozen source manifest before regenerating output. Its `--check` mode compares generated fixture, manifest and notice bytes without rewriting them. The evaluated Rust primitive backends do not participate in extraction.

From the repository root, with Python 3.10 or later and HTTPS access to the pinned upstream source:

```text
python research/crypto/vectors/extract.py --check
```

To reproduce using an existing copy of the exact upstream tree without network access:

```text
python research/crypto/vectors/extract.py --check --source-dir /path/to/pinned/ACVP-Server
```

The ordinary Rust test uses only the retained fixture and needs no source download:

```text
cargo test -p thorum-crypto-lab --test acvp --locked --offline
```

Run extraction without `--check` only when intentionally regenerating the frozen output. A changed source hash is an error even during regeneration. Changing the upstream commit, selection or expected hashes requires a reviewable fixture update.

## Coverage and limitations

The intended primitive versions are `ml-dsa` 0.1.1 and `ml-kem` 0.3.3. This selected corpus exercises key generation, external pure deterministic signing, external pure verification, deterministic encapsulation, valid decapsulation and implicit rejection for the named parameter sets. It does not cover every ACVP group, parameter set, signature interface, prehash mode, randomness mode, key validity check or malformed encoding. It does not test the delivery KDF or AEAD. Separate adversarial tests and composition analysis remain necessary.

Passing these comparisons establishes agreement with the selected published answers for the exact implementation versions tested. It does not establish implementation certification, constant time behavior, recipient anonymity, key privacy, private authorization, proof system soundness or composed protocol security. A benchmark or successful local round trip cannot replace these independent expected output comparisons.

## Attribution and license status

NIST is the source of the sample data. [UPSTREAM-NOTICE.txt](UPSTREAM-NOTICE.txt) preserves the complete upstream README license notice and identifies the date and nature of the extraction and formatting changes. The exact source README URL and byte hash are retained in `sources.json`. The upstream repository carries its NIST notice in its README rather than a standalone root license file at this commit. This directory does not replace that notice with the project's license or describe all upstream material as subject to one SPDX license expression. Use and redistribution remain subject to the retained upstream notice.
