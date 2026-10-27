# Third party notices

## Scope and original notices

Thorum project code is covered by the project [MIT license](LICENSE). Registry dependencies retain their own licensing terms, copyrights and notices. The project license does not replace those terms.

The [dependency inventory](research/crypto/dependency-inventory.json) records all 92 registry packages in the current Cargo.lock, including development and target specific packages across all platforms represented by the resolution. The dependency graph covers the workspace and its isolated primitive, relation and proof laboratories. No released binary distribution is represented by this inventory. A package in the lock file is not necessarily linked on every platform.

Each package record contains its name, version, upstream SPDX expression, repository URL and metadata field, registry archive checksum, original license filenames, provenance and source byte hashes. The [license directory](research/crypto/licenses) preserves the original text bytes. Identical files share one content hash filename. Copyright statements are retained exactly rather than replaced with Thorum attribution. No license alternative is selected by this inventory.

The collection includes root LICENSE, COPYING and NOTICE files, explicit license files in package metadata, and reviewed packaging exceptions. The r-efi package stores its license grants and copyright in AUTHORS, which is preserved under its original filename in the inventory. The unicode-ident expression includes Unicode-3.0 in addition to its alternative code licenses. These source terms remain distinct from the project MIT license.

The 20 p3 0.8.0 subcrate archives declare MIT OR Apache-2.0 but omit the workspace root license texts. Their archive authenticated VCS metadata identifies release commit `a21e3ed42905040ad49c519e402f018381c12d0c`. The [original workspace license sources](research/crypto/license-sources/p3-0.8.0) preserve both texts from that exact commit. Inventory records include their repository paths, commit, Git blob identifiers, SHA256 hashes and local source inputs. Generation verifies both hashes before copying their original bytes. The tiny-keccak 2.0.2 package declares CC0-1.0 and places its repository URL in the homepage field. The inventory records that reviewed metadata exception and retains the complete original CC0 text.

## Reproduction and byte verification

The generator uses Python 3.11 or later and captures `cargo metadata --format-version 1 --locked --offline` internally. Cargo.lock is parsed with the standard library TOML reader. Every cached registry archive is verified against its lock checksum before notice bytes are read. Archive notice bytes must also match the resolved source package. The separately preserved workspace originals are checked against their reviewed commit and content hashes. Full Cargo metadata, local paths, environment details and host identifiers are not published.

After the complete locked registry cache is available, the commands are:

```text
python research/crypto/dependency_inventory.py
python research/crypto/dependency_inventory.py --check
```

Generation reproduces the inventory, this notice and the copied license artifacts. Check mode compares exact bytes and the complete artifact set without rewriting files. Missing packages, old records, missing notices, altered bytes, stale copied files, unknown license identifiers and missing license metadata cause a failure. Additional license identifiers or packaging exceptions require an explicit generator review. The license directory disables Git text conversion so original bytes remain stable across checkouts.

## Dated advisory source check

On 2026-10-27, a public OSV query batch for all 92 exact resolved registry versions returned 1 matching advisory record. The recorded response covers the current lock file. This is a dated database response and upstream source review, not a security audit or a guarantee of absent vulnerabilities. Inventory generation and check mode do not contact OSV or refresh this snapshot.

| Package | Version | Record | Classification | Patched versions |
|---|---|---|---|---|
| paste | 1.0.15 | [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html) | informational unmaintained | None recorded |

The paste record is an informational maintenance notice, with no patched version recorded. This procedural macro enters the graph through p3-field. The exact resolution is retained for the isolated experiment. Replacement or an upstream dependency migration remains an open maintenance task. This record is not described as a demonstrated runtime exploit.

| Snapshot field | Value |
|---|---|
| Reviewed Cargo.lock SHA256 | `79276c95e6772e0ed31470e8e7c7b7d54204dbc04ec5fbfb87ea6baccb0847c5` |
| Raw OSV response body SHA256 | `860fa05d158bf8441deeef59b79900ce68b7b170926a5bb3adbc54818977b748` |
| Raw OSV response body length | 366 bytes |
| Source | [OSV query batch API](https://google.github.io/osv.dev/post-v1-querybatch/) |

The reviewed resolution contains ml-kem 0.3.3. Its [upstream security repair](https://github.com/RustCrypto/KEMs/pull/386) removes secret indexed CBD table access across all parameter sets, including ML-KEM-1024. That repair was identified through the upstream changelog despite an earlier empty advisory response for the older lock. An empty database result therefore does not replace source review. In the reviewed resolution, ctutils 0.4.6 is above the [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) patched threshold, and cmov 0.5.4 is above the [RUSTSEC-2026-0003](https://rustsec.org/advisories/RUSTSEC-2026-0003.html) patched threshold.

The proof dependency source review also inspected the [upstream advisory index](https://github.com/Plonky3/Plonky3/security/advisories), including earlier FRI shape, final polynomial and transcript binding repairs. The retained 0.8.0 sources still contain the hiding RNG lock behavior reported in [issue 2363](https://github.com/Plonky3/Plonky3/issues/2363). The isolated proof profile disables every parallel feature and does not include Rayon. The [proof laboratory record](docs/proof-lab.md) states the exact configuration and remaining security limits. These source findings are separate from the OSV batch response.

The inventory records upstream declarations and original notices. It is not a complete legal review, a dependency implementation audit, a cryptographic composition review, or evidence that private payments, confidential stake or production key management have been implemented. Distribution obligations require review for the actual source and binary artifacts being distributed.
