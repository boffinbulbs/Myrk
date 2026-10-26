# Third party notices

## Scope and original notices

Thorum project code is covered by the project [MIT license](LICENSE). Registry dependencies retain their own licensing terms, copyrights and notices. The project license does not replace those terms.

The [dependency inventory](research/crypto/dependency-inventory.json) records all 52 registry packages in the current Cargo.lock, including development and target specific packages across all platforms represented by the resolution. The dependency graph belongs to the isolated cryptographic research laboratory. No released binary distribution is represented by this inventory. A package in the lock file is not necessarily linked on every platform.

Each package record contains its name, version, upstream SPDX expression, repository URL, registry archive checksum, original license filenames and source byte hashes. The [license directory](research/crypto/licenses) preserves the original text bytes. Identical files share one content hash filename. Copyright statements are retained exactly rather than replaced with Thorum attribution. No license alternative is selected by this inventory.

The collection includes root LICENSE, COPYING and NOTICE files, explicit license files in package metadata, and reviewed packaging exceptions. The r-efi package stores its license grants and copyright in AUTHORS, which is preserved under its original filename in the inventory. The unicode-ident expression includes Unicode-3.0 in addition to its alternative code licenses. These source terms remain distinct from the project MIT license.

## Reproduction and byte verification

The generator uses Python 3.11 or later and captures `cargo metadata --format-version 1 --locked --offline` internally. Cargo.lock is parsed with the standard library TOML reader. Every cached registry archive is verified against its lock checksum before notice bytes are read. The selected bytes must also match the resolved source package. Full Cargo metadata, local paths, environment details and host identifiers are not published.

After the complete locked registry cache is available, the commands are:

```text
python research/crypto/dependency_inventory.py
python research/crypto/dependency_inventory.py --check
```

Generation reproduces the inventory, this notice and the copied license artifacts. Check mode compares exact bytes and the complete artifact set without rewriting files. Missing packages, old records, missing notices, altered bytes, stale copied files, unknown license identifiers and missing license metadata cause a failure. Additional license identifiers or packaging exceptions require an explicit generator review. The license directory disables Git text conversion so original bytes remain stable across checkouts.

## Dated advisory source check

On 2026-10-26, a public OSV query batch for all 52 exact resolved registry versions returned 0 matching advisories. The recorded response covers the current lock file. This is a dated database response and upstream source review, not a security audit or a guarantee of absent vulnerabilities. Inventory generation and check mode do not contact OSV or refresh this snapshot.

| Snapshot field | Value |
|---|---|
| Reviewed Cargo.lock SHA256 | `3bc0a865e041ab8e07d9f70d7cc97ff2e2d933326bf390b982c1f57ace3a4fd4` |
| Raw OSV response body SHA256 | `8f96b1b7aa528c6256c0169be2e70b792354589655daacac7b173cfae52596b9` |
| Raw OSV response body length | 169 bytes |
| Source | [OSV query batch API](https://google.github.io/osv.dev/post-v1-querybatch/) |

The reviewed resolution contains ml-kem 0.3.3. Its [upstream security repair](https://github.com/RustCrypto/KEMs/pull/386) removes secret indexed CBD table access across all parameter sets, including ML-KEM-1024. That repair was identified through the upstream changelog despite an earlier empty advisory response for the older lock. An empty database result therefore does not replace source review. In the reviewed resolution, ctutils 0.4.6 is above the [RUSTSEC-2026-0385](https://rustsec.org/advisories/RUSTSEC-2026-0385.html) patched threshold, and cmov 0.5.4 is above the [RUSTSEC-2026-0003](https://rustsec.org/advisories/RUSTSEC-2026-0003.html) patched threshold.

The inventory records upstream declarations and original notices. It is not a complete legal review, a dependency implementation audit, a cryptographic composition review, or evidence that private payments, confidential stake or production key management have been implemented. Distribution obligations require review for the actual source and binary artifacts being distributed.
