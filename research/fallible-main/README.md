# Fallible source to actual main commitment

This laboratory connects a successful checked fallible input to the retained owned main commitment. It complements the [source failure controls](../fallible-source/README.md). One actual raw owner reaches preparation, tiled extension and the real hiding MMCS. The diagnostic then terminates that attempt. It constructs no proof and cannot resume its prefix.

## Construction and observation

The fixed source has height 256, width two and 512 canonical field values. The retained preparation layout, four random codewords and blowup eight produce:

$$
(H,W)=(256,2)
\longrightarrow(2H,W+4)=(512,6)
\longrightarrow(16H,W+4)=(4096,6).
$$

The original MMCS salts each committed row with sixteen fields. Its actual leaf input has twenty two fields, with unchanged canonical encoding, SHA3 framing, compression and physical row order. The actual returned root is computed by that MMCS. No expected preimage, root or validity predicate enters the construction.

Two observations have separate boundaries:

| Observation | Actual data accessed | Fixed comparison |
| --- | --- | --- |
| Returned main matrix | The original MMCS `get_matrices` view and owned checked windows | All 24,576 main fields |
| Committed leaf preimages | A single pass forwarding observer around the original leaf hasher input | 360,448 bytes containing 24,576 data and 65,536 salt fields |

The forwarding observer returns the exact original leaf digest and supplies no expected values. Upstream private salt vectors are not accessed directly. No extra query or opening obtains their contents. One bounded capture is transferred without duplication. The real returned main matrix is read separately before the owner closes.

Every captured byte and returned main field matches the retained [salted leaf fixture](../source-commitment/fixtures/salted-leaves.bin). The actual root matches the separately reconstructed [root record](../source-commitment/fixtures/root.json). The leaf fixture is an older candidate capture. Its independent SHA3 reconstruction validates that root, not an independent derivation of every transform coefficient. No earlier reference producer or complete proof is replayed.

## Original randomness and ownership

Actual delivered RNG fingerprints match the saved main prefix observations. The original mask source delivers 10,948 bytes and salt source 279,800 bytes, including the original 32 byte construction fork. One original constructor MMCS clone remains counted. The PCS, configuration, RNG and prover data are not cloned or reset for inspection.

One actual main commitment uses two tiled LDE calls and one returned data inspection. The planning anchor retains its unchanged operation and RNG observations. Context construction includes two original small quartic symbolic degree inferences by source inspection. There is no full signature symbolic collection, transcript construction, quotient commitment or opening.

Before termination, three entries are complete and ten remain planned under the unchanged thirteen role reservation of 1,325,056 field bytes. Actual raw, prepared and main file contents total 112,640 bytes. The original private opening flag remains unused before and after closure.

The original proving attempt is deliberately dropped before completion. Its actual `Unwind` marker closes the outer owner. This records intentional diagnostic termination, not a source fault or a completed proof. The inner committed data remain retained under their original leases. Four real reads through the closed lease and its alias refuse, including after the public Context is dropped. A subsequent request refuses before source initialization or reads, with unchanged cause and operation counts. No prover data or transcript escapes for resumption, and `ProofProduced` is never recorded.

## Measured scope

One guarded test passed in 0.10 seconds on Windows x86_64 with Rust 1.94.1 on an Intel Core i9-13900H. Peak private process commit was 2,150,400 bytes and aggregate job commit was 3,432,448 bytes. Installed process and aggregate limits were each 512 MiB, with a fresh 2 GiB memory admission and 120 second deadline. These are fixed main construction diagnostic measurements.

Stored field contents, dense salt matrices, digest vectors, the 360,448 byte capture, static expected fixture, 98,304 byte returned field observation and serialized transport are separate quantities. This small peak does not establish full signature prover feasibility. The full signature remains outside the unchanged raw width, stored shape and public value admissions. Complete hiding security composition and atomic same witness private ledger integration remain open.

The [native observations](results/native.json), [validation](validation.json), [source manifest](provenance.json) and [source notes](NOTICE.md) retain exact scope. Text identities normalize CRLF to LF. Binary fixture identities retain raw bytes.

## Reproduction

```text
python research/fallible-main/static_check.py
cargo clippy --manifest-path research/fallible-main/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/fallible-main/Cargo.toml --release --features diagnostics --lib --test main --locked --offline -- -D warnings
cargo test --manifest-path research/fallible-main/Cargo.toml --release --features diagnostics --test main --locked --offline --no-run
```

Default builds expose no context. The ignored diagnostic requires its explicit feature, `KOVA_FALLIBLE_MAIN_GATE=reviewed-external-resource-admission`, an exclusive `KOVA_FALLIBLE_MAIN_RECORD` output and actual external limits. After a separate admission, invoke the compiled test with `--ignored --exact fallible_source_reaches_real_main_commitment --test-threads=1`. CI checks saved evidence, source identities, formatting, compilation and strict lints without executing the diagnostic.
