# Complete packed signature native witness

This separate integration target exercises the actual complete packed signature and note ownership constraints. It imports the retained source unchanged, with `native-execution` enabled only for this test package. The source package's default constructor refusal remains intact.

The selected fixture is A0 with verification key A, signature A0, transaction T0 and note N_A. The unchanged independent fixture provides the expected canonical transaction, authorization values and derived bytes. The harness loads typed subsets through a bounded reader. It does not call a host signature verification callback or generate new fixture signatures.

## Test scope

One complete witness has 8,192 rows and 43,176 columns. Its raw field storage is 1,414,791,168 bytes. The complete symbolic record contains 69,242 assertions per row and degree four. These quantities do not predict native memory or runtime.

The native test constructs one trace, compares the exact canonical transaction and 196 authorization values, and checks 288 bytes across five source and derived values. It then evaluates the actual complete AIR over every row. Constructor success alone is not acceptance.

After a valid baseline, six controls alter one physical row at a time. Each uses the real current and next row frames, including the last to first wrap. Both affected frames are evaluated. The exact original cells are restored and the affected frames are checked again.

| Control | Physical row | Intended failing constraints |
| --- | ---: | --- |
| Unread source word hold | 600 | 580 on both affected frames |
| Compensated nonBoolean pair | 0 | 3367 and 3368 |
| Key source read | 0 | 6141 and 25047 |
| Signature prefix boundary | 0 | 6182 and 21797 |
| Note owner read | 234 | 6280 and 25052 |
| Late note context | 8191 | 6157 and 24958 |

The compensated pair changes two bits of one byte while preserving its weighted value. It isolates Boolean encoding. The four port flips require both the selected word equality and the exact named consumer to fail. They exercise connected source reads and do not establish an isolated signature validity or ownership theorem. No padding only multirow mutation is included in this first selection.

The finite scope is one constructed trace, one complete positive scan, six negative borrowed frame checks and six restored positive borrowed frame checks, comprising 24 frame evaluations. Observations are synchronized before interpreting expectations. Diagnostic output contains bounded row and constraint indices, without witness values.

## Implementation status

The actual guarded test passed once on Windows 11 with a Core i9-13900H and Rust 1.94.1. The complete A0 witness passed every row. All six controls produced the exact expected constraint indices, and all six restorations passed. The observed test duration was 89.62 seconds, including construction, reference comparisons, the complete scan and the controls. This is not payment latency or proof generation time.

| Measured quantity | Actual record |
| --- | ---: |
| Complete constructed witnesses | 1 |
| Full positive scans | 1 |
| Negative borrowed frame checks | 6 |
| Restored positive borrowed frame checks | 6 |
| Borrowed frame evaluations | 24 |
| Peak process commit bytes | 1,419,198,464 |
| Peak aggregate commit bytes | 1,420,480,512 |
| Backend proofs | 0 |

The copied Windows guard enforced a 300 second deadline, 2 GiB process and aggregate commit limits and at least 5 GiB freshly available memory. It installed and read back both hard limits before resuming the child. No timeout or guard termination occurred. Source, fixture, dependency and executable identities matched after execution. Exact observations and the projected resource record are retained in fixtures-observations.jsonl and validation.json.

Release compilation and strict selected Clippy checks also pass. CI compiles this ignored native target and checks the recorded evidence. It does not automatically repeat the large native allocation. Fresh execution requires separate resource admission.

Native acceptance and rejection remain distinct from proof generation, payment validation and network capabilities. The later tuple corpus, consistent changed source controls, hiding proofs and complete payment joins remain separate work.

## Source derivation

The bounded fixture reader, canonical transaction mapper and global frame approach derive from research/signature-storage/src/native_tests.rs at revision 3d0193b6e4edd23692befba71fdc77d1a214f046. The narrower new test uses the actual packed relation. It does not execute the retained native suite. The original source and fixture provenance, license notices and research references remain applicable. Project source uses the repository MIT license, copied unchanged here. Exact registry versions and checksums remain in Cargo.lock.

## Reproduction

```text
python research/signature-packed-native/static_check.py
cargo fetch --manifest-path research/signature-packed-native/Cargo.toml --locked
cargo fmt --manifest-path research/signature-packed-native/Cargo.toml --all -- --check
cargo test --manifest-path research/signature-packed-native/Cargo.toml --release --locked --offline --test native --no-run --jobs 1
cargo clippy --manifest-path research/signature-packed-native/Cargo.toml --release --test native --locked --offline -- -D warnings
```

After separate native resource admission, set `KOVA_PACKED_NATIVE_GATE=reviewed-external-resource-admission` and select only:

```text
cargo test --manifest-path research/signature-packed-native/Cargo.toml --release --locked --offline --test native --jobs 1 -- --ignored --exact a0_complete_packed_native_and_source_controls --test-threads=1
python research/signature-packed-native/static_check.py --check-results
```

The static checker validates source identities and independently derived case predictions without executing the relation. `--registry-root` additionally checks actual retained Cargo registry sources. The Windows guard can enforce the recorded external limits around the exact compiled executable. Test result files are exclusive and preserve earlier evidence.
