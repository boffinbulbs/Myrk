# Deferred fallible source ingestion

This component extends the retained [preparation owner](../source-preparation/README.md) with a fallible raw field stream and deferred iterator initialization. Existing raw ingestion already accepts an iterator. The change places its initialization after metadata, owner, reservation and exclusive output creation checks, and preserves actual source errors through cleanup. The original laboratory remains unchanged.

## Construction boundary

For a raw matrix with height $H$ and width $W$, let $N=HW$. Both public entries use one canonical writer:

$$
\operatorname{encode}(x)
=\mathop{\Vert}_{i=0}^{N-1}\operatorname{LE}_{32}(x_i),
\qquad x_i\in\mathbb F_{2013265921}.
$$

`write_raw` accepts ordinary fields. `try_write_raw` accepts `Result<BabyBear, Error>`. The latter retains a checked source error at any read, including the probe after field $N-1$. An early end or an additional valid field remains `Incomplete`. A source error never becomes a default field or a supplied validity verdict.

| Order | Operation | Failure effect |
| --- | --- | --- |
| 1 | Validate shape and exact resource accounting | No producer initialization or output reservation on shape refusal |
| 2 | Check owner phase and reserve a bounded output | Existing failed owners refuse reentry |
| 3 | Create the output exclusively | A preexisting unowned file survives |
| 4 | Initialize and pull the producer | Actual typed source errors enter the pending output cleanup |
| 5 | Require exactly $N$ fields and a clean end | No partial output can seal |
| 6 | Sync, close the writer and open the checked output lease | Successful lease retains its directory owner |

The deferred factory is private implementation machinery that creates a data iterator. Public callers supply field data. There is no expected root, row callback or proof acceptance predicate. Constructing an input object can itself open descriptors before the call. The tested boundary concerns its `IntoIterator` initialization and subsequent reads.

The unchanged raw width bound is eight. Stored dimensions remain at most 4096 by 12, with at most sixteen reservations and 2 MiB of field contents. The complete signature header, 8192 by 42178, remains refused. These limits do not admit a full signature prover.

## Failure and ownership

The inherited owner records `Ready`, `Preparing`, `Complete` and `Failed`. A real source failure closes the pending writer and removes only the file that owner created. The first typed cause remains visible across store clones and explicit cleanup. Conservative reservations remain charged. Cleanup never reopens a failed owner.

A successful checked output descriptor outlives the public store handle through its shared owner. Its descriptor closes before the final directory lease. Exclusive output collisions preserve unowned files even at owner destruction. Cleanup is flat and best effort. This is not durable recovery or authenticated immutable secret storage.

## Recorded evidence

One guarded native test records fifteen primary cases and five failed owner reentries:

| Cases | Actual operation and result |
| --- | --- |
| Two successes | Fallible and ordinary copies match all 96 expected bytes and 24 fields from saved independent literals |
| Three source faults | Same opened source truncation returns `Length`, a noncanonical field returns `NonCanonicalField`, and the extra probe returns actual checked `Bounds` |
| Eight shape refusals | Four shapes through both entries initialize and pull the producer zero times |
| Two output collisions | Real exclusive creation returns `AlreadyExists` before initialization and preserves sentinel bytes |
| Five reentries | Failed owners refuse before initialization, with original cause and reservation unchanged |

Each source contains twelve fields in a 4 by 3 checked file, or 48 bytes. Each tested store reserves at most 48 field bytes and one entry. The diagnostic took 0.05 seconds on Windows x86_64 with Rust 1.94.1 on an Intel Core i9-13900H. Recorded private process commit peaked at 1,294,336 bytes and aggregate job commit at 2,256,896 bytes. Installed process and aggregate limits were each 512 MiB, with a fresh 2 GiB memory admission and 120 second deadline. These are fixed diagnostic observations, not network or prover benchmarks.

The [native record](results/native.json), [validation](validation.json), [source manifest](provenance.json) and [adaptation](raw-adaptation.patch) preserve the exact scope. Compilation includes retained interfaces. The test executes no preparation randomness, transform, commitment, opening, transcript, AIR evaluation or proof. The new nominal preparation type has not yet been connected to the complete source prover. Hidden witness authorization, full proof security composition and atomic private ledger integration retain their separate gates.

## Reproduction

```text
python research/fallible-input/static_check.py
cargo clippy --manifest-path research/fallible-input/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/fallible-input/Cargo.toml --release --features diagnostics --lib --test input --locked --offline -- -D warnings
cargo test --manifest-path research/fallible-input/Cargo.toml --release --features diagnostics --test input --locked --offline --no-run
rustfmt --edition 2024 --config skip_children=true --check research/fallible-input/src/lib.rs research/fallible-input/tests/input.rs
```

The ignored diagnostic requires `KOVA_FALLIBLE_INPUT_GATE=reviewed-external-resource-admission`, an exclusive `KOVA_FALLIBLE_INPUT_RECORD` output, and actual external resource limits. Invoke the compiled test with `--ignored --exact deferred_input_retains_actual_source_failures --test-threads=1` only after a separate admission. CI checks saved evidence and compilation without replaying the diagnostic. Original licenses and [provenance](NOTICE.md) remain applicable.
