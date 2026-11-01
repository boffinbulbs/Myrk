# Fallible input across proving owners

This laboratory connects the [deferred fallible raw writer](../fallible-input/README.md) to the actual retained extension, source, composite and proving context. Ordinary and fallible fields use one owner family and the same phase transitions. A raw source failure returns through `Context::try_prove` before main preparation or proof construction begins.

## One nominal ownership chain

The raw input is an owned matrix of the same preparation type throughout the chain:

$$
\text{Context}
\longrightarrow\text{CompositeStore}
\longrightarrow\text{SourceStore}
\longrightarrow\text{CommitmentStore}
\longrightarrow\text{PreparationStore}.
$$

Each ordinary or fallible entry shares its original phase claim, failure guard and successful finish. Private deferred writer closures call the next owned layer after its outer checks. Public callers supply fields or typed source errors. They supply no expected root, row predicate or validity callback.

Changing only the innermost method would leave incompatible `OwnedMatrix`, `Entry`, `Role` and `FileState` types across the original crates. The local derivative connects all of those types to one preparation package. Original laboratories and their recorded results remain unchanged.

On successful raw ingestion, the entry calls the original owned prover. Its source still leads to the natural 512 point domain, actual owned preparation, tiled extension, committed main data, normalized quotient construction and original single opening. The original shared private opening flag, continuing randomness, transcript and proof construction order are retained. This diagnostic exercises the earlier failure path. It does not produce a proof from the new nominal context.

## Typed failure before proving effects

For an actual checked reader error $e$, the caller receives the original nested cause:

$$
e\mapsto\operatorname{Access}(e)
\mapsto\operatorname{Preparation}
\mapsto\operatorname{Storage}
\mapsto\operatorname{Main}.
$$

The preparation owner closes its writer and removes its partial owned output. Extension and source guards preserve the cause before the composite guard closes the shared lifecycle. Cleanup and a subsequent refused request cannot replace that cause with an unwind marker. Infallible storage trait unwinds retain their distinct semantics.

The actual context still validates its original fixed profile and reserves thirteen roles totaling 1,325,056 field bytes. Failure leaves the raw entry `Removed` and the remaining twelve entries `Planned`. The immediate source owner retains its 2,048 byte raw reservation. A second request through the same context refuses before iterator initialization and reads.

## Recorded native controls

Three checked 256 by 2 synthetic source files use independently saved canonical trace literals:

| Source event | Actual checked error | Reads attempted |
| --- | --- | ---: |
| Truncate the same opened file before its first read | `Length` | 1 |
| Replace field 255 with the noncanonical prime | `NonCanonicalField` | 256 |
| Read row 256 on the terminal extra probe | `Bounds` | 513 |

All three calls preserve the exact nested error through the actual `Context::try_prove` entry. Three failed owner reentries initialize and read their producer zero times. Actual composite, source and extension snapshots remain failed with their original cause and reservations.

The original observer measures unchanged DFT, commitment, opening, verification and RNG counters after each construction baseline. Both actual PCS and planning anchor retain unchanged delivered RNG fingerprints and empty commitment roots. The original construction includes one MMCS clone and 32 delivered salt seed bytes per observer. Those effects are included, with no seed reset. No masks or additional salts are drawn by the failing raw calls.

Context construction also invokes the unchanged small resource planner twice. Its fixed quartic relation has width two, two public values and four constraints, and uses the retained symbolic degree inference. Three context constructions therefore include six such planner calls by source inspection. These are constructor operations, not measured full signature symbolic collections.

One guarded test passed in 0.03 seconds on Windows x86_64 with Rust 1.94.1 on an Intel Core i9-13900H. Peak private process commit was 1,290,240 bytes and aggregate job commit was 2,326,528 bytes. The installed process and aggregate limits were each 512 MiB, with a fresh 2 GiB admission and 120 second deadline. These are fixed failure diagnostic measurements.

The [native record](results/native.json), [validation](validation.json), [source manifest](provenance.json) and [provenance notes](NOTICE.md) preserve this scope. No successful proof, original proof replay, opening control, wide source walk or full signature symbolic collection executes. The complete signature remains outside the unchanged raw width, stored shape and public value admissions. Full hiding security composition and same witness private ledger integration remain separate requirements.

## Reproduction

```text
python research/fallible-source/static_check.py
cargo clippy --manifest-path research/fallible-source/Cargo.toml --release --lib --locked --offline -- -D warnings
cargo clippy --manifest-path research/fallible-source/Cargo.toml --release --features diagnostics --lib --test input --locked --offline -- -D warnings
cargo test --manifest-path research/fallible-source/Cargo.toml --release --features diagnostics --test input --locked --offline --no-run
```

Default builds expose no context. The diagnostic requires its explicit feature, ignored test selection, `KOVA_FALLIBLE_SOURCE_GATE=reviewed-external-resource-admission`, an exclusive `KOVA_FALLIBLE_SOURCE_RECORD` output and real external limits. After a separate admission, invoke the compiled test with `--ignored --exact actual_context_retains_fallible_raw_source_causes --test-threads=1`. CI checks source identities, recorded evidence, explicit formatting, compilation and strict lints without executing the native diagnostic.
