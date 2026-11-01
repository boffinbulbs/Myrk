# Header admission and finite reader ownership

This laboratory connects header admission to the [retained proof decoder](../proof-transport/README.md). The component checks an eight byte header before requesting payload capacity. Successful bytes enter the unchanged typed decoder, fixed shape checks and borrowed canonical serializer. Typed proof and cap objects are reconstructed as data. No proving, verification, commitment or RNG operation runs.

## Resource authority

One attempt admits one complete finite input. Its authority is spent before the first read, including failed reads. The type supplies no clone or reset method. Reentry returns before reading, reserving payload capacity or decoding another proof.

For declared payload length $n$, admission requires:

$$
0\le n\le 2^{21},\qquad
B_{\mathrm{wire}}=8+n+1\le 2^{21}+9.
$$

The first eight bytes hold `KPV1` and a big endian unsigned length. Before this header is admitted, only eight bytes of read credit exist. After admission, the complete header, payload and one byte trailing-data probe are charged before `try_reserve_exact(n)`. The probe requires EOF. A returned trailing byte rejects before typed decoding. The payload limit remains two MiB. The experimental envelope is not a production chain wire format.

| Phase | Allowed effect |
|---|---|
| Claim | Spend the attempt once |
| Stack header | Read at most eight bytes before header admission |
| Length admission | Reject unsupported magic and excessive declared payload |
| Credit and reservation | Charge the complete request, then request payload capacity |
| Payload | Fill only the admitted payload slice |
| EOF probe | Read at most one extra byte and require EOF |
| Decoder | Apply the original lexical, typed, shape and canonical checks |

Every successful required read advances the input. EOF or any I/O error terminates the attempt. Read calls have a fixed ceiling of $2^{21}+9$. A result larger than its supplied buffer is rejected before advancing a slice. This implements finite byte and call accounting. An individual `Read` implementation can still block. Deployment requires caller deadlines and connection and peer admission. These are not provided by the byte budget. The behavior was reviewed against the [Rust 1.94.1 I/O source](https://raw.githubusercontent.com/rust-lang/rust/1.94.1/library/std/src/io/mod.rs).

The reader does not retry `Interrupted`. It returns the original `io::Error`, including its cause. EOF while filling a required slice is separately classified as truncation. An allocation error retains its original `TryReserveError`. Forced allocation failure was not selected for this diagnostic.

Reservation calls, requested payload bytes, observed vector capacity and total process allocations are separate quantities. A rejected header has no payload reservation call. This does not claim that arbitrary caller readers or the entire process allocated nothing. The allocator may provide more capacity than requested, as specified by the [Rust 1.94.1 vector source](https://raw.githubusercontent.com/rust-lang/rust/1.94.1/library/alloc/src/vec/mod.rs). The component stores the observed capacity and creates no additional header-plus-payload copy.

## Ownership and error scope

The function consumes its reader argument. Owned reader values are dropped on success and failure. A borrowed reference does not transfer ownership of its underlying resource. Tests observe wrapper destruction and actual file read errors. They do not probe operating system descriptors after closure.

This is per-request resource authority, not consensus, stake or proof ownership. Header admission does not authenticate file contents or make them immutable. The decoder does not verify a public statement. Parsing success never marks `ProofProduced` or admits a payment.

## Actual diagnostic

The saved 596,650 byte synthetic proof reaches the actual decoder through an owned file and a separate seven byte fragmented reader. Both original inputs pass encoding, shape and canonical checks. The producer, previous decoder diagnostic and healthy cryptographic verifier are not rerun.

| Control group | Actual result |
|---|---|
| Short or invalid header, excessive lengths | Reject before payload reservation or decoding |
| Write-only file used for reading | Preserves an actual operating system I/O error |
| Actual file truncation | Stops at observed EOF before decoding |
| Trailing byte | Rejects at the accounted probe |
| Malformed and wrong-shape payloads | Reach the original decoder and reject there |
| Synthetic interruption and probe timeout | Preserve original error kind and cause identity |
| Reader contract violation | Rejects an excessive returned count |
| Maximum and zero length payloads | Respect their admitted capacity requests and reject invalid JSON |
| Fourteen failed and two successful reentries | Perform no new read, reservation or decoding |

Fourteen failure cases pass their expected controls. Thirty-two tracked reader destructions are asserted across original and reentry calls. The interruption control makes one read call. The probe timeout is a synthetic I/O fault, not a network deadline test. One bounded scratch file is reused, truncated and removed. No socket or server is selected.

[Native results](results/native.json) retain actual byte, call, capacity and decoder counters. Failure snapshots are ordered as spent flag, read calls, validated returned byte counts, charged wire credit, reservation calls, requested payload bytes, observed capacity, decoder admissions, typed decodes, decoded shapes and canonical encodings.

One guarded release diagnostic passed. [Validation](validation.json) records the original 512 MiB process and aggregate job caps, fresh two GiB availability requirement and 120 second deadline. Three separately guarded compiler preparations passed. [Provenance](provenance.json) binds the exact source, unchanged codec, fixture, dependency and feature identities. No cryptographic proof is generated or verified by this result.

## Reproduction

```text
python -I -S research/frame-reader/static_check.py
cargo clippy --manifest-path research/frame-reader/Cargo.toml --release --features diagnostics --lib --test reader --locked --offline -- -D warnings
cargo test --manifest-path research/frame-reader/Cargo.toml --release --features diagnostics --test reader --no-run --locked --offline --jobs 1
```

Native reproduction requires a fresh isolated report and scratch directory, reviewed exact identities and finite external resource admission. The diagnostic uses exclusive output creation. Saved evidence checks do not run it again.

## Remaining protocol work

This component supplies a finite reader boundary for the small source proof schema. Production transport, blocking I/O deadlines and aggregate peer policy remain separate. Full signature proving remains refused by current resource classes. The [complete overlay inventory](../overlay-composition/README.md) records the conditional contents and outstanding proving architecture.

Batching, DEEP and proximity errors, joint mask and salt exposure, repeated observations, actual multiround Fiat Shamir, knowledge and quantum assumptions remain explicit review obligations. The same hidden witness must connect eligibility, ownership, authorization, stable nullifiers, spent state, conservation, policy, encrypted delivery and atomic ledger consumption. Private payments by default and the [complete roadmap](../../docs/delivery-roadmap.md) remain the project requirements.
