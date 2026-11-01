# Bounded source proof decoding

This laboratory adds a bounded decoding boundary for the [retained source proof](../source-prover/README.md). It reuses the earlier conservation laboratory's lexical admission and shape mechanisms, with matching delimiters and canonical serializer comparison. Its diagnostic decodes a previously generated synthetic proof. It performs no proving, verification, commitment, RNG sampling or challenger operations.

## Admission sequence

The decoder keeps five separate conditions:

$$
\operatorname{Decode}(b)=
\operatorname{Budget}(b)\land
\operatorname{TypedEncoding}(b)\land
\operatorname{FixedShape}(b)\land
\bigl(\operatorname{Serialize}(\operatorname{Parse}(b))=b\bigr).
$$

The equation describes encoding admission. Cryptographic validity additionally requires the original verifier, configuration and expected public statement. Successful decoding does not establish a valid proof or private payment.

| Boundary | Actual behavior |
|---|---|
| Borrowed frame | Checks `KPV1`, a four byte big endian payload length and exact remaining length |
| Lexical budget | Bounds bytes, nesting, tokens, container items, strings and numbers before owned proof decoding |
| Typed decoding | Uses the original `p3_uni_stark::Proof` and retained hiding PCS and FRI proof types |
| Fixed shape | Checks dimensions, opening order, salts, cap roots, rounds, claims and grinding witnesses |
| Canonical equality | Streams actual typed serialization into a borrowed comparison writer, without a second encoded vector |

The experimental frame is eight header bytes followed by JSON. `KPV1` is not a production chain format. Input is already a borrowed slice. This component does not prevent an upstream network reader from allocating that slice before admission. A reader must inspect its bounded header before payload allocation.

## Resource and shape limits

| Quantity | Bound |
|---|---:|
| Payload bytes | 2,097,152 |
| Lexical nesting | 24 |
| Lexical tokens | 200,000 |
| Items per lexical container | 16,384 |
| String bytes | 64 |
| Decimal digits | 20 |

Lexical admission is an allocation budget, not a complete JSON grammar or proof schema. The real typed decoder still rejects malformed grammar, missing and duplicate fields, and invalid field representations. Unknown fields ignored by that decoder are rejected by canonical comparison. Shape validation follows owned decoding. These limits do not constitute a formal maximum allocation theorem for every parser path.

The fixed relation is the original 256 by two Quartic source relation. Prepared height is 512 and main LDE shape is 4096 by six. The comparator retains extension degree four, 64 queries, eight quotient chunks, nine binary FRI rounds, sixteen salt columns and zero grinding. Input opening order is auxiliary, main, quotient, with respectively one matrix of width eight, one of width six and eight of width eight. No dimensions are accepted from a caller's proposed profile.

JSON field values use the original Montgomery representation. The original field deserializer rejects words at or above 2,013,265,921. Four coefficient extension arrays retain their original fixed length decoder. Cap deserialization requires a power of two root count, followed here by the fixed one root shape check. Pruned authentication paths retain conservative bounds derived from the actual tree heights.

## Diagnostic evidence

The 596,650 byte fixture is copied unchanged from the previous source prover result. The producer and its healthy verifier were not rerun. Four original canonical decoding passes include framed, unframed and restored inputs.

| Controls | Tested result |
|---|---|
| Fourteen resource and frame errors | Reject with zero calls to owned proof decoding |
| Fourteen encoding, shape and canonical errors | Reject through the actual typed decoder or subsequent boundary |
| Four canonical writer controls | Sticky errors, overrun, underrun and successful partitioned writes behave as required |
| Altered commitment with valid encoding and shape | Decodes without cryptographic verification |

The final control demonstrates the separation between decoding and verification. It is not counted as an accepted cryptographic proof. No `ProofProduced` owner state or payment acceptance is selected.

One guarded release diagnostic passed. [Validation](validation.json) records the original 512 MiB process and aggregate job limits, fresh two GiB availability requirement and 120 second deadline. Three separately guarded preparation commands passed strict default and diagnostic checks and test compilation. [Provenance](provenance.json) records exact source, fixture and dependency identities. The graph contains 62 registry packages and 64 total nodes, with active features retained or narrower than the preceding source laboratory.

## Reproduction

```text
python -I -S research/proof-transport/static_check.py
cargo clippy --manifest-path research/proof-transport/Cargo.toml --release --features diagnostics --lib --test transport --locked --offline -- -D warnings
cargo test --manifest-path research/proof-transport/Cargo.toml --release --features diagnostics --test transport --no-run --locked --offline --jobs 1
```

The saved evidence check does not execute the native diagnostic. Native reproduction requires a fresh isolated output directory, reviewed source and fixture identities, explicit finite resource admission and the retained external guard. The diagnostic uses exclusive report creation and never overwrites an existing result.

## Remaining integration

The [finite reader experiment](../frame-reader/README.md) adds header admission before payload reservation, one request authority and actual reader error controls. Production transport, blocking I/O deadlines and aggregate peer limits remain separate work. This diagnostic exposes no node RPC or production decoder API. Full signature construction remains outside current resource admission, as recorded in the [complete overlay inventory](../overlay-composition/README.md). Hiding, soundness, knowledge and quantum transcript composition, and the same hidden witness payment ledger remain open.

The [roadmap](../../docs/delivery-roadmap.md) retains private payments by default, confidential staking, work and stake consensus, mining, governance, restricted viewing and service APIs, ordinary nodes, desktop and mobile wallets, contracts, Safe, migration, compact history and later Aegis.
