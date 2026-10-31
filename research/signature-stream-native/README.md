# Streamed native signature and ownership

This experiment connects the complete bounded signature and note owner AIR to the actual owned source cursor. Every genuine adjacent frame is evaluated through the retained `PackedSignatureOwnerAir::eval`. The native checker receives the actual private witness in process. Cryptographic hiding requires a separate proof construction.

## Complete relation and global frames

The original AIR executes the clock, packed sources, four Keccak windows, source sponge, canonical decoding, challenge sampling, transforms, matrix reconstruction and hint equations. Source owner and transaction context bindings execute in the same relation as all 64 final signature challenge equalities. The harness calls the complete retained entry point rather than a reconstructed subset.

For global frame $r$, its next source row is

$$
\operatorname{next}(r)=(r+1)\bmod8192.
$$

First, last and transition selectors use the actual global coordinate. The last frame borrows the saved original row zero, with the external transition disabled. Internal Keccak slots retain their actual joins. Three rolling full width rows replace a complete wide trace allocation.

A successful run requires all 8192 baseline frames to satisfy the complete AIR, and three additional negative and three restored evaluations. Baseline progress logging does not select which rows are evaluated. Every failing baseline records its actual failure before termination.

## Connected consumer controls

Each new control changes one real source byte while keeping its held word consistent in both borrowed rows and its current packed port. The same complete AIR must reject exactly the expected consumer equation. Every saved cell is restored before a new empty failure evaluation and continued source generation.

| Genuine frame | Connected obligation | Required failed constraint |
|---|---|---:|
| 234 to 235 | Same hidden note owner and private key binding | 25052 |
| 5369 to 5370 | Actual final signature challenge equality | 23836 |
| 8190 to 8191 | Same canonical transaction context | 24958 |

These are frame local counterfactuals. They do not create globally consistent false witnesses or invalid computation proofs. Unexpected additional failures reject the control. No host callback or filtered failure list substitutes for the actual equations.

## Evidence and resource boundary

The [validation record](validation.json) retains actual counts and guard measurements. The source count is one streamed construction and 8198 full AIR calls, comprising 8195 positive and three negative evaluations. There are no reference generations, complete wide trace allocations, symbolic collections or backend proofs in this experiment.

The retained symbolic shape supplies a source bound of 69242 failures per evaluation. The actual concrete builder collects its complete finite failure list. Each list is dropped before the next call. Saved observations retain only the count and up to eight leading indices. The bound is not a newly measured clean assertion count or an allocator bound.

The unchanged component guard enforces process and aggregate memory limits, fresh available memory and a 120 second deadline. Component success does not establish full prover resource feasibility. A failed or interrupted run cannot be reported as a partial successful scan.

## Remaining integration

Native validity of a bounded synthetic owner is distinct from universal constraint soundness, a hiding signature proof and a private payment. Hidden membership, stable nullifier derivation, spent state, conservation, encrypted delivery and authenticated ledger authority still need direct same witness composition. The public full constructor remains disabled and the retained proof resource refusal remains.

No complete post quantum, Fiat Shamir or knowledge security profile is established by native checking. The private chain, confidential stake, consensus, mining and wallet roadmap retains its separate implementation and review gates.

## Reproduction

Rust 1.94.1 and exact locked dependencies define the compiled scope. Static checks validate source identities and saved observations without regenerating source rows or executing the AIR.

```text
python -I -S research/signature-stream-native/static_check.py
cargo clippy --manifest-path research/signature-stream-native/Cargo.toml --locked --offline --no-default-features --lib -- -D warnings
cargo clippy --manifest-path research/signature-stream-native/Cargo.toml --locked --offline --no-default-features --features stream-controls --lib --test stream -- -D warnings
cargo test --manifest-path research/signature-stream-native/Cargo.toml --locked --offline --no-default-features --features stream-controls --release --test stream --no-run --jobs 1
```

Native execution requires a separate frozen source and resource review. Provenance, the exact root adaptation and the MIT license retain the implementation lineage.
