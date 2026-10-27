# Compact transform reference record

The [compact constraint specification](../../docs/compact-ntt.md) defines the scalar register bank, eight slot arithmetic program, canonical write induction and separate proof profile. The module reuses the existing transform types, exact multiplication evaluator and twiddle functions. No new dependency or whole signature verifier is introduced.

The original [normal residue references](../ntt-proofs/README.md) remain unchanged. Actual compact AIR tests compare all 47 classifications and all 2113 public fields. The 31 valid cases additionally match direct odd root DFT definitions. The new bank boundaries match 309 retained stage states, and its eight arithmetic slots match 35584 valid records from the original product, quotient, carry and reduction corpus. Hostile rows from the larger original corpus are not relabeled as valid evidence.

The causal tests reconstruct exact local products and matching declared final outputs while breaking required routing. The separate 169 hostile checks cover all eight slots and sixteen write destinations, initialization and padding holds, forbidden counter states, complete normalization and bytewise public aliases. Sixteen cases produce a noncanonical final write equal to q while retaining exact local products. Typed constructors reject them, and direct AIR checks independently reject them when that guard is bypassed.

The actual proof corpus verifies inverse and repeated forward executions, fresh masks and salts, selected public values, bytewise aliases, transcript profile and bounded canonical transport. Eight raw false proofs are constructed after deliberately bypassing witness checks and fail direct backend verification as well as the canonical wrapper. An integration test uses the shared public types, verifies both modes and rejects compact proofs under the original profile.

`reference_vectors.py` reproduces all three complete SHA3-512 adapter goldens, fixed compact parameters, exact historical source hashes and analytical field array dimensions. `profile_check.py` is a source change guard for the reviewed implementation and closed profile. Dependency resolution remains covered by the existing NTT profile guard. Neither guard proves mathematical correctness, privacy, knowledge soundness or a security level.

```text
python research/compact-ntt/reference_vectors.py --check
python research/compact-ntt/profile_check.py
cargo test -p thorum-ntt-proof-lab --locked --offline compact:: -- --test-threads=1
cargo test -p thorum-ntt-proof-lab --release --locked --offline compact:: -- --test-threads=1
cargo test -p thorum-ntt-proof-lab --release --locked --offline --test compact_transforms -- --test-threads=1
```

Both full polynomial inputs and outputs are public diagnostic values. Invertibility prevents any coefficient confidentiality claim at that boundary. Reusing the arithmetic inside a private signature verifier requires exact canonical input linkage and internal output consumption, with full sampling, challenge equality, same witness consistency and transaction binding. No private payment acceptance, independent audit, new benchmark or composed quantum security result follows from this component.
