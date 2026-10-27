# Matrix sampling reference record

The [constraint specification](../../docs/matrix-sampling.md) defines one bounded SHAKE128 and rejection sampling relation, its complete control, immutable banks, diagnostic statement, proof profile and incomplete production boundary. It follows the matrix expansion algorithm in [FIPS 204](https://csrc.nist.gov/pubs/fips/204/final) and SHAKE in [FIPS 202](https://csrc.nist.gov/pubs/fips/202/final).

The generator reuses the existing independently implemented round function in the [hash reference](../hash-proofs/README.md) and compares completed coefficients and cursors with the [full transparent signature oracle](../signatures/README.md). Four distinct retained public key seeds supply all 56 coordinates each. The corpus contains 224 genuine cases, 1008 exact output bytes each, 1344 full before and after sponge states and 288 selected round states. All full streams additionally match Python hashlib SHAKE128. Existing source versions, selected official bytes and native synthetic fixtures retain their exact hashes.

Ten injected exact capacity streams exercise ignored high bits, rejection at q, consumption ending at 840, 843 or 1008 bytes, and three cases with fewer than 256 accepted coefficients. They explicitly make no SHAKE seed claim. Separate sampler constraints test those control paths, while genuine cases require the hash and sampler to share one bank inside the same AIR. A combination of unrelated hash and sampler fixtures cannot replace that connection.

Actual AIR tests cover all 224 genuine cases. Selected round comparisons cover all 200 state bytes. Causal cases recompute genuine wrong source hashes and matching outputs before breaking a required seed, coordinate or continuation link. Other tests require complete bank holds, exact output byte linkage, fixed event order, monotone counts and terminal completion. Unsupported streams are also built without the normal witness precheck and rejected by sampler constraints, including attempts to complete through padding.

The real proof corpus rejects thirteen raw false constructions at the backend, all 1090 public mutations, wrong profile and sixteen canonical transport corruptions. Repeated honest witnesses produce different commitments. Public integration tests verify independently supplied expected data without passing a seed to the verifier. The diagnostic polynomial is public and can identify repeated seeds, so this interface supplies no key privacy or owner permission.

`profile_check.py` pins reviewed source and the fixed parameter declarations. The existing hash profile guard checks resolved dependencies separately. A source change guard is not a correctness proof or security audit. The original primitive hash profile, output limit, measurements, note identities and nullifier derivations remain unchanged.

```text
python research/matrix-sampling/reference_vectors.py --check
python research/matrix-sampling/profile_check.py
cargo test -p thorum-hash-proof-lab --locked --offline matrix_sampler:: -- --test-threads=1
cargo test -p thorum-hash-proof-lab --release --locked --offline matrix_sampler:: -- --test-threads=1
cargo test -p thorum-hash-proof-lab --release --locked --offline --test matrix_sampler -- --test-threads=1
```

Six blocks are a bounded laboratory support class. They do not establish full standard completeness, a production resource policy, private signature authorization, quantum composition or a new benchmark. The complete signature relation must connect these exact seed and output cells to the same hidden key and private arithmetic.
