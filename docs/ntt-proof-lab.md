# Normal residue NTT proof laboratory

The crate also exposes a separately namespaced [compact register profile](compact-ntt.md). It uses eight arithmetic slots, exact canonical writes and a fixed serial program with the same typed polynomial statement. The original profile and all reference data below retain their existing parameters. Neither diagnostic profile supplies private signature verification or owner permission.

## Implementation boundary

The [NTT component](../crates/thorum-ntt-proof-lab/src/lib.rs) constrains length 256 forward and inverse polynomial transforms under $q=8380417$. It connects canonical coefficient states, fixed twiddles, exact modular multiplication, modular additions and subtractions, all eight butterfly stages and inverse normalization inside one hiding STARK configuration.

The harness publishes its complete input and output polynomials. The NTT is invertible, so publishing an output permits recovery of its input. This is a transform correctness experiment rather than polynomial confidentiality, a private ownership proof or spending permission. No production payment acceptance path consumes these standalone transform proofs.

Future private authorization must keep coefficients, owner keys, signatures, hashes, matrices and their intermediate values internal to the same composed relation. It must connect the actual signature computation to the same hidden input note and exact authorized transaction. This component does not decode keys or signatures, convert signed coefficients, sample matrices or challenges, apply hints, reconstruct `w1`, verify a signature challenge or authorize a transaction.

Existing hidden input commitments, stable nullifiers and private payments by default remain unchanged. Complete private payment and confidential stake feasibility remain separate gates before kernel integration.

## Exact ordering and arithmetic

The component uses canonical unsigned normal residues rather than Montgomery form. Set $n=256$ and $\psi=1753$. The checks $\psi^{256}=q-1$ and $\psi^{512}=1$ establish the required root order. For eight bit reversal $\operatorname{rev}_8$, define

$$
r_i=\psi^{2\operatorname{rev}_8(i)+1}\pmod q.
$$

The forward output and inverse coefficients are

$$
A_i=\sum_{j=0}^{255}a_jr_i^j\pmod q,
\qquad
a_j=8347681\sum_{i=0}^{255}A_ir_i^{-j}\pmod q.
$$

Here $8347681=256^{-1}\pmod q$. The points $r_i$ are the odd roots of $X^{256}+1$. Their bit reversed order is part of the relation. The independent reference evaluates these formulas directly, without invoking the staged transform as its oracle.

Twiddles use $\zeta_k=\psi^{\operatorname{rev}_8(k)}\pmod q$ for indices 1 through 255. Index zero is an unused zero sentinel in the retained table. The schedule matches the normal residue implementation in pinned `ml-dsa 0.1.1`, corresponding to NIST Algorithms 41 and 42. The exact source and standard records are retained with the [references](../research/ntt-proofs/source_record.json). [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final).

Forward stage $s$ uses length $128\mathbin{\gg}s$ and group twiddle index $2^s+g$. Its butterfly computes

$$
t=\zeta_kv\bmod q,
\qquad
u'=u+t\bmod q,
\qquad
v'=u-t\bmod q.
$$

Inverse stage $s$ uses length $2^s$, decreasing index $(256\mathbin{\gg}s)-1-g$ and canonical negative twiddle $q-\zeta_k$. It computes

$$
u'=u+v\bmod q,
\qquad
t=u-v\bmod q,
\qquad
v'=-\zeta_kt\bmod q.
$$

Every stage has 128 butterflies, ordered by group and then local index. Forward execution needs 1024 modular products. Inverse execution needs 1024 butterfly products and 256 normalization products. These are analytical operation counts rather than measured resource costs.

## State transitions and exact reduction

The first row contains the input polynomial. Forward rows zero through seven perform the eight layers, with output entering the sticky padding state at row eight. Inverse rows zero through seven perform its layers. Row eight normalizes coefficients zero through 127, and row nine normalizes 128 through 255. Each normalization row holds the untouched half unchanged. Row ten enters sticky padding with the complete inverse output.

Eleven Boolean selectors fix this schedule, including the padding selector. First and last row constraints establish the initial stage and required terminal state. Stage transitions cannot skip a layer or stop before output. Padding holds every coefficient unchanged and binds the full expected output. Unused add and borrow flags are zero during normalization and padding.

Each coefficient has 23 Boolean bits and a canonical complement satisfying $v+\bar v=q-1$. Each row contains 128 copies of the [exact multiplication gadget](arithmetic-proof-lab.md). Their operands and results are connected to the correct coefficient wires and fixed twiddles. Quotients and carries cannot substitute a product that vanishes only modulo the unrelated AIR field prime $2013265921$.

Boolean sum reduction and difference borrow flags give exact modular equations. For canonical values, sum residuals lie in $[-2q+1,2q-2]$ and difference residuals in $[-2q+2,2q-1]$. These intervals are strictly inside the AIR prime, so field equalities establish the corresponding integer equalities. The evaluator is restricted to the exact BabyBear field used by this argument.

## Public interface

The expected statement is constructed through

```rust
Statement::new(
    mode: Mode,
    input: [u32; 256],
    output: [u32; 256],
    context: [u8; 64],
) -> Result<Statement, Error>
```

`Mode::Forward` has code one and `Mode::Inverse` code two. Every public coefficient must be below $q$, and proving and verification repeat that validation. `Witness::from_input([u32;256])` accepts canonical input and keeps generated intermediate states, products, quotients and carries inside the proving process. The witness has no general serialization or plaintext export interface.

`prove_ntt(&Witness, &Statement)` produces proof bytes or an error. `verify_ntt(&[u8], &Statement)` receives an independently supplied expected statement and no private witness. A successful native transform calculation or local witness check is not accepted as a proof.

The public vector has 2113 base field elements: one mode byte, 1024 little endian input coefficient bytes, 1024 little endian output coefficient bytes and 64 context bytes. Each coefficient byte is linked separately to its 8, 8 and 7 bit chunks and a zero fourth byte. This rejects coefficient plus AIR prime aliases without relying on a packed field equality. The first row binds input bytes and every padding row binds output bytes.

The context is opaque transcript data. A fresh context leaves the mathematical transform unchanged but requires a proof for the fresh complete statement. It does not authenticate a payment, owner, network version or signature message by itself.

## Profile and transport limits

The profile is `thorum.ntt-proof-lab.modq8380417.radix4096.serial.p3-0.8.0.v1`. It is distinct from the arithmetic, hash and private payment component profiles.

| Property | Fixed value |
|---|---|
| Original trace | 256 rows and 39051 columns |
| Coefficient and product slots per row | 256 coefficients and 128 exact multiplication gadgets |
| Stored hiding degree | Nine bits with 512 extended rows |
| Maximum symbolic constraint degree | Two |
| Public vector | 2113 base field elements |
| FRI queries and log blowup | 64 queries and 2 |
| FRI folding rounds | Nine |
| Quotient openings | Four chunks of four extension elements |
| Challenge extension | Degree 4 over BabyBear |
| Random codewords | Four |
| Merkle salts | 16 base field elements per committed row |
| Grinding difficulties | Zero bits |

Both commitment layers use the inspected hiding configuration with fresh operating system seeded private randomness. Verification samples no fresh entropy. The source enforced masking budget is $256\ge2(64+4\cdot2)=144$. These declarations do not establish independent zero knowledge, quantum knowledge soundness or complete composition security.

The three local adapter namespaces are `thorum.ntt-proof-lab.leaf.v1`, `thorum.ntt-proof-lab.node.v1` and `thorum.ntt-proof-lab.transcript.v1`, retaining full SHA3-512 outputs. Upstream fixed metadata additionally uses Keccak256 fingerprints. The [profile guard](../research/ntt-proofs/profile_check.py) checks fixed declarations and resolved dependency features.

This wide trace has distinct transport limits:

| Limit | Value |
|---|---:|
| Encoded proof bytes | 67108864, or 64 MiB |
| JSON tokens | 8000000 |
| Items per collection | 65536 |
| JSON nesting depth | 24 |
| String content bytes | 64 |
| Unsigned integer token digits | 20 |

These limits describe bounded decoding and acceptance. They are not measured peak memory, worst case execution or a denial of service bound. Earlier profiles retain their own limits. Typed decoding, fixed shape checks and exact canonical reencoding precede cryptographic verification. Shape checks fix degree, roots, trace width, quotient and masking dimensions, 64 queries, nine FRI rounds, salts and bounded Merkle paths.

## Reference evidence and remaining gates

The [independent corpus](../research/ntt-proofs/README.md) has 47 relation cases, including 31 satisfying transforms and eight additional malformed statement cases. It retains all intermediate stage arrays, 54016 butterfly and normalization records including hostile constructions, the full twiddle table, direct evaluation points and three adapter digest goldens. Each direction independently matches direct quadratic negacyclic DFT formulas. Round trips are supplementary evidence.

Basis, dense, maximum coefficient and alternating patterns exercise ordering, signs, normalization, arithmetic boundaries and both halves. Rejection constructions isolate wrong twiddles, skipped layers, wrong signs, missing or altered scale factors, false field products, ordering, mode and expected input or output. Separate diagnostics distinguish genuine local arithmetic from the global transform relation. Reference classification, actual AIR comparison and raw proof rejection are distinct verification boundaries.

| Validation boundary | Recorded result |
|---|---|
| Release suite | 12 unit tests and one external integration test pass |
| Debug suite | 11 unit tests and one external integration test pass |
| Actual proof construction | Forward and inverse proofs verify, with fresh commitments on repeated proving |
| Raw false proofs | Seven constructions bypass the local witness precheck and fail actual verification |
| Constrained wiring | 25 causal faults and four field alias cases fail their required checks |
| Expected statement binding | 52 targeted public mutations fail acceptance |
| Independent relation corpus | All 47 cases and all 2113 public field values agree with the reference |
| Valid stage and arithmetic data | 309 coefficient states and 35584 valid product, carry and flag records match |
| Proof adapter hashing | Three independent full digest goldens match |

The retained 54016 operation records include hostile constructions. The 35584 actual valid auxiliary comparisons are a distinct subset and are not a claim that every retained record describes valid arithmetic.

```text
cargo test -p thorum-ntt-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-ntt-proof-lab --release --locked --offline -- --test-threads=1
python research/ntt-proofs/reference_vectors.py --check
python research/ntt-proofs/profile_check.py
```

The public polynomials and deterministic fixtures are not secret material or entropy evidence. They do not provide signature conformance validation, an independent audit or a numerical security level. No timing, peak memory, throughput, proof size or privacy result is inferred from operation counts or an informal proof run.

The remaining authorization relation needs canonical signed decoding, strict signature norm checks, exact matrix and challenge sampling, coefficient conversion, matrix and challenge products, hints, `UseHint`, `w1` packing and full signature challenge equality. All operations must use the same private keys, signature, hashes, matrices and note ownership data, with an exact signed transaction binding. Stable nullifiers do not supply owner permission, and this transform component does not complete that connection.

Authenticated roots, global spent state, atomic persistence, recipient encryption, recovery, confidential staking and metadata testing retain their existing gates. The full server and desktop wallet plan remains dependent on those requirements.
