# Conditional private signature row

## Executable scope

The reconstructed row component proves one bounded ML DSA87 verification computation over private operands. The public statement contains a row index from zero through seven and a 64 byte opaque context. The seed, transformed response arrays, public key row, transformed challenge, hints, intermediate state and reconstructed bytes remain private.

This is a conditional relation. The component does not establish that its operands came from the same encoded key and signature. It does not establish full signature validity, hidden note ownership, canonical transaction authorization, conserved value or payment acceptance. Consistently changing a complete private operand can produce another valid component witness. Context enters the proof transcript and does not supply a canonical transaction mapping.

## Mathematical relation

Let $q=8380417$, $n=256$ and $r\in\{0,\ldots,7\}$. The witness contains a 32 byte seed $\rho$, seven canonical transformed response polynomials $\widehat z_j$, a ten bit key row $t_1$, a canonical transformed challenge $\widehat c$ and 256 Boolean hints $h$.

The component reconstructs

$$
v = \operatorname{NTT}^{-1}\!\left(
  \sum_{j=0}^{6}\widehat A_{\rho}[r,j]\circ\widehat z_j
  - \widehat c\circ\operatorname{NTT}(8192t_1)
\right)\pmod q.
$$

Here $\circ$ denotes coefficientwise multiplication in the transform representation. Sampled matrix coefficients already represent $\widehat A$ and receive no additional transform. The inverse includes multiplication by $8347681=256^{-1}\pmod q$.

Each coefficient then passes through the actual `UseHint` evaluator. Its four bit results are packed low nibble first:

$$
w_{1,i}=\operatorname{UseHint}(v_i,h_i),\qquad
b_k=w_{1,2k}+16w_{1,2k+1},\quad 0\leq k<128.
$$

All 128 bytes stay private and are retained after their final producer. A later complete authorization relation must bind them to the final challenge and the same signature, key, hidden input note and canonical transaction.

## Constrained execution

| Physical rows | Operation |
|---|---|
| 0 through 293 | Seven matrix columns with six complete SHAKE128 blocks per column and sequential products/accumulation |
| 0 through 31 | Key row loading in parallel with the matrix schedule |
| 294 through 421 | Forward transform of the actual shifted key row |
| 422 through 453 | Same index challenge product and subtraction |
| 454 through 581 | Inverse transform |
| 582 through 613 | Actual inverse normalization |
| 614 through 645 | Same index hint application and exact byte producers |
| 646 through 1023 | Retained private output and constrained padding |

Four real Keccak rounds occupy each physical hash row. Full 200 byte sponge state joins include unused capacity and output bytes. The old 1008 byte output bank remains live through the final candidate operation. A column transition requires the actual final count lane `C8` to equal 256 before the next reset. The last accumulation write survives that reset.

Six blocks provide 336 represented candidates per column. Unsupported completion within that finite class is a separate capacity outcome. It is not a claim that every standard seed completes inside the bound. The independent reference set distinguishes genuine streams, represented late completion cases and unsupported capacities.

## Fixed proof profile

The namespace is `thorum.reconstructed-row-proof-lab.mldsa87.private-row.four-rounds.serial.p3-0.8.0.v1`.

| Property | Value |
|---|---:|
| Original rows | 1024 |
| Columns | 24794 |
| Public values | 65 |
| Actual constraint degree | 3 |
| Stored degree bits | 11 |
| Quotient chunks | 8 |
| Binary FRI rounds | 11 |
| Queries | 64 |
| Log blowup | 3 |
| Extension dimension | 4 |
| Random codewords | 4 |
| Salt elements | 16 |

Both commitment layers retain hiding. Proving uses independently seeded fresh operating system generators. Leaf, node and transcript adapters retain complete SHA3 512 digests under separate fixed domains. The closed verifier bounds encoded bytes to 32 MiB, total tokens to three million, collection members to 32768 and depth to 24. It applies preflight before owned decoding, exact shape checks and byte identical canonical reencoding before backend verification.

These parameters describe an isolated laboratory component. Complete privacy, proof composition and a production post quantum security argument remain separate requirements.

Signature arithmetic uses $q=8380417$. The AIR uses the separate BabyBear prime $p=2013265921$ and a degree four challenge extension of size $p^4$, with $\log_2(p^4)\approx123.63$. This field size calculation is not a classical or quantum security level. Complete soundness, zero knowledge and knowledge soundness analysis must account for the actual AIR, openings, FRI, transcript, hiding configuration and composition. The 64 query and log blowup three settings alone do not establish that analysis.

## Independent references and validation

The [reference package](../research/reconstructed-row/README.md) computes all retained stages with Python integer and hash oracles. It includes eight complete inputs, 28 genuine matrices, full sponge states, selected rounds, every candidate event, transforms, normalization, hints, packing, false source joins and valid whole operand alternatives. Its selected continuation fault is independently reconstructed without loading a separate large streamed corpus.

The executable tests retain complete constraint and reference checks. The serial proof corpus covers fresh accepted proofs, public statement changes, a different transcript profile, canonical shape and encoding mutations, and sixteen actual raw false proofs. Each raw case bypasses the local witness precheck only in test code, passes the closed transport and shape, and must fail both backend and strict wrapper verification. Diagnostic subrelations establish their stated local mathematics and never act as verifier alternatives.

The [test inventory check](../research/reconstructed-row/check_test_inventory.py) requires the exact ignored library and external API tests before CI invokes them. The dedicated row jobs execute those tests explicitly. Default summaries containing ignored proof tests do not establish actual proof execution. Local large provers run serially under separately recorded source and resource gates.

### Explicit proof reproduction

The [dedicated workflow jobs](../.github/workflows/checks.yml) perform the inventory check before the following exact selections. Each proof command executes actual backend proving and verification. Local reproduction requires the separately recorded resource gates and serial execution with the validated toolchain and locked offline dependencies. The mathematical reference generator remains a separate Python only check.

```text
python research/reconstructed-row/check_test_inventory.py
cargo test -p thorum-hash-proof-lab --release --lib --locked --offline reconstructed_row::proof::tests::one_honest_private_reconstructed_row_proof -- --exact --ignored --nocapture --test-threads=1
cargo test -p thorum-hash-proof-lab --release --lib --locked --offline reconstructed_row::proof::tests::corpus_tests::three_fresh_private_rows_public_mutations_and_transport -- --exact --ignored --nocapture --test-threads=1
cargo test -p thorum-hash-proof-lab --release --lib --locked --offline reconstructed_row::proof::tests::corpus_tests::sixteen_raw_false_row_proofs_reject_backend_and_wrapper -- --exact --ignored --nocapture --test-threads=1
cargo test -p thorum-hash-proof-lab --release --test reconstructed_row --locked --offline conditional_row_external_api_and_separate_profiles -- --exact --ignored --nocapture --test-threads=1
```

These selections do not complete private signature verification or note ownership. The canonical reference package and its frozen records retain their original bytes.

Analytical payloads for four byte base elements are

$$
B_{\mathrm{raw}}=4HW=101556224,\qquad
B_{\mathrm{randomized}}=8H(W+4)=203145216,
$$

$$
B_{\mathrm{main\ LDE}}=64H(W+4)=1625161728\ \text{bytes}.
$$

These expressions are array payloads, not process peak bounds. The 23515989 byte maximum shape fixture is synthetic and does not form a valid proof. Component proof records and local diagnostic durations do not measure a complete signature, payment or mobile wallet.
