# Packed signature and ownership corpus

This separate integration target evaluates nine remaining independent reference tuples against the actual complete packed signature and note ownership AIR. It imports the retained source unchanged. The previously tested A0 tuple is excluded.

The intended authorization relation requires both a valid signature for the actual expected transaction and a matching owner inside the privately witnessed note. The corpus tests these conditions together. It uses actual constraint evaluation after successful construction, without a host verification callback or reference verdict as an acceptance rule.

## Selected cases

| Tuple | Verification key | Signature | Expected transaction | Note | Reference prediction |
| --- | --- | --- | --- | --- | --- |
| A1 | A | A1 | T1 | N_A | Accept |
| B0 | B | B0 | T0 | N_B | Accept |
| B1 | B | B1 | T1 | N_B | Accept |
| A0_empty_context | A | A0_empty_context | T0 | N_A | Reject |
| A0_wrong_context41 | A | A0_wrong_context41 | T0 | N_A | Reject |
| A0_same_owner_alternate_note | A | A0 | T0 | N_A_alt | Accept |
| A0_wrong_owner_note | A | A0 | T0 | N_B | Reject |
| A0_wrong_verification_key | B | A0 | T0 | N_B | Reject |
| A1_wrong_expected_transaction | A | A1 | T0 | N_A | Reject |

The same owner alternative is a distinct positive note witness. The wrong owner case rebuilds its note sources consistently. A rejection caused only by broken source holds or port encoding would not establish the intended ownership check.

The message representative MU depends on the actual verification key and expected transaction. Its reference therefore follows that pair. It does not follow the signature's original transaction when that transaction is deliberately mismatched. Final challenge references additionally depend on signature operands. The two cross key or transaction cases have no corresponding independent final challenge golden, so that direct comparison is omitted for them.

The connected hash obligations can be written as

$$\mu(pk,T)=H_{\mu}\bigl(\operatorname{TR}(pk)\,\|\,M_{\mathrm{ctx}}(T)\bigr),\qquad
\operatorname{Owner}(n)=H_{\mathrm{owner}}(pk).$$

The received signature challenge must also match

$$c_{\mathrm{received}}=H_{\mathrm{challenge}}\bigl(\mu(pk,T)\,\|\,\operatorname{Encode}(W_1(pk,\sigma))\bigr).$$

Here the hash names include the retained framing and domain rules. The matrix, transform and hint equations determine W1 from the same private source inputs. It is not a free verification operand. The corpus evaluates these connected constraints rather than passing in an accepted signature verdict.

## Finite checks

The harness selects nine constructions and nine actual native scans, with at most one live trace. Four scans are expected to accept every row. The five negatives stop after the first failure bearing row. Each observed verdict is synchronized before its reference prediction is interpreted. Constructor or parser refusal is a test failure rather than native rejection.

All cases compare the exact canonical transaction and 196 authorization fields. Four direct byte checks per case cover RHO, key derived owner, MU and note commitment. Seven cases also compare a valid independent final challenge golden. This gives 43 byte comparisons covering 2,464 bytes. This is separate from the complete constraint evaluation and does not compare every transform coefficient independently.

Wrong ownership is expected to reach row 234 and the owner equality range. The context, key and transaction failures are expected to reach the final challenge range at row 5,369. Cross key and transaction cases require a nonempty failure set in that range, without inventing an exact first byte or mismatch count.

## Implementation status

The actual guarded corpus passed once on Windows 11 with a Core i9-13900H and Rust 1.94.1. All nine traces were constructed and evaluated serially. Four valid cases passed every row. Five invalid cases failed at the intended owner or final challenge constraints. The same owner alternate note passed, while the consistently rebuilt wrong owner note failed at row 234. All five rejected cases reached the real constraints after successful construction.

| Actual result | Record |
| --- | ---: |
| Constructed and evaluated traces | 9 |
| Maximum live traces | 1 |
| Accepted complete scans | 4 |
| Rejected first failure scans | 5 |
| Independent byte comparisons | 43 |
| Independently compared bytes | 2,464 |
| Rows inferred from the checker | 54,483 |
| Peak process commit bytes | 1,419,747,328 |
| Peak aggregate commit bytes | 1,421,107,200 |
| Backend proofs | 0 |

The observed test duration was 303.35 seconds for the complete serial corpus. This includes construction, independent comparisons and constraint evaluation. It is not payment latency or proof generation time. Negative scans stop after their first failure bearing row. The row sum follows those observed positions and the pinned checker behavior, rather than treating the reported trace height as a negative scan length.

The guard installed and read back 2 GiB process and aggregate commit limits before resuming the child. It required at least 5 GiB freshly available memory and enforced the separately selected 1,200 second corpus deadline. No timeout or guard termination occurred. Actual observations and resource metadata are retained in fixtures-observations.jsonl and validation.json. All executed source, fixture, dependency and executable identities matched after the run.

Release compilation and strict selected lint checks also pass. CI compiles this ignored target and checks the retained evidence without automatically repeating the large corpus. Fresh execution requires a separate finite resource admission.

Native constraint checks remain distinct from hiding proofs, payment validation, membership, unspent state and network capabilities. A valid owner relation does not establish that a note is eligible to spend in the ledger. The complete private payment joins and security composition remain separate work.

## Derivation

Bounded typed fixture reading, canonical transaction construction and direct byte comparisons derive from research/signature-packed-native/tests/native.rs at revision a3f63b2d76539cbb5ce21bd171da937804ec8d57. The unchanged raw and reference fixtures retain their original provenance. The corpus imports the actual relation and does not execute the prior suite. Original notices and attribution remain applicable. Project source uses the repository MIT license, copied unchanged here. Registry identities remain pinned in Cargo.lock.

## Reproduction

```text
python research/signature-packed-corpus/static_check.py
cargo fetch --manifest-path research/signature-packed-corpus/Cargo.toml --locked
cargo fmt --manifest-path research/signature-packed-corpus/Cargo.toml --all -- --check
cargo test --manifest-path research/signature-packed-corpus/Cargo.toml --release --locked --offline --test corpus --no-run --jobs 1
cargo clippy --manifest-path research/signature-packed-corpus/Cargo.toml --release --test corpus --locked --offline -- -D warnings
```

After separate resource admission, set `KOVA_PACKED_CORPUS_GATE=reviewed-external-resource-admission` and select only:

```text
cargo test --manifest-path research/signature-packed-corpus/Cargo.toml --release --locked --offline --test corpus --jobs 1 -- --ignored --exact remaining_nine_packed_native_tuples --test-threads=1
python research/signature-packed-corpus/static_check.py --check-results
```

The static checker verifies source identities and saved observations against independently derived expectations without executing the AIR. The optional `--registry-root` argument also checks actual retained Cargo registry sources. The copied Windows guard can enforce the recorded limits around the exact executable. Result files are exclusive and preserve existing evidence.
