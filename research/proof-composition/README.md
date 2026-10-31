# Complete proof resource and security composition

The current packed authorization relation has 8,192 rows, 43,176 columns, 69,242 constraints per row and 196 public values. Its native constraints have been exercised under their recorded scope. A complete hiding proof for that relation remains an integration milestone.

This analysis connects the [packed relation](../signature-packed-native/README.md), [source prover](../source-prover/README.md) and [resource preflight](../proof-preflight/README.md). The [saved projection](projection.json) uses bounded integer arithmetic over existing records. It constructs no trace, field object or proof. The comparison profile is the retained small quartic experiment, with four extension coordinates, four random columns, blowup eight, eight quotient chunks and 64 queries. These are experimental settings, not selected chain security parameters.

## Complete source payload

Let $H$ be the raw height, $W$ its width, $r=4$ random columns, $e=4$ extension degree, $c=8$ quotient chunks, $s=4$ field bytes and $L=16H$ committed rows. Retaining all source roles gives

$$
\begin{aligned}
F_{\mathrm{raw}}&=sHW, & F_{\mathrm{prepared}}&=2sH(W+r),\\
F_{\mathrm{main}}&=sL(W+r), & F_{\mathrm{quotient}}&=csL(e+r),\\
F_{\mathrm{auxiliary}}&=sL(e+r), & F_{\mathrm{canonical}}&=8Hes.
\end{aligned}
$$

The source owner retains thirteen field roles: raw, prepared and main, eight quotient chunks, auxiliary and canonical quotient source. Their total is the sum of these six payload classes.

| Field contents | Completed small source class | Conditional packed relation |
|---|---:|---:|
| Raw source | 2,048 | 1,414,791,168 |
| Prepared source | 12,288 | 2,829,844,480 |
| Main LDE | 98,304 | 22,638,755,840 |
| Eight quotient LDEs | 1,048,576 | 33,554,432 |
| Auxiliary LDE | 131,072 | 4,194,304 |
| Canonical quotient source | 32,768 | 1,048,576 |
| Total field bytes | 1,325,056 | 26,922,188,800 |

The small total matches the actual source owner reservation. Removing raw and canonical roles reproduces the earlier independent storage record's 1,290,240 bytes. Six literal small role quantities provide an additional inventory comparison. The packed projection is conditional arithmetic. No files of those dimensions were created.

## Commitment and transport boundaries

Ten committed matrices use sixteen salt fields per row. Main, quotient batch and auxiliary commitments retain three binary digest trees with 64 byte digests. Their content sizes are

$$
S_{\mathrm{salt}}=10L\cdot16s,\qquad
S_{\mathrm{digest}}=3(2L-1)\cdot64.
$$

For the packed projection these are 83,886,080 and 50,331,456 bytes respectively, before allocator overhead and FRI. These contents are separate from field files and are not added into a claimed simultaneous memory peak.

At 64 distinct main query indices, canonical main row values contain $64(W+r)s=11,054,080$ bytes. Two extension claims per main column contain $2(W+r)es=1,381,760$ bytes. Query deduplication and serialization change actual transport. These figures exclude salts, sibling digests, quotient and auxiliary rows, FRI and framing. They are neither serialized proof sizes nor lower bounds for every possible query sample.

The current class refuses raw width above eight, stored dimensions above 4,096 by twelve, field contents above 2 MiB and public value shapes above eight. The packed relation exceeds all four. Streaming column construction preserves the field contents and does not by itself resolve these limits. The source view, quotient kernel and nominal context also retain explicit small shape requirements.

## Security obligations

For the current extension field, exact cardinality satisfies

$$
|\mathbb F_{p^4}|=p^4,\qquad p=2013265921,\qquad
2^{123}<p^4<2^{124}.
$$

Cardinality describes the challenge space. It does not establish achieved soundness, a protocol attack bound or a complete post quantum security level. Constraint folding, opening combination, proximity regimes and repeated observations introduce separate error terms. Increasing hash output width does not establish those terms.

The retained masking check requires $r\geq e$ and $N_m\geq2(q+eo)$. An extension eight experiment cannot keep four random columns. Its masks, domains, salts, commitment interfaces, transport and theorem applicability require a new coherent analysis before selecting a profile. This projection selects no replacement profile.

| Composition boundary | Required evidence |
|---|---|
| Constraint and opening batching | Exact instance shape, degree, challenge distribution and applicable error terms |
| Low degree testing | Concrete query and fold schedule, proximity assumptions and complete error composition |
| Hiding | Joint mask and salt exposure, single opening lifetime and repeated observation analysis |
| Fiat Shamir and knowledge | Applicability to the actual multiround transcript and required quantum extraction model |
| Hash and authorization assumptions | Explicit constructions, adversary budgets and primitive specific analysis |
| Private payment relation | Same hidden witnesses across membership, owner permission, authorization, nullifier, value, policy and delivery |

The pinned security dependency decomposes AIR, DEEP, low degree testing, batching and collision terms. Selecting valid inputs and proving applicability remain protocol responsibilities. No security score from that dependency was computed here. [ethSTARK Documentation](https://eprint.iacr.org/2021/582) supplies construction background. [STARK based signatures from the RPO permutation](https://eprint.iacr.org/2024/1553) concerns its own construction and assumptions. [Quantum Fiat Shamir research](https://eprint.iacr.org/2019/190) addresses three round protocols. These references do not establish applicability to Kova's complete multiround construction.

A single authorization relation is not a multi input payment cost. Independent proof acceptance cannot replace constrained shared hidden witnesses and atomic ledger consumption. The existing ML-DSA authorization baseline, hidden inputs, stable nullifiers and private payment target remain unchanged.

## Recorded execution and next construction boundary

One isolated Python 3.14.5 run completed on 1 November 2026. It matched both prior small records, compared six small role quantities and rejected four malformed dimension cases. No prior native test or model was imported or replayed. The unchanged external guard enforced 512 MiB process and aggregate job limits, 2 GiB freshly available memory and a 120 second deadline. Peak process and job commit were 10,125,312 and 11,431,936 bytes. The [validation](validation.json) binds exact source and output identities.

The next construction review must account for row hashing, salt and tree ownership, query gathering and transform buffer overlap together. A verifier compatible bounded construction or a genuinely narrower connected relation needs concrete source and adversarial evidence before any larger class. No wide proof follows from this projection.

```sh
python -I -S research/proof-composition/static_check.py
```

This command checks saved identities and evidence without importing the model. A separately admitted fresh run uses the [unchanged Windows guard](run_guarded_windows.ps1), isolated Python with `-I -S`, the fixed [model](model.py) and a fresh output location. Existing outputs cannot be overwritten. The model accepts no parameter override.
