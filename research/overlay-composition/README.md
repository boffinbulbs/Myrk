# Complete overlay resource composition

This inventory connects the [measured signature overlay](../signature-overlay/README.md) to the current owned source and commitment construction. It executes scalar arithmetic against saved evidence. It constructs no field values, witness, commitment or proof. The full signature remains outside the admitted execution classes.

## Statement and comparison parameters

The retained relation has height $H=8192$, width $W=42178$, 196 public values and 71,623 assertions of degree four. The experimental comparator uses extension degree $e=4$, random columns $r=4$, 64 queries, blowup eight, binary folding and 16 base field salt columns. These are research parameters. They are not selected chain security parameters. The [complete instance and security record](instance-security.md) traces the actual nominal owners, verifier checks, challenge order, claim incidence and unresolved theorem obligations.

Let $W_p=W+r$ and $L=16H$. Actual preparation writes $W$ input fields followed by $W+2r$ sampled fields for each source row, then reinterprets the flat sequence at width $W_p$. Thus prepared height is $2H$. The current tiled transform consumes that actual prepared order.

## Retained contents

For four byte base fields, the thirteen source roles have the following conditional contents. Eight quotient matrices occupy eight separate roles.

| Role | Bytes | Overlay result |
|---|---|---:|
| Raw source | $4HW$ | 1,382,088,704 |
| Prepared source | $8HW_p$ | 2,764,439,552 |
| Main LDE | $4LW_p$ | 22,115,516,416 |
| Eight quotient LDEs | $8\cdot4L(e+r)$ | 33,554,432 |
| Auxiliary LDE | $4L(e+r)$ | 4,194,304 |
| Canonical quotient source | $8He\cdot4$ | 1,048,576 |
| Total | | **26,300,841,984** |

These are projected field file contents, not allocated wide matrices or a measured memory peak. Streaming raw ingestion does not remove the retained main LDE. The [earlier packed inventory](../proof-composition/README.md) remains an unchanged record of its different relation.

Three base commitment trees retain salt contents $10L\cdot16\cdot4=83,886,080$ bytes and digest contents $3(2L-1)\cdot64=50,331,456$ bytes. The quotient tree commits eight matrices in one batch. It does not become eight separate digest trees.

With binary folding to height eight, the FRI tree heights are $L/2,L/4,\ldots,8$. There are 14 rounds, with total leaf height $L-8$. Two extension columns flatten to eight base columns before salt is added.

| Retained FRI contents | Formula | Bytes |
|---|---|---:|
| Field matrices | $32(L-8)$ | 4,194,048 |
| Salt matrices | $64(L-8)$ | 8,388,096 |
| Digest layers | $64(2(L-8)-14)$ | 16,775,296 |

Actual prover code retains all FRI commitment data through query generation, while borrowing the original input commitments. These retained contents overlap in that phase. File contents, resident salt and digest vectors, temporary allocations and operating system caching remain different quantities.

## Construction lifetimes

| Phase | Source ownership and live work | Remaining accounting |
|---|---|---|
| Raw ingestion | Checked fields enter the canonical owner only after metadata and exclusive output admission | Iterator, bounded reader and write buffering |
| Preparation | Original accepted random fields enter the actual flat prepared order | Rejection sampling and writer buffering |
| Main transform | A four column tile moves into the DFT and grows from 262,144 to 2,097,152 payload bytes | Reallocation transient, twiddle caches and allocator overhead |
| Main commitment | Same owner stored rows feed actual salted leaf hashing and retained MMCS | Full row access, salt matrix, digest tree and descriptor lifetimes |
| Quotient construction | Actual committed data feed the original AIR folder, normalized selectors and sealed output | Layout discovery, packed constraints and source buffers |
| Coupled commitment | Eight quotient outputs and their coupled masks retain the original domain order | Random banks, transforms and all committed output ownership |
| Opening and FRI | Private flags are consumed once, original claims are transcript bound, all folding trees remain live for queries | Compression vectors, denominators, gathered rows and authentication paths |
| Proof and transport | Actual proof construction precedes the owner's completion state | Codec, untrusted parsing, serialization and network admission |

The transform grows the moved vector. Its input and output are not two independently retained matrices. This does not establish that allocator growth has no temporary overlap. Four base field selector arrays contain 1,048,576 bytes in the conditional quotient domain and expire before the later FRI query phase. Their size is not an additional permanent tree allocation. Layout discovery and allocation metadata are not included in these payload equations.

The inventory's `quotient_mask_bank_bytes` entry counts the seven independently sampled banks, $7H(e+r)\cdot4=1,835,008$ bytes. The actual coupled allocation also includes an eighth bank, initially zero and then derived from the others. Its complete mask vector contains $8H(e+r)\cdot4=2,097,152$ bytes. Accepted entropy, complete allocated mask storage and retained quotient LDEs are separate quantities.

## Query and entropy boundaries

The current pruned Merkle opener removes redundant authentication siblings. It still gathers a row for each of the 64 supplied queries, preserving duplicate indices. Main query data therefore contain $64W_p\cdot4=10,798,592$ field bytes in this implementation. The two main opening points add $2W_pe\cdot4=1,349,824$ claim bytes. Claims for random codeword columns are moved into the proof tuple rather than discarded. All main, quotient and auxiliary claims total 1,350,976 field bytes. Salt, FRI siblings, authentication paths, commitments, framing and public data remain separate.

These quantities describe field contents. They are not serialized proof size. The previous complete small proof encoded 596,650 JSON bytes. Its dimensions do not establish wide transport feasibility. `ResourcePlan.declared_serialized_proof_cap` declares two MiB, while the retained diagnostic writer bounds its own output. The subsequent [typed decoder](../proof-transport/README.md) and [header admitted reader](../frame-reader/README.md) enforce their own fixed small proof resource boundaries. They do not verify a payment statement or supply production network deadlines and peer admission.

Accepted random fields are also different from delivered RNG bytes. The main, quotient and auxiliary constructions consume respectively $H(W+8)$, $88H$ and $16H$ accepted base fields. Rejection sampling can require additional draws. Saved small records satisfy those lower bounds. Observer forks create separate journals, so the old parent salt byte counter does not cover every FRI child stream. No total delivered wide RNG byte count is claimed.

## Independent evidence and execution limits

The [whole Keccak integer reference](../keccak-fixed-reference/README.md) evaluates the separate fixed wiring relation against complete primary state vectors and integer column equations. It preserves the refusal of direct graph materialization and does not supply a new proof class.

The fresh inventory agrees with the independently saved small owner reservation of 13 roles and 1,325,056 bytes. Its main only subtotal matches 112,640 bytes, 24,576 returned main fields and 360,448 actual leaf preimage bytes. The complete small proof's nine FRI commitments agree with the separate geometric count. No producer of those records was repeated.

Eight malformed scalar cases reject. The sole isolated integer evaluation passed under a 512 MiB process and aggregate job limit, a fresh two GiB availability requirement and a 120 second deadline. [Validation](validation.json) retains the result and exact source identities. This small evaluator's peak is unrelated to wide proving feasibility.

Current preflight refuses raw width above eight before symbolic collection. Stored shape, field file budget and public shape are separate checks. The quotient kernel also bounds width, domain rows and public values before layout discovery, then checks its constraint count. Its later count check does not bound arbitrary symbolic layout construction. Current Context, main commitment and quotient entry points are monomorphic small relation adapters. Raising one numeric limit would not supply complete integration.

## Security and private ledger obligations

The [authorization construction boundary](authorization-construction.md) identifies why scheduling unchanged hash gadgets cannot fit the current class and specifies the private equalities needed to join signature ownership to membership, stable nullifiers and the complete payment relation. It selects no new prover or execution class.

The [two phase wire binding contract](two-phase-wire-binding.md) gives prospective local producer/read placement and exact copy-product equations. It identifies the missing second commitment phase in the actual prover and verifier, and refuses the proposed placement under current limits. Its conditional algebra does not supply a complete private authorization proof.

The [common private witness contract](private-witness-join.md) binds the same note, owner key, real signature, nullifier secret and path across the ordinary v2 payment obligations. Its exact confidential asset equations and output encryption boundary expose the remaining joint-proof construction requirements. It supplies no accepting payment route.

The [encrypted output construction boundary](encrypted-output-boundary.md) traces the actual KEM, sampler, KDF and GCM operations and fixes their same-opening association. It identifies the missing finite sampling and cipher correspondence required before a complete private encryption proof can be selected.

The [whole GCM software word relation](gcm-word-relation.md) gives the exact portable key, payload and tag relation and both conditional source-correspondence directions. It retains the hardware, constrained-copy, combined proving-resource and complete payment gates.

The [whole GCM integer reference](../gcm-word-reference/README.md) checks that relation against six independently retained complete records and a full public synthetic output instance. Its bounded integer results do not supply the complete private encryption proof or reduce the remaining combined proving geometry.

The [whole encrypted output completion relation](whole-encryption-completion.md) joins the same opening through canonical KEM, actual modular arithmetic, KDF and complete GCM. It proves both conditional semantic directions, separates successful termination from completeness on every canonical key and refuses its explicit selector representation under current limits. Its finite-state bound is mathematical and impractical, with no new program or proving class.

| Boundary | Required evidence |
|---|---|
| Algebraic soundness | Actual batching multiplicities, DEEP and proximity errors, domains and folding schedule |
| Hiding | Joint mask and salt exposure across claims, queries and repeated observations |
| Transcript | Actual multiround Fiat Shamir binding, classical knowledge and quantum theorem applicability |
| Transport | Framing, canonical decoding, allocation and aggregate input limits before parsing |
| Ownership | Same private note, verification key, signature, membership and stable nullifier witness |
| Ledger | Spent state, conservation, policy, encrypted delivery and atomic authenticated consumption |

Field cardinality is not an achieved security score. The full signature has no hiding proof in this inventory. Component acceptance cannot replace the same witness payment relation. Payments remain private by default in the protocol requirements. The [complete roadmap](../../docs/delivery-roadmap.md) retains consensus, confidential staking, mining, governance, service and viewing interfaces, wallets, contracts, Safe, migration and later Aegis.

## Reproduction

```text
python -I -S research/overlay-composition/static_check.py
```

This command checks saved identities and results without importing the model. To reproduce the integer evaluation, use a fresh isolated copy, remove only its generated inventory, review exact source identities and apply explicit resource limits before running `python -I -S model.py`. The Windows guard creates exclusive attempt outputs. It never overwrites a previous attempt. No wide prover is selected by these commands.
