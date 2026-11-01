# Complete proof instance and security obligations

This source review connects the complete signature overlay to the retained owned prover, verifier and transcript. It identifies the construction and security obligations that remain before a private payment proof can be selected. It computes no security score and admits no larger proving class.

The reviewed repository baseline is `34e9081ae763fc612ddbbc2bc821159f1bf7336a`. Dependency source references below concern the exact Plonky3 `0.8.0` packages in the [retained lockfile](../fallible-source/Cargo.lock). The [overlay inventory](README.md), [symbolic overlay record](../signature-overlay/README.md) and [streamed witness validation](../signature-overlay-native/README.md) provide their separate recorded evidence. The earlier [complete small proof](../source-prover/README.md) is snapshot evidence for a different relation. Later fallible input and main commitment tests did not repeat that complete proof.

## Nominal source and acceptance boundaries

| Boundary | Actual source | Construction and verifier responsibility |
|---|---|---|
| Owned input and context | [context](../fallible-source/src/context.rs), [source](../fallible-source/src/source.rs), [extension](../fallible-source/src/extension.rs) | `Context::try_prove` forwards real fallible fields. Raw failure precedes `begin_attempt` and proving transcript initialization. This context is fixed to the small relation. |
| Composite lifetime | [composite owner](../fallible-source/src/composite.rs) | Raw identity, phase transitions, reservations, leases and first failure are checked by the current nominal owner. `Step` and attempt destruction close actual failed work. |
| Original commitment calls | [owned PCS](../fallible-source/src/owned_pcs.rs), [current hiding adapter](../fallible-source/src/hiding_pcs.rs) | Main, quotient and auxiliary inputs reach original owned storage and actual retained MMCS commitments. A supplied root is not an input to this construction. |
| Complete small prover | [owned prover](../fallible-source/src/owned_prover.rs) | The relation is `QuarticAir`, with public values `[5, 260]` and no preprocessing. Real `Proof` assembly precedes `finish_produced`. Successful compilation of this route is distinct from execution of the earlier snapshot. |
| Original verifier | `p3-uni-stark/src/verifier.rs` | `verify_with_preprocessed` derives widths, public count and quotient structure from the verifier's AIR, configuration and checked degree. `prepare_opening_claims` derives the opening domains and points. `verify_constraints` checks the folded AIR equality at the sampled point. |
| Hiding PCS | [retained hiding implementation](../storage-pcs/backend/src/hiding_pcs.rs) | The verifier validates random opening nesting and widths, then rejoins them to the public claims before inner verification. The prover checks metadata and hiding budgets before consuming private opening flags. |
| Opening combination and FRI | [two adic PCS](../storage-pcs/backend/src/two_adic_pcs.rs), [FRI verifier](../storage-pcs/backend/src/verifier.rs) | Claimed values precede the opening combination challenge. Actual input MMCS paths authenticate rows with the derived dimensions. Reduction, authenticated folds and the final polynomial equality are separate checks. |
| Typed transport | [proof transport](../proof-transport/README.md), [frame reader](../frame-reader/README.md) | Resource admission, owned typed decoding, fixed shape and canonical encoding do not execute cryptographic verification. The reader does not supply network deadlines or peer policy. |

The generic uni-STARK verifier accepts a proof supplied degree only after checking the PCS degree bounds. It is not itself an application policy fixing one particular height. A future payment verifier must own the exact AIR, allowed height, expected public statement and protocol context. `StarkShape` binds shape, not the constraint polynomials themselves. Shape labels do not replace selecting the correct AIR.

## Instance incidence

Let $H$ denote raw trace height, $W$ main width, $e$ extension degree, $r$ random columns and $q$ query count. The retained comparison has $e=r=4$, $q=64$, blowup eight, binary folding and constant final polynomial. These are experimental parameters, not chain security parameters.

| Quantity | Completed small proof snapshot | Conditional complete overlay | Source of meaning |
|---|---:|---:|---|
| Raw height $H$ | 256 | 8,192 | Actual AIR and source constructor |
| Main width $W$ | 2 | 42,178 | Verifier AIR width |
| Public values | 2 | 196 | Verifier AIR public count and expected statement |
| Assertions per row | 4 | 71,623 | Original `QuarticAir` assertions and saved overlay record |
| Maximum assertion degree | 4 | 4 | Saved symbolic records, including selectors |
| Prepared domain height | 512 | 16,384 | Original hiding extension, $2H$ |
| Main stored width $W+r$ | 6 | 42,182 | Actual random column append |
| Quotient evaluation domain | 2,048 | 65,536 | $8H$, after quotient sizing and ZK adjustment |
| Quotient chunks | 8 | 8 | Degree sizing, original split and coupled masking |
| Canonical chunk height | 256 | 8,192 | Quotient domain split into eight cosets |
| Masked chunk domain height | 512 | 16,384 | Original chunk randomization |
| Each committed LDE height $L$ | 4,096 | 131,072 | Prepared height times blowup, $L=16H$ |
| FRI committed rounds | 9 | 14 | Binary folds from $L$ to eight |
| Final polynomial coefficients | 1 | 1 | `log_final_poly_len = 0` |
| Query index bits | 12 | 17 | Logarithm of maximum LDE height |

The overlay column is a source projection under the same comparison settings. Current main, quotient and context adapters cannot construct that instance. No full overlay verifier or proof execution is established by this table.

The underlying two adic natural domain has shift one. The main LDE uses the generator coset and physical bit reversed row order. Quotient evaluation uses the disjoint domain selected by the original domain operations. Chunk domains preserve their split order and normalized vanishing polynomials. Recomposition in `recompose_quotient_from_chunks` uses those domains, including the normalization factors. An implementation must preserve these concrete domain operations rather than substitute a polynomial with the same roots but different normalization.

For the comparison degree four relation, the base quotient evaluation domain has height $8H$. Each unmasked chunk has height $H$, and its hiding domain has height $2H$. The resulting PCS functions have degree less than $2H$ before their opening reduction. This is an instance degree description, not a proximity or soundness bound.

The actual opening order is auxiliary, main, quotient. The auxiliary batch has one matrix of width $e+r$ at one point. The main batch has one matrix of width $W+r$ at two points. The quotient batch has eight matrices of width $e+r$, each at one point. There is no preprocessed batch in this relation.

$$
N_{\mathrm{pairs}}=(e+r)+2(W+r)+8(e+r)=2(W+r)+9(e+r).
$$

This gives **84** small and **84,436** conditional overlay function and point pairs. There are eleven point occurrences across the ten matrices, not 84,436 independent challenge points. The values use $\zeta$ and, for main next row claims, $\zeta g_H$. PCS combination powers advance over the actual ordered widths and points. A security analysis that supplies only the query count omits this batching incidence.

## Transcript and challenge order

There is one evolving original challenger. Each nested protocol seeds its own description into that same borrowed state. The source does not reset to a diagnostic prefix or join separately accepted proofs.

| Challenge | Information already absorbed | Consumer and verifier check |
|---|---|---|
| Constraint combination $\alpha_{\mathrm{AIR}}$ | Uni-STARK description, main root and public values. A preprocessing root would also precede it if declared. | Original quotient folder and verifier `verify_constraints` use the same challenge and assertion order. |
| Out of domain point $\zeta$ | Previous state, quotient root and auxiliary root. The optional OOD grinding step is absent at difficulty zero. | `prepare_opening_claims` rejects a point in the original trace domain, derives the next point and constructs claims. AIR and quotient equality are checked after PCS verification. |
| PCS combination $\alpha_{\mathrm{PCS}}$ | PCS description and every full extension claim, including the random column claims restored from the proof tuple. | `PcsShape`, the reduction exponent offsets and input authentication establish the concrete combined opening problem. |
| Each FRI folding challenge $\beta_i$ | FRI description, all preceding state and the current folded matrix commitment. | `verify_fri` and `fold_query` authenticate each current matrix, apply the scheduled fold and combine reductions at their correct heights. |
| Query indices | All folding roots and challenges, followed by the final polynomial coefficients. | The verifier derives the indices from the challenger. Input rows, FRI siblings, authentication proofs and final polynomial equality are checked at those indices. |

The same `alpha` identifier appears at different layers in source. The table distinguishes its two protocol roles. Prover [PCS transcript](../storage-pcs/backend/src/pcs_transcript.rs) and [FRI transcript](../storage-pcs/backend/src/transcript.rs) schedule their own messages, challenges, nested brackets and completion. Verifier transcripts replay those schedules. The [FRI driver](../storage-pcs/backend/src/prover.rs) retains real commitment data until query generation.

| Protocol description | Bound instance data |
|---|---|
| `p3-uni-stark`, version 1 | Trace heights, main and preprocessing widths, public and periodic counts, quotient chunk count, next row flags, randomization presence, OOD grinding and interaction pattern |
| `p3-fri-pcs`, version 1 | Commitment grouping, matrix grouping, point grouping, claimed width at each point, batch grinding and interaction pattern |
| `p3-fri`, version 1 | Ordered fold arities, blowup, maximum arity, final coefficient count, query count, index width, commit and query grinding, and interaction pattern |

All retained grinding difficulties are zero: OOD, lookup, PCS batch, each FRI commit and FRI query. Zero difficulty supplies no grinding credit. Canonical witness checks reject nonzero unused proof witnesses. The fixed owned context has no lookup argument. The [actual profile check](../fallible-source/src/hiding_pcs.rs) refuses changes to its retained PCS settings.

`p3-challenger/src/fs/domain_separator.rs` encodes a 64 byte protocol identifier, a 32 byte pattern fingerprint, length delimited instance labels and a domain tag. `fs/pattern/sequence.rs` computes that fingerprint with Keccak256. The same shape cannot identify a different AIR, network or payment policy. Future application domain binding is an additional obligation.

The [experimental hash setup](../storage-pcs/tests/common/hash.rs) uses SHA3-512 for leaf, node and transcript hashing, with separate length prefixed domains `kova.storage-pcs.leaf.v1`, `kova.storage-pcs.node.v1` and `kova.storage-pcs.transcript.v1`. Leaf fields use canonical little endian `u32`, nodes use little endian `u64`, and each hash appends its item count in big endian. Digests contain eight `u64` words. The [diagnostic setup](../fallible-source/src/diagnostics_setup.rs) uses `kova.storage-pcs.quartic.v1` as its initial context and a 64 byte `HashChallenger` output. Its public deterministic seeds are synthetic test inputs.

`SerializingChallenger32` observes canonical base fields as little endian words and samples extension coordinates through masked rejection sampling below the base modulus. Query bits come from masked bytes with an explicit field order bound. `FieldToFieldCodec` forwards the actual field challenger operations. Its canonical wire encoding and the JSON field representation are different interfaces. A codec constant named `SECURITY_BITS` does not prove overall protocol security. Hash state reuse, pattern hashing, extension encoding and all nested challenges require a concrete random oracle reduction.

## Shape checks and authenticated data

The verifier does not accept the PCS transcript's comments as a trust boundary. The actual chain is:

1. `verify_with_preprocessed` checks degree bounds, expected public length, trace local and next widths, quotient count and extension widths, randomization presence and unused grinding witnesses. Preprocessing requires consistency with verifier key metadata.
2. `prepare_opening_claims` constructs domains and point locations from the checked degree, verifier AIR and sampled point. It rejects an OOD point inside the original trace domain.
3. `verify_with_preprocessing` checks all random claim nesting and widths before appending them. The combined values enter `PcsVerifierTranscript` before the PCS challenge.
4. `verify_fri` derives the height schedule from claims and configuration. It checks round counts, query counts, sibling arities, final polynomial length and grinding fields.
5. `open_inputs` checks batch and matrix counts, derives dimensions and calls the actual input MMCS verifier. It then checks opening denominators and row to claim widths before combining authenticated row values with claims.
6. FRI authentication and fold equality connect those reductions to the final polynomial. Uni-STARK quotient recomposition and the actual AIR identity finish the relation check.

The standalone PCS API receives its commitment claims from its caller. It does not know payment policy. Conversely, typed proof decoding establishes neither this chain nor its public statement. No vulnerability or complete security theorem follows from examining a count comment in isolation.

## Hiding and ownership lifetime

The original check requires

$$
r\ge e,\qquad N_m\ge2(q+e\max(o,1)),
$$

where $N_m$ is the applicable mask height and $o$ that matrix's opening point count. For main $o=2$ and for quotient and auxiliary $o=1$. Extension eight with four random columns fails the first condition. No replacement profile is selected.

| Lifetime | Actual boundary | Remaining security obligation |
|---|---|---|
| Raw and prepared data | Original owner and exact field order. Preparation writes $W$ raw fields followed by $W+2r$ sampled fields, then reinterprets at width $W+r$. | Relate actual masks to the full hidden witness and its constraints. |
| Main and quotient | Actual same owner stored data feed MMCS and quotient construction. Coupled quotient masks include the derived eighth bank. | Joint distribution of main, quotient and auxiliary disclosures. |
| Private opening | Configuration, metadata and budget preflight precede atomic flag consumption. Clones share `Arc<AtomicBool>`. Two valid requests sharing authority encounter the real already opened guard. | This protects one committed private instance from repeated disclosure. Fresh commitments still require analysis across proofs about the same witness. |
| Queries and claims | Random column OOD values move into the proof tuple. Salt fields enter leaf hashes and authenticated query data. Duplicate query rows remain in gathered contents. | Claims removed from public vectors are not secret from the proof recipient. Analyze all claims, salts and queries jointly. |
| Proof completion | A complete original transcript finishes and the actual `Proof` value is assembled before `ProofProduced`. | Native witness checks, terminal main prefixes and decoding do not establish proof validity or extractability. |

The [latest composite owner](../fallible-source/src/composite.rs) preserves the writer busy claim correction and first failure. Original private opening flags remain in the retained hiding implementation. Prover data cloning can copy salt matrices and digest vectors while sharing stored ownership and opening authority. Such clones are not a free memory or privacy reset.

Base and FRI commitment salts use separate RNG lifetimes. Observers create child streams. A parent journal does not measure every child's delivered entropy. Neither byte counters nor the inequality above establish a simulator for the complete proof distribution.

## Security terms and primary references

The pinned `p3-security` implementation exposes AIR, DEEP, batching, proximity, grinding and collision terms. Its regime objects require caller supplied instance data and assumptions. No calculator is imported or executed here. In particular, `FriParameters::conjectured_soundness_bits` is a conjectural query expression, not a complete bound.

| Obligation | Required model and source correspondence | Status for the complete overlay |
|---|---|---|
| Constraint batching and DEEP | Actual assertion count and degree, quotient split, list size and challenge distribution. `p3-security/src/air.rs` and `deep.rs` implement different terms. | Source incidence recorded. Complete theorem correspondence and conservative error composition unresolved. |
| PCS combination | All function and point pairs, their heights and exponent ranges, with actual claims bound before sampling. | 84 and 84,436 are distinct instances. Applicable proximity gap bound and adversary budget unresolved. |
| FRI proximity | Exact code rate, domains, arities, final polynomial, list decoding regime and query dependence. | Schedule recorded. No selected proven or conjectural chain regime. |
| Hiding MMCS and masks | Joint disclosures, fresh randomness, salts, single opening authority and repeated proofs. | Mechanical checks exist. Full simulator and repeated observation guarantee unresolved. |
| Hash binding | Actual SHA3-512 leaf, node and challenger construction plus Keccak256 pattern fingerprint and encodings. | Concrete classical and quantum adversary budgets and composition unresolved. Digest width alone is insufficient. |
| Fiat Shamir and knowledge | An interactive protocol with the required soundness or extraction property, followed by a reduction matching actual ordered multiround hashing. | Classical ROM, QROM and knowledge applicability remain distinct unresolved obligations. |
| Payment acceptance | One hidden witness joining eligible membership, note owner, authorization, stable nullifier, spent state, conservation, policy and encrypted delivery. | No atomic authenticated ledger acceptance interface is supplied by these components. |

The primary [Proximity Gaps for Reed-Solomon Codes](https://eprint.iacr.org/2020/654), Ben-Sasson, Carmon, Ishai, Kopparty and Saraf, FOCS 2020 with the archive's correction, establishes bounds under specified decoding radii and field conditions. Those conditions must be matched to this implementation before using a term. The broader [ethSTARK Documentation](https://eprint.iacr.org/2021/582) describes its own construction and conjectures. Neither reference supplies an automatic bound for this source composition.

The dependency's reference label for ePrint 2024/1553 differs from the archive title, [STARK-Based Signatures from the RPO Permutation](https://eprint.iacr.org/2024/1553), by Atapoor, Delpech de Saint Guilhem and Al Kindi. Bibliographic identification is not a theorem application. `p3-security/src/deep.rs` itself notes a difference between its list size factor and that paper's Theorem 2. An applicable conservative DEEP bound requires resolving that correspondence. This review does not change the pinned dependency or select the paper's signature construction.

The subsequent [quotient basis reference](../quotient-basis/README.md) derives a fixed Fourier transform from the normalized coset quotient and its coupled masks to telescoping coefficient segments. Its finite integer reference checks literal cases, a complete tiny coefficient image and seven hostile controls. This resolves a polynomial basis correspondence. Commitment, challenge, padding, hiding and theorem composition obligations remain separate.

Don, Fehr, Majenz and Schaffner's [Security of the Fiat-Shamir Transformation in the Quantum Random-Oracle Model](https://arxiv.org/abs/1902.07556v4), version 4 dated 27 July 2020, treats the three round setting. Don, Fehr and Majenz's [The Measure-and-Reprogram Technique 2.0: Multi-Round Fiat-Shamir and More](https://arxiv.org/abs/2003.05207v3), version 3 dated 7 March 2022, gives a multiround reduction in Corollary 13. Corollary 15 assumes a constant round public coin interactive proof with the underlying soundness or quantum proof of knowledge property being preserved. The oracle reduction requires a uniformly random function of the specified domain and range and has round dependent loss. This implementation's evolving hash state, nested descriptions, rejection sampling and oracle commitments have not been shown to satisfy the required protocol and oracle model. No QROM security conclusion is established here.

[Zero-Knowledge IOPPs for Constrained Interleaved Codes](https://eprint.iacr.org/2026/391), Chiesa, Fenzi and Weissenberg, archive submission 25 February 2026, presents its own honest verifier zero knowledge and extraction construction. It is not a zero knowledge theorem for the retained hiding FRI implementation merely because the security dependency cites it.

The dependency also cites newer proximity results and conjectures. Their exact theorem versions, regimes and applicability remain unselected here. No extrapolation from an archive abstract, an unreviewed calculator default, field cardinality or a successful ML-DSA authorization check is a complete classical or quantum proof system security claim.

## Resource decision and next construction

The [current inventory](README.md) separates thirteen source field roles, salt and digest vectors, FRI retained data, claims and query gathering. Its conditional full field contents are 26,300,841,984 bytes, including 22,115,516,416 main LDE bytes. Conditional main query contents are 10,798,592 field bytes. None is a measured simultaneous memory peak or serialized proof size.

Raw width above eight is refused **before** symbolic construction. Stored dimensions 4,096 by twelve, two MiB field contents and eight public values are separate checks. The quotient kernel has its own row, width and public limits. Its assertion cap of 256 follows layout discovery and cannot bound an arbitrary symbolic DAG. The dense full constructor remains refused. Current owner and quotient adapters remain monomorphic small classes.

The construction decision is to preserve those refusals. Raw streaming has not made a complete full proof feasible. No additional codec layer, replacement authorization primitive, detached proof composition or larger resource class is selected.

One bounded construction question is whether layout and degree metadata can be derived from the actual AIR without retaining its complete symbolic expression graph. `p3-air` symbolic builders currently retain assertion expressions, while uni-STARK quotient sizing and `p3-security::StarkAirParams::from_air` obtain symbolic constraints. A metadata design must account for exact constant handling, public and periodic values, row selectors, base and extension assertions, degree hints, ordered assertions, overflow and unsupported operations. It must not turn a declaration into proof validity or bypass the width preflight.

The subsequent [bounded metadata laboratory](../layout-metadata/README.md) executes the actual fixed AIR without retaining its expression graph and matches the saved assertion count and degree histogram. It is a separate tested diagnostic, not an integration into the proving planner. The 22 GB retained main LDE, monomorphic source and quotient adapters, actual committed row and query construction, security composition and private payment joins remain. No larger proof class follows from that result.

## Review scope

The original review at the stated baseline changed documentation only. Source and local link checks and whitespace review supported that record. It executed no compiler, model, symbolic collector, witness walk, proof producer, healthy verifier or earlier reference run. Subsequent metadata measurements have their own linked validation scope. No cryptographic theorem is added by this review.
