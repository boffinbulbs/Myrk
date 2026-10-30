# Factorized private verifier scheduling

The factorized schedule with bound activity removes 7991 columns from the complete bounded signature relation while retaining degree four. The earlier bound activity variant measures 181221 constraints per row. Aggregate transform write routing reduces that count to 74725 while retaining the same columns and degree. Nine explicitly constrained intermediate fields avoid the higher degree of the first factorized variant. This is a native constraint laboratory with no proof or payment acceptance API.

The [reference relation](../signature-complete-native/README.md) remains unchanged. Most component modules are compiled directly from that source. Adapted sampler and matrix modules replace expanded activity expressions with producer bound fields. The transform module binds mutually exclusive writes through aggregate source expressions. The [source delta](source-delta.patch) identifies copied changes with zero context hunks. Original licenses and [source identities](provenance.json) are retained.

## Clock relation

Let $m=64$ and $n=128$. Low indicators $l_0,\ldots,l_{m-1}$ and high indicators $h_0,\ldots,h_{n-1}$ satisfy

$$
l_i,h_j\in\{0,1\},\qquad \sum_i l_i=\sum_j h_j=1.
$$

Each transition rotates the low bank. With carry $c=l_{m-1}$, the high bank follows

$$
h'_j=h_j+c(h_{j-1}-h_j),\qquad h_{-1}=0.
$$

The first row fixes $l_0=h_0=1$. The last row fixes $l_{m-1}=h_{n-1}=1$. The zero predecessor prevents the high bank from wrapping into a second complete schedule. Exact row and interval selectors are

$$
s_r=l_{r\bmod m}h_{\lfloor r/m\rfloor},\qquad
s_{[a,b)}=\sum_{r=a}^{b-1}s_r.
$$

These selectors feed the retained source, hash, sampling, transform and hint equations. Key, signature and note bytes retain their original hold rules. Replacing a linear indicator with a product affects the degree of equations that use it, even when the controller alone has low degree.

![Two constrained indicator banks select the fixed private verifier source routes](schedule.svg)

## Activity binding

The first factorized relation has two degree six constraints in the challenge sampler and eight degree five constraints in the matrix sampler. Each uses an activity expression with a phase selector $\phi$ and a completed count indicator $d$. The current relation introduces one challenge activity field and eight matrix activity fields. Each satisfies

$$
a(a-1)=0,\qquad a=\phi(1-d).
$$

The count indicator is the same private state consumed by the sampler. It retains its original Boolean, initialization and transition constraints. The activity equality is asserted inside the same AIR before the source consumer uses $a$. A caller cannot choose activity independently or disable a required source read.

Here $\phi$ has degree two, so its activity binding has degree three. If a source expression $X$ has degree three, the consumer $a(X-x)=0$ has degree four. Expanding $\phi(1-d)(X-x)$ directly has degree six. The source statement is preserved through an explicit intermediate relation rather than a host validity check.

## Earlier symbolic scope

The [version two record](records/validation-v2.json) reports seven ordinary tests and one separately guarded symbolic test. The tests check all selectors and intervals for a 32 row integer reference, 8192 native selector positions, source dimensions, carry and boundary failures, fractional or multiple indicators and repeated schedule refusal. Restoration provides positive controls for eight local clock mutations. Activity tests cover all eight Boolean phase/completion combinations, cache corruption and a deliberately detached negative control that would hide a false source read without the producer equality.

The version two equation set contains 181221 constraints per row and has degree four at width 47058. The symbolic process used a verified 512 MiB process and aggregate limit, a 120 second deadline and at least 2 GiB free memory admission. Its peak process commit was 308523008 bytes and peak aggregate commit 309809152 bytes on Windows with Rust 1.94.1. It built expression trees, not a native field trace.

## Earlier native baseline

The separately gated native test constructs one actual synthetic A0 trace, checks the supported matrix and signature stages against the retained independent integer reference and evaluates the complete signature and owner equations. That case passes. Nine activity cell mutations reject through the two affected full AIR frames, with their original global row selectors and exact restoration. One corrupted activity field also rejects in complete AIR evaluation. Several equations may detect a mutation. These cases do not isolate a single producer assertion.

The complete valid baseline and the AIR's current and next row access justify the localized mutation checks. They are borrowed frames of the full trace, not a two row replacement trace. The test keeps one wide trace at a time and never clones it. Its raw field contents are 1541996544 bytes. On the recorded Windows execution, peak process commit was 1547743232 bytes and aggregate commit was 1549017088 bytes. Both limits were installed and read back at 2 GiB before resume, with 5 GiB free physical memory admission and a 300 second deadline.

The [native guard](run_native_guarded_windows.ps1) and exact ignored test are public. The signature and note values are existing public synthetic fixtures. No signing or fixture regeneration occurs. The original degree four symbolic result is retained from [version two](records/validation-v2.json), with exact equality of the nine equation source files checked before this native record.

## Earlier native reference corpus

A second guarded execution checks the other nine supported reference tuples sequentially. Each trace is compared with its independent matrix and signature intermediates, evaluated through the complete native AIR and dropped before the next trace is constructed. Four cases accept and five reject. Together with the earlier A0 baseline, all ten supported tuple verdicts match: five accepting and five rejecting cases.

The rejected cases cover an empty context, a wrong context, a note with another owner, a wrong verification key and a wrong expected transaction. An alternate note with the same owner remains conditionally accepted by this authorization layer. Exact note membership, stable nullifiers, creation rules and conservation must still bind that note in the full payment relation.

The recorded corpus execution constructs nine traces, never more than one at a time. Peak process commit is 1548148736 bytes and aggregate commit is 1549393920 bytes, under the same 2 GiB readback limits and 5 GiB free memory admission, with a 1200 second deadline. The original A0 activity mutations are retained from [its separate record](records/validation-v3.json), rather than repeated in the corpus execution.

These are finite native reference cases. A complete hiding proof remains a separate gate. Native checks directly receive the private witness and do not establish network privacy or proof security.

## Earlier reconstructed source rejection

A third guarded execution checks 77 hostile mutation routes against one complete A0 trace. It retains the two earlier tuple records without repeating their corpus executions. The nine equation and constructor source files remain byte identical to the degree four relation.

| Mutation family | Routes | Control |
| :--- | ---: | :--- |
| Wrong matrix nonce with reconstructed suffix | 1 | Complete Keccak and local arithmetic pass |
| Detached corrected accumulator with reconstructed suffix | 1 | Complete local arithmetic passes |
| Exact multiplication with detached operand | 1 | Complete local arithmetic passes |
| Matrix, transform, hint and digest source cells | 9 | Full relation rejects, exact cells restored |
| Final received signature seed bytes | 64 | Both affected global frames reject, exact cells restored |
| Noncanonical correction write | 1 | Full relation rejects and restored baseline accepts |

Reconstructing matrix counts also changes their activity producers. The test rebuilds all nine activity fields from the actual low and high clock banks and the actual private completion indicators. It accepts no independent phase input. For selected row $r$ and completion indicator $d$, reconstruction uses the same relation $a=s_{[u,v)}(r)(1-d)$ as the AIR. Before each reconstructed suffix negative, all 8192 rows are checked for agreement with those producers. A stale cache cannot explain those suffix rejections.

The test performs four complete positive baseline or restoration checks and fifteen complete negative checks. The 64 seed mutations use actual borrowed current and next frames with unchanged global selectors. The first and last also retain complete negative evaluations. The count of 77 describes distinct routes, not isolated equations or independent security properties. Several mutations violate multiple joins.

The exact selected process retains one native trace without cloning. Peak process commit is 1547710464 bytes and aggregate commit is 1548984320 bytes. The guard installed and read back both 2 GiB limits before resume, required 5 GiB free physical memory and enforced an 1800 second deadline. A small ordinary test separately exercises clock bank decoding, the matrix boundary and changed completion producers. No backend proof, signing or fixture generation occurs.

## Transform write routing

The transform schedule selects one complete operation row. Source package version 0.3.0 aggregates its mutually exclusive write equations while retaining the same actual operands, integer products, private scratch and output state. Let $s_r$ be the constrained selector for operation row $r$, $w_j$ a write slot and $e_{r,j}$ its exact source expression. The expanded equations and aggregate form are

$$
s_r(w_j-e_{r,j})=0,\qquad
w_j=\sum_r s_r e_{r,j}.
$$

Their equivalence depends on the same AIR enforcing exactly one schedule position. Missing write slots and dormant rows contribute zero. The original Boolean carry flags retain their zero condition outside butterflies. No caller supplies a free operation selector, operand or acceptance result. Forward transforms run from row 450 through 3521, followed by inverse transforms through 5313. Matrix sampling overlaps forward transforms, so their registers remain separate.

![Constrained schedule and actual private producers determine transform writes and state](routing.svg)

The forward row specific equations contribute 65536 assertions and the inverse equations 40960. Aggregating those equations and their dormant rules removes 106496 assertions. The complete symbolic relation measures 74725 constraints per row at degree four, with the same 47058 columns, 8192 rows and 196 public values. Expression terms and field widths remain relevant costs. Assertion count alone is not a proving time measurement.

The exact public source is tested afresh because its transform equations changed. Eight ordinary tests pass. Separate serial native executions check A0 and its nine activity mutations, the other nine reference tuples, and the 77 hostile source routes described above. All ten tuple verdicts match, five accepting and five rejecting. The source reconstruction tests still check actual activity producers before suffix rejection. Each process keeps at most one trace. No proof backend runs.

The new complete symbolic process has peak aggregate commit 297562112 bytes under 512 MiB readback limits. The native process limits remain 2 GiB each, with 5 GiB free memory admission. Their measured aggregate peaks are 1548984320 bytes for A0, 1549180928 bytes for the remaining tuples and 1549152256 bytes for hostile routes. Deadlines remain 300, 1200 and 1800 seconds respectively. These measurements validate the finite native scope and do not establish a hiding signature proof or private network capability.

## Conditional complete cost

The [cost calculation](costs.json) retains blowup eight, extension degree four, four random columns, sixteen salt columns and 64 queries only for comparison. It does not select a chain proof profile. For degree $d$ in the retained two adic hiding construction,

$$
q=2\,2^{\lceil\log_2 d\rceil},\qquad
H_Q=qN,\qquad \text{constraint row positions}=H_Q C,
$$

where $C$ is the actual number of constraints per row. Each quotient chunk needs its own commitment field file in the current storage experiment.

| Quantity | Original | Factorized v1 | Bound activity v2 | Aggregate routing |
| :--- | ---: | ---: | ---: | ---: |
| Witness columns | 55049 | 47049 | 47058 | 47058 |
| Constraints per row | 205201 | 181203 | 181221 | 74725 |
| Maximum symbolic degree | 4 | 6 | 4 | 4 |
| Quotient chunks | 8 | 16 | 8 | 8 |
| Quotient domain rows | 65536 | 131072 | 65536 | 65536 |
| Constraint row positions | 13448052736 | 23750639616 | 11876499456 | 4897177600 |
| Raw field contents in bytes | 1803845632 | 1541701632 | 1541996544 | 1541996544 |
| Prepared and commitment field files in bytes | 32509329408 | 27824291840 | 27796045824 | 27796045824 |
| Field files | 11 | 19 | 11 | 11 |

Version two retains the original quotient size and eleven field files while reducing conditional field contents and constraint positions. All native shapes still exceed current height, width and aggregate field byte limits. No allowance was expanded and no native proving speedup is claimed. Field positions are an arithmetic count, not an instruction or runtime measurement. [Versioned records](records/README.md) preserve the first experiment and its higher degree result byte identical.

## Schedule alternatives

1. A direct thirteen bit clock makes an exact row selector a degree thirteen product. Its complete signature composition has not been measured. Raw width alone is insufficient for selection.
2. A structured controller can retain explicit indicators for expensive events. Its producer, reset and hold rules must bind every consumer before register reuse is valid.
3. The retained AIR interface supports verifier defined periodic columns and authenticated preprocessed columns. Their public values, transcript binding, queried widths and evaluation tables have costs. Moving a wide schedule into public preprocessing does not make that cost disappear.

Public schedule inputs must be fixed by the verifier. Host supplied row selectors, assumed lookups and independently accepted component joins cannot replace the complete relation. Complete proof resource and security composition analysis remains the next integration gate. The [current record](validation.json) identifies the exact symbolic and native executions for aggregate routing.

## Reproduction

```text
python research/signature-scheduling/reference.py --check
python research/signature-scheduling/static_check.py
python research/signature-scheduling/compare.py --check
python -m unittest discover -s research/signature-scheduling -p test_compare.py -v
cargo fmt --manifest-path research/signature-scheduling/Cargo.toml --all -- --check
cargo test --manifest-path research/signature-scheduling/Cargo.toml --release --locked --lib -- --test-threads=1
cargo clippy --manifest-path research/signature-scheduling/Cargo.toml --release --all-targets --locked -- -D warnings
```

All four ignored tests require their own exact resource admission and environment markers. A marker acknowledges an installed external limit and does not install one. Ordinary tests execute none of them. For the baseline, build the release test executable, set KOVA_BOUND_NATIVE_GATE to reviewed-external-resource-admission and pass that executable to the guard with the exact selection native_tests::a0_native_baseline_and_activity_mutations, --exact --ignored --nocapture --test-threads=1, ExpectedTests 1 and TimeoutSeconds 300. For the nine remaining tuples, use KOVA_BOUND_NATIVE_CORPUS_GATE with the same marker value, native_tests::remaining_native_reference_tuples and TimeoutSeconds 1200. For the hostile routes, use KOVA_BOUND_NATIVE_HOSTILE_GATE with that marker value, native_tests::bound_reconstructed_suffixes_and_source_routes_reject and TimeoutSeconds 1800. Run the selected tests serially with fresh output prefixes and fresh memory admission. No complete signature prover is included.
