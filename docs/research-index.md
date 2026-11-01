# Research implementation index

This index records the individual laboratory boundaries, retained references and source construction stages. The [protocol overview](../README.md), [research specification](research-target.md) and [implementation record](development.md) define the surrounding requirements. Each laboratory retains its own exact dependencies, reproduction commands and measured scope.

## Proof research map

The workspace contains eight isolated hiding proof crates. Their component and diagnostic statements are research interfaces rather than a production payment format. Exact dependencies, independent references, closed transport profiles and test scope are recorded with each component.

| Component | Verified relation scope |
|---|---|
| [Conservation](proof-lab.md) | Four private u64 amounts and bounded integer conservation without note linkage |
| [Canonical notes](note-proof-lab.md) | Four exact commitments linked to private amounts, with public input commitments |
| [Hidden membership](membership-proof-lab.md) | Hidden input commitments and depth 32 paths, common root membership, distinct inputs and conservation |
| [Stable nullifiers](nullifier-proof-lab.md) | Same retained secrets and hidden commitments linked to stable public nullifiers within membership and conservation |
| [Hash and XOF](hash-proof-lab.md) | Bounded SHA3 and SHAKE, with further signature source and sampling components |
| [Exact arithmetic](arithmetic-proof-lab.md) | Canonical integer multiplication modulo 8380417 and reusable coefficient constraints |
| [Polynomial transforms](ntt-proof-lab.md) | Complete forward and inverse normal residue transforms in a public polynomial harness |
| [Owner key binding](owner-binding-proof-lab.md) | Private verification key preimages connected to owner fields in the same hidden note relation |

The hash crate additionally contains [matrix sampling](matrix-sampling.md), [sparse challenge sampling](challenge-sampling.md), [canonical signature and challenge linkage](signature-challenge.md), [private key source constraints](key-source.md) and a [conditional private signature row](reconstructed-row.md). Canonical key parsing and conditional row computation are implemented components. Their actual key, signature, all eight row, note and transaction connections remain incomplete. Knowledge of a verification key or its hash preimage grants no spending permission.

[Coefficient constraints](coefficient-constraints.md) and [compact transforms](compact-ntt.md) retain their exact arithmetic and layout evidence. The [transparent signature reference](../research/signatures/README.md) supplies full independent verification calculations over public synthetic data. It is an oracle, not private authorization.

The [transaction signature and note ownership reference](../research/signature-ownership/README.md) adds six existing signatures over exact typed transactions, two native verification paths and complete independent integer calculations through all eight signature rows and final challenge equality. Canonical v2 notes supply explicit owner match and mismatch cases. This is reference evidence for the missing complete private authorization relation, without a native AIR, backend proof or payment authority claim.

The [native signature laboratory](../research/signature-native/README.md) constrains the same private key, signature and canonical note sources together with sixteen forward transforms. The note owner field is bound to the private key hash and transaction authorization supplies the public 196 byte input. The transform outputs and input note commitment remain private witness columns. This retained snapshot ends before matrix reconstruction and final signature verification.

The [complete bounded native relation](../research/signature-complete-native/README.md) adds all 56 matrix streams, eight reconstructed rows, normalized inverse transforms, actual hints, private packed bytes and the full final challenge equality. It binds the same key and note owner to authorization derived from the typed transaction. Native evaluation receives private data directly. A hiding proof backend, private ledger composition and their security and resource analysis remain separate gates before payment acceptance.

The [private verifier scheduling experiment](../research/signature-scheduling/README.md) uses two constrained clock banks and explicit activity producers in the complete degree four relation. Ten native reference verdicts match, and 77 hostile source routes reject with baseline and restoration controls. These are native witness checks. A complete hiding signature proof remains separate work.

The [retained constraint folding experiment](../research/constraint-folding/README.md) evaluates that actual AIR on finite synthetic row groups through the backend constraint folder. Captured residuals match a separate scalar fold and independent integer arithmetic. This isolates evaluation and folding from the outstanding polynomial commitment, complete proof and security composition requirements.

The [conditional proof profile analysis](../research/proof-profile/README.md) includes all batched columns, masking budgets and field storage in the retained classical model. Its scenarios separate numerical model output from the remaining protocol, knowledge and quantum security obligations.

The [output lifetime laboratory](../research/output-lifetimes/README.md) constrains nine shared banks against dedicated storage under the retained schedule. Independent full-coordinate intervals and actual synthetic native rejection controls test temporal reuse before any complete signature layout change.

The [private signature storage laboratory](../research/signature-storage/README.md) connects that mapping to actual canonical transform writes and matrix consumers. Its separate native records retain complete signature and note ownership constraints while reducing the physical output layout. The original scheduling source remains the reference.

The [proof resource preflight](../research/proof-preflight/README.md) exposes the retained masking check and derives finite shapes from actual AIR helpers. Unsupported complete shapes are refused before large symbolic evaluation. Resource plans retain separate security, private ledger and prover integration obligations.

The [checked storage matrix](../research/storage-matrix/README.md) supplies owned synthetic rows through the retained matrix interface, with canonical field decoding, checked windows and explicit storage failures. It is a storage integration component. Complete commitment, quotient and FRI integration remains separate from these accessor tests.

The [storage commitment experiment](../research/storage-commitments/README.md) connects those rows to the actual retained salted MMCS. Independent integer and SHA3 references cover four roots, including a mixed height batch. Memory and storage paths are compared through ordinary openings and pruned multiproofs.

The [stored polynomial proof laboratory](../research/storage-pcs/README.md) carries checked storage through a complete small quartic STARK, including actual coupled quotient masks, the randomization polynomial and FRI openings. Main randomization writes directly to storage. Main, quotient and randomization commitments are constructed one column at a time. Its proof bytes match the retained dense prover and its ordinary verifier rejects raw false traces and corrupted mask coupling. Remaining resident inputs, larger proofs and private payment integration remain separate work.

The [proof feasibility record](proof-feasibility.md) distinguishes implemented experiments from open hiding, knowledge soundness, quantum model, resource and composition obligations. Standardized primitives and full digests do not establish the composed protocol's security level.

The [owned source preparation laboratory](../research/source-preparation/README.md) uses one field preparation kernel for ordinary dense inputs and owned checked files. Eight bounded test groups compare the retained layout and continuing randomness, then exercise corrupt input, partial writes and failed ownership cleanup. This preparation layer creates no commitment or proof. Its next integration boundary is an owned source PCS entry with an unchanged verifier.

The [streamed commitment input laboratory](../research/source-extension/README.md) reuses that preparation kernel and constructs the main LDE through bounded full and partial column tiles. All fields match the retained dense calculation, with sixteen independently interpolated physical output cells. Unified reservations and failure controls cover raw, prepared and LDE files. This policy ends at file construction and does not yet create a commitment root or opening proof.

The [owned source commitment laboratory](../research/source-commitment/README.md) connects that construction to the actual hiding Merkle MMCS and original private prover data. Owned and dense convenience roots match retained ordinary dense dispatch. An independent SHA3 calculation reproduces the full root from 4,096 synthetic salted leaves. Failure after an actual commitment closes the outer attempt while retaining the inner construction leases. Opening compatibility remains a separate gate.

The [source opening laboratory](../research/source-opening/README.md) completes that finite PCS gate with three identical actual opening proofs accepted by the retained verifier. It rejects changed roots, claims and authentication digests and refuses a consumed private prover data clone. Independent arithmetic reconstructs ten Merkle roots and four extension opening values. This establishes small source opening compatibility. Complete AIR validity and private payment integration remain separate requirements.

The [composite storage laboratory](../research/source-composition/README.md) places main, eight quotient and auxiliary matrices under one owned file policy and one associated prover data family. Six actual input commitments compare the new and retained dense paths, including roots, fields and continuing entropy. Whole attempt reservations remain fixed after failure. This construction comparison does not derive an AIR quotient or construct a complete computation proof.

The [owned computation laboratory](../research/source-stark/README.md) connects that storage to the real quotient evaluator and one original batched opening for a complete fixed quartic proof. Owned and freshly constructed retained proofs have identical complete bytes and pass the retained full verifier. Independent checks reconstruct twelve roots from actual leaf digests. The full private signature and payment relations remain separate gates.

The [invalid witness laboratory](../research/source-stark-false/README.md) changes one canonical field while retaining the public endpoints. The frozen prover returns a complete proof whose openings pass the retained verifier before its constraint identity rejects the invalid witness. The existing honest fixture still verifies. This single control covers the fixed synthetic relation.

The [packed source laboratory](../research/source-packing/README.md) constrains selected private words and repeated byte reads under one fixed clock. Its actual symbolic shape and eighteen adversarial native rejections cover alignment, source holds, padding, stale reads and range aliases, with restored positive controls. This is a small source mechanism. Full signature routing, ownership and payment integration remain separate work.

The [full source inventory](../research/source-certificate/README.md) compares independently organized scalar accounts of every physical row in the retained signature schedule. It records complete source coverage, framing, last use, alignment and simultaneous word demand. Its literal peak is 125 source words.

The [complete packed signature source](../research/signature-packed/README.md) connects that inventory to a compiled replacement layout with 2,547 held words and 125 Boolean read ports. Its actual fixed route test matches every row and source byte offset against the frozen inventory. Symbolic analysis, native controls and proof integration are recorded separately. The full constructor is disabled by default.

The subsequent [complete symbolic shape record](../research/signature-packed-shape/README.md) evaluates the actual candidate AIR once and records 69,242 assertions with maximum degree four. Its guarded execution fits the retained memory limit without constructing a native trace.

The [first complete packed native witness](../research/signature-packed-native/README.md) accepts the independent A0 fixture across every row. Six causal source corruptions fail at their exact expected constraints, and all restorations pass. The bounded run constructs one trace and distinguishes its full scan from borrowed global frame checks.

The [remaining packed native corpus](../research/signature-packed-corpus/README.md) evaluates nine additional reference tuples serially. Four valid witnesses pass and five wrong owner, context, key or expected transaction cases fail at their intended constraints. The legitimate same owner alternate note passes with consistently rebuilt sources. These records cover the ten selected bounded fixtures across separate gates.

The [consistent virtual padding controls](../research/signature-packed-padding/README.md) alter the held signature and note tails together with every matching read port. Each of four controls fails only its intended padding rule on all 8,192 global frames, and all restored witnesses pass. The run records 73,728 frame evaluations on one complete trace. Full equivalence, hiding signature proofs and private payment integration remain separate work.

The [fixed signature proof boundary](../research/signature-proof-contract/README.md) owns the actual private witness and immutable canonical transaction, deriving public authorization values through the retained mapper. Three nonproving test groups cover exact public reference vectors, canonical limit errors and the actual packed relation resource refusal without observed RNG or storage effects. A complete streamed producer, hiding proof and same witness ledger joins remain unfinished.

The [owned signature source](../research/signature-owned-source/README.md) places witness ownership and retained constraint modules in one cohesive source version. Its private decoding state emits only its assigned row columns, preserving current state before each update. Two complete decoding walks match the retained prefix oracle and independent terminal values, with malformed source and cursor controls. Other construction stages, masked random access and complete proof integration remain unfinished.

The [initial hash source](../research/signature-hash-source/README.md) advances genuine hash state and decoding in the same row from one owned witness and canonical transaction. Its bounded block reference, independent source bank checkpoints and challenge XOF reference cover the initial pass and private source timing. The dummy tail is provisional until matrix and final hashing are integrated. This is constructor evidence, with complete private payment proving still unfinished.

The [owned sampling source](../research/signature-sample-source/README.md) extends that composition with private challenge state driven by the actual current row XOF. A bounded original loop oracle and independent retained terminal coefficients check register timing, source consumption and completion. This remains component construction evidence within the complete private payment proof work.

The [owned forward source](../research/signature-forward-source/README.md) reads decoded and sampled operands from that same row and preserves transform register timing and physical bank lifetimes. A bounded adapted reference and retained independent stage values cover the forward pass. Matrix and inverse overlap, complete rows and private payment proof integration remain unfinished.

The [matrix hash source](../research/signature-matrix-source/README.md) extends the same owner with genuine matrix expansion and current squeeze bank timing. Sparse overlays preserve source and forward fields. Saved streams and a bounded original body adaptation check terminal chunks and intermediate construction. Coefficient sampling and accumulation are covered by the following source stage.

The [accumulator source](../research/signature-accumulator-source/README.md) consumes actual current matrix bytes and physical forward banks for rejection sampling, accumulation and point correction. Independent retained arithmetic vectors supplement a bounded reference, and typed capacity failure is terminal. Inverse construction is covered by the following source stage. Final phases, complete rows, hiding proofs and private ledger integration remain unfinished.

The [inverse source](../research/signature-inverse-source/README.md) reads actual accumulator tiles and held forward scratch within the same owner. Eleven saved state checkpoints per transform supplement the bounded reference across partial initialization, normalization and the held terminal state. Hint reconstruction is covered by the following source stage. Final challenge equality, complete rows, hiding proofs and private ledger integration remain unfinished.

The [hint source](../research/signature-hint-source/README.md) reads actual inverse outputs and decoded hints, preserving canonical dormant gadgets and delayed private W1 byte updates. Saved step fields and comparisons of every packed byte on every row supplement the bounded reference. Final sponge construction is covered by the following source stage. The following source stages cover final sponge and complete bounded row construction. Actual AIR signature equality, hiding proofs and private ledger integration remain unfinished.

The [final sponge source](../research/signature-final-source/README.md) consumes actual MU and completed W1 with full state carry across nine blocks. A bounded six row reference and saved terminal bytes check construction and dummy restoration. Raw signature comparison remains diagnostic. The next source stage connects clock and packed private sources. Actual AIR signature equality, hiding proofs and private ledger integration remain unfinished.

The [clock and packed source](../research/signature-port-source/README.md) completes one streamed row walk through the actual immutable owner and bounded source pipeline. Literal words, selected byte reads, clock carries, virtual tail bytes and preserved upstream fields are checked without allocating a complete wide trace. Terminal routed byte comparison remains diagnostic. Actual clock and packed constraints, full signature AIR, hiding proofs and private ledger integration retain separate verification gates.


The [genuine clock and packed constraint frames](../research/signature-frame-native/README.md) execute the actual retained equations on twelve adjacent source frame pairs with real global boundary selectors. Seven new frame mutations reject at their recorded constraints and seven restorations pass. This is finite native constraint coverage. The following full streamed AIR stage covers complete native evaluation and final signature equality for one fixed witness. Hiding authorization proofs and private ledger integration retain separate gates.

The [complete streamed signature and ownership relation](../research/signature-stream-native/README.md) evaluates the actual retained AIR on all 8192 global frames produced by the same immutable synthetic owner and canonical transaction. Three packing and hold consistent controls separately reject changed note ownership, transaction context and final signature bytes, with all full AIR restorations passing. This validates the complete bounded native computation without allocating a complete wide trace. Hiding proofs, universal soundness, prover resources, composed security and private ledger integration remain separate.

The [committed quotient construction](../research/quotient-source/README.md) reads the actual main commitment data through an owner checked logical view and writes canonical extension coefficients to a sealed sink. All 4,096 visible fields match the retained fast view and all 8,192 quotient coefficients match an independent integer implementation. Nine fixed arithmetic mutations separate. The fixed synthetic relation uses one main commitment, two main extension tile calls and no opening or proof.

The [coupled quotient commitment](../research/quotient-mask/README.md) consumes the sealed source under the same owner and attempt. Its diagnostic compares all 24,576 main fields and 262,144 quotient chunk fields with the retained dense path, including actual roots and continuing synthetic randomness. Ten source and owner controls complete under the external guard. The dense comparison shares the quotient and transform algorithms. The independent mask arithmetic check follows below. Uninterrupted transcript composition, complete hiding proofs and private ledger integration remain separate work.

The [eight domain normalization reference](../research/mask-normalization/README.md) checks the same private helper used by its source adapter against independent integer arithmetic. All eight ordered domains and normalizers and all 2,048 final mask coordinates match. Six mutations separate, and two malformed shapes are refused before any update. The selected runs construct no commitment or proof. The fixed bank includes zero and modulus minus one inputs. Equal normalizer degeneracy and the boundary between domain metadata and mask coordinate controls remain explicit.


## Complete source proof integration

The [uninterrupted source prover](../research/source-prover/README.md) connects the committed main view and canonical quotient source to actual coupled and auxiliary commitments, original OOD evaluation and a single original opening. Its [source relation and lifecycle](../research/source-prover/transcript.svg), [saved observations](../research/source-prover/results/measurement.json) and [validation record](../research/source-prover/validation.json) distinguish a complete small proof from full private signature and payment integration. One original verifier acceptance and ten actual verifier rejections are recorded. CI checks saved evidence and compilation without replaying the native proof.


The [live source failure laboratory](../research/source-failure/README.md) adds real quotient source length and auxiliary exclusive output collision cases under the same proving lifecycle. Its [measurement](../research/source-failure/results/measurement.json) and [validation](../research/source-failure/validation.json) record first cause preservation, actual committed descriptor closure and diagnostic sentinel preservation. These are storage failure controls, with no opening, verifier or completed proof selected.

The [private opening authority laboratory](../research/source-consumption/README.md) exercises actual point budget refusal and the original shared private flag guard. Its [measurement](../research/source-consumption/results/measurement.json) and [validation](../research/source-consumption/validation.json) distinguish preflight from consumption and record caller closure across actual committed lease aliases. No inner opening, verifier or complete proof is selected.

The [complete proof composition analysis](../research/proof-composition/README.md) connects packed relation dimensions, full source role contents and security obligations. Its [static projection](../research/proof-composition/projection.json) crosschecks actual small reservations and the independent earlier storage model. It admits no proof and assigns no achieved security score.

The [packed lifetime inventory](../research/packed-lifetimes/README.md) records all 67 physical regions, source reviewed family obligations and conservative schedule conflicts. Its [saved inventory](../research/packed-lifetimes/inventory.json) separates source metadata from the unimplemented mode overlay candidate. The [schedule figure](../research/packed-lifetimes/schedule.svg) shows active phase boundaries under one global clock.

The [arithmetic overlay component](../research/arithmetic-overlay/README.md) constrains both modes, original multiplication and UseHint equations, held inputs and result updates in one bank. Its [native measurement](../research/arithmetic-overlay/results/measurement.json) records a complete positive scan and sixteen rejection controls. Complete native signature equivalence and hiding proofs remain separate from that component result.

The [complete signature overlay](../research/signature-overlay/README.md) binds that shared workspace to actual private source operands and the original transform, hint and ownership computation. Its [symbolic result](../research/signature-overlay/results/symbolic.json) records 71,623 assertions of degree four in a 42,178 column layout. Complete native source equivalence and hiding proofs remain separate from this symbolic result. The [validation](../research/signature-overlay/validation.json) and [source manifest](../research/signature-overlay/provenance.json) preserve its exact scope and provenance.
