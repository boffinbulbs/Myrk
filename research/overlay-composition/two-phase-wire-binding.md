# Two phase wire binding and its implementation boundary

This source and mathematical specification supplies a prospective linear size copy relation for an immutable circuit. It identifies the additional commitment phase that the current prover and verifier would need. It does **not** supply a complete authorization layout, a new admitted proof class, an implemented memory argument or an accepting payment API. Complete execution remains refused. The [source record](wire-binding-sources.json) separates inspected definitions from preserved context.

The [whole Keccak relation](keccak-fixed-wiring.md) and its [finite integer reference](../keccak-fixed-reference/README.md) provide one concrete fixed graph. They do not make a list index into a constrained long distance copy. The [private state event relation](private-state-events.md) separately requires actual operation equations, initialization and chronological read/write consistency. The construction below treats immutable producer references; it does not turn a multiset argument into mutable sequential memory.

## Actual integration gap

The retained `p3-air` 0.8.0 `AirBuilder` uses current and next row windows. `ExtensionBuilder` supplies extension expressions and assertions. Its separate `PermutationAirBuilder` trait asks for a permutation window, randomness and values. Those trait definitions are not an implementation of a second commitment phase.

In the retained `p3-uni-stark` 0.8.0 ordinary prover and verifier folders, extension assertions fold into the same constraint evaluation, but there is no implementation of `PermutationAirBuilder` or supplied permutation window. The actual configuration documentation explicitly says uni-STARK has no lookups and ignores lookup grinding. A grinding option does not create a copy protocol.

The actual transcript order is main commitment, optional preprocessing commitment, public values, constraint batching challenge, quotient commitment, optional hiding randomization commitment, out of domain challenge, then the opening argument. Its proof commitments are `trace`, `quotient_chunks` and optional `random`. Opened values have trace, optional preprocessing, quotient and optional random rows. There is no second witness commitment or copy challenge in that shape.

The current owned producer uses those phases and constructs that actual proof before calling `finish_produced`. Its quotient kernel takes the original main window, public values and one batching challenge. It refuses nonempty preprocessing and periodic columns. It does not receive copy randomness, a committed prefix product window or a fixed program table. The owner is the small monomorphic Quartic relation, rather than a circuit interpreter. Supporting extension equations alone cannot bridge these omissions.

These are source observations, not a failed proof execution or a library audit. No compiler, metadata collector, copy evaluator, reference, witness producer, prover or verifier was run for this increment.

## Verifier owned fixed program

Let a supported immutable circuit have $M$ value nodes and $N$ variable input edges. Every node has an exact opcode, arity at most two, fixed constants and ordered source nodes. Every edge has a unique identifier and exact producer, consumer and input slot. Nodes are in a topological order. These data must come from the actual supported verifier program and rules. A peer descriptor or its hash is insufficient.

All identifiers need canonical bounded encodings. For the single Keccak graph, $M=156736$ and $N=308736$ are below the actual BabyBear characteristic, so its individual node and edge identifiers can be injected as field elements. That observation does not establish an encoding or bound for a complete signature/payment graph. Larger identifiers require separately constrained limbs; reducing an integer modulo the field is not an identifier check.

The proposed local placement is the following.

1. Each node has one header row containing its output value $V$ and zero, one or two active operand read values $R_0,R_1$. The actual opcode equation, input Boolean/range equations and applicable source equations hold on that row. Unused operand cells are constrained neutral values.
2. Immediately after that header come its outgoing send rows, one for each fixed outgoing edge. The header's value is held by current/next row equalities through all these rows. These equalities cover header-to-first-send and consecutive sends of the same node. They do not hold across the next node's header. A send emits that actual held value. No separate host-filled sender table is trusted.
3. A consumer header emits one receive tuple per active input slot, using its actual local operand read value. A sender emits its fixed edge tuple. Their orders may differ, but each fixed edge has exactly one send and one receive.

For an edge $e$, use the complete tuple

$$t=(e,\operatorname{producer}(e),\operatorname{consumer}(e),\operatorname{slot}(e),\operatorname{value}).$$

Copy every coordinate. Unique edge labels prevent exchanging two different edges with the same value or endpoints. Row kind, opcode, source labels, edge labels, multiplicities, activity and ordering must be constrained by the supported fixed schedule. They are not private advice that the host is allowed to choose freely. A future fixed program table needs its own actual binding and evaluation path; the current quotient kernel rejects such preprocessing.

This schedule gives local value holding before sends and actual consumer reads at headers. It neither overlaps unrelated live banks nor requires a producer's value to be read from a distant row before the copy argument has established it. Mutable sampler and NTT state still need their original read-before-write, version, rejected-update, initialization, hold and terminal equations. An immutable expansion would have to derive each new version from those actual equations. No such whole expansion is selected here.

The syntax of this fixed circuit is public. Witness-dependent signature addresses, rejection decisions and activity must still remain private and be constrained by actual selection and state equations. Publishing their values as program metadata is not a permitted specialization.

## Fixedness and two fresh challenges

Phase one must commit to **both** the producer values and the consumer read values, together with all operation, source and control witness columns. The complete supported program and expected public statement must already be bound to the verifier's rules. Only then may the protocol draw separate copy challenges $\beta,\gamma$ in an extension field $E$.

For the conditional algebra below, the two complete tuple lists are fixed before independent uniform challenges. This is an interactive algebra hypothesis. It does not claim that the existing Merkle/Fiat Shamir implementation supplies that hypothesis against adaptive or quantum provers. A binding commitment, actual full word fixedness and the real multiround transcript require separate arguments.

For a five coordinate tuple define

$$L_\beta(t)=\sum_{j=0}^{4}\beta^j t_j.$$

For each real row $h$, let

$$\sigma_h=\prod_{s\text{ sent on }h}(\gamma+L_\beta(s)),\qquad
\delta_h=\prod_{t\text{ received on }h}(\gamma+L_\beta(t)).$$

There is at most one send or at most two receives on a row, and an empty product is one. A second witness contains extension values $Z_h$ and $d_h$ satisfying

$$\delta_h d_h=1,\qquad Z_{h+1}\delta_h=Z_h\sigma_h,$$

with initial $Z_0=1$ and a separate terminal row enforcing $Z_R=1$. There are $R$ real rows. There must be an actual terminal row: suppressing a last-to-first transition is not a terminal condition. Padding has no emissions, $d=1$ and holds $Z$; a final terminal row has no outward transition. Complete selector and boundary equations remain to be designed for a real AIR.

The inverse equation matters. A zero receive factor cannot erase the prefix state and allow it to restart later. Every accepted denominator is nonzero. Starting at one and ending at one also excludes a zero send product in an accepted recurrence. No host division result or Boolean verdict substitutes for either equation.

An honest zero denominator would be a typed terminal refusal after the first commitment and challenges have already occurred. The proposed policy does not retry, reset the challenger, change the profile or resume an aborted prefix. An actual sampler/error implementation and its completeness analysis are not selected.

## Conditional copy proposition

Assume the local operation/holding/schedule constraints, exact tuple counts, phase one fixedness and nonzero denominator equations above. Telescoping the recurrence and using both endpoint values gives

$$\prod_{i=1}^{N}(\gamma+L_\beta(S_i))=
\prod_{i=1}^{N}(\gamma+L_\beta(T_i)).$$

If the complete tuple multisets agree, a nonzero-denominator prefix witness exists, by its successive uniquely defined ratios. Thus an actual circuit assignment gives a local placement and prefix witness whenever those denominators are nonzero.

For the converse, regard the difference of these products as a polynomial $Q(X,Y)$ over $E$. If the tuple multisets differ, $Q$ is nonzero. Indeed, over the rational function field $E(X)$, both products are monic products of linear polynomials in $Y$. Equality forces the same multiset of their roots, hence the same multiset of polynomials $L_X(t)$. Equality of those polynomials forces equality of every tuple coordinate. This uses full tuple coordinates and their canonical field encodings.

Each factor has total degree at most four. Consequently $Q$ has total degree at most $4N$. For independent uniform $\beta,\gamma$, a nonzero $Q$ vanishes with probability at most $\min(1,4N/|E|)$. One elementary way to obtain this bound is to group by the degree in $Y$: at most the degree of the leading coefficient many $X$ values kill that coefficient, and for every other $X$, the resulting nonzero univariate polynomial has at most its degree many roots. This is an algebraic conditional bound, not an achieved protocol security level.

Separately, for any fixed $\beta$, at most $N$ choices of $\gamma$ make an honest receive factor zero. The corresponding conditional refusal probability is at most $\min(1,N/|E|)$. This is a completeness event, distinct from a false copy equality. No retry amplification, Fiat Shamir, hash binding, proximity, batching, knowledge or quantum conclusion is inferred from either expression.

When exact tuple equality holds, each unique fixed edge's receive value equals its sender's held producer value. Starting at bound input nodes and applying the actual gate equations in topological order therefore recovers the immutable circuit assignment. This establishes the placement correspondence under the stated assumptions. It does not establish the complete signature relation, private source binding, ledger validity or a proof-system theorem.

## Concrete geometry decision

For the retained single whole Keccak graph, the proposed placement has

$$R=M+N=156736+308736=465472$$

real rows, plus a terminal row. Its smallest possible power of two row count is therefore $524288$. This already exceeds the current necessary raw height limit of $256$, before source, sponge, sampler, signature arithmetic or payment joins. The count includes send rows explicitly; the larger height is not hidden by the narrow local arithmetic.

Before padding, a literal prefix implementation has $R+1$ values of $Z$ and $R$ values of $d$, or $930945$ extension values. These are manual counts for this specified placement, not allocated arrays, an allocation peak, serialization, execution admission or an optimality lower bound. Constants can change a future representation only with a new correspondence and resource analysis.

With challenges fixed and before schedule selectors, a two-receive denominator has degree at most two in the local base values. Its inverse and prefix equations have degree at most three in the base and extension trace variables. The send side has at most one factor. These local statements do not determine combined AIR degree, assertion order/count, quotient chunk count, masks or a proving profile. The old eight quotient chunks cannot be imported from them.

| Dimension | Result for this proposal |
|---|---|
| Local operation cells | Header output and up to two actual operand cells; complete width with control, program, source and auxiliary columns unselected |
| Height | At least 465473 rows before power of two padding for one permutation; no full signature height selected |
| Public statement | Original full authorization has 196 public values; a supported binding to that exact statement is still required |
| Prepared and LDE | Existing preparation doubles raw height and has physical blowup eight; it is not admitted for this proposal |
| Quotient and copy auxiliary | New phase and joint equations needed; actual degree, chunking, normalized reconstruction and coupled mask design unselected |
| Claims and queries | New auxiliary current/next openings and actual repeated query rows must be accounted; no claim count or transported size selected |
| Salts, trees and FRI | Complete new commitment, masks, salts, entropy, authenticated-oracle and folding analysis missing |
| Source and ownership | Bound private initialization, fixed program tables, per-phase leases, buffers, descriptors and terminal cleanup need actual source integration |
| Wire and parser | New proof shape and bounded complete relation parser required; no executable transport selected |
| Security | Conditional copy algebra only; full binding, hiding, repeated observations, batching, Fiat Shamir and knowledge obligations remain open |

The original `8192 x 42178` signature, 71623 assertions and degree four remain their separate historical geometry. Raw width above eight is refused before its original symbolic collection. Stored `4096 x 12`, the two MiB field budget, quotient `4096 x 8` with its later 256 assertion bound, public bound eight and the monomorphic `256 x 2` owner remain distinct. The existing small proof parser and declared resource plan cannot parse or admit this proposal. No cap, profile, class or authorization primitive is changed.

## Required new protocol and ownership path

A complete successor would need this ordered contract in a new versioned protocol:

1. Bind actual verifier-owned network/rules/program/AIR/resource descriptors and the actual expected public statement.
2. Commit to the complete phase one witness and supported fixed program data through an actual authenticated mechanism.
3. Draw the two copy challenges from the uninterrupted transcript.
4. Construct and commit to the copy auxiliary witness under an actual hiding scheme and the same owned attempt.
5. Draw a fresh joint constraint batching challenge, then construct and commit to a quotient that includes operation, holding, copy, inverse and boundary equations.
6. Perform the actual separately required hiding-randomization commitment, out of domain sampling and raw/physical domain admission, then open every required phase in one complete proof.

The current randomization commitment is not a copy witness commitment: its purpose, contents and position differ. The current AIR batching challenge and later PCS batching challenge are not silent replacements for the new copy challenges. A root supplied by the caller, one extra opened point or two detached component proofs do not establish this sequence.

This needs actual matched prover and verifier folders with second-phase windows and challenges; a changed transcript shape; actual same-owner source, preparation, commitment and opening authority; complete new proof/codec fields and refusal rules; the joint quotient and its normalized reconstruction; and independent adversarial controls. The existing opening flags cannot be reset or reinterpreted as second-phase authority. Preserve the busy-claim fix, shared private opening flags, physical-domain guard and actual sampled raw-domain guard. Only an actual complete `Proof` can precede `ProofProduced`.

Every failure must retain its truthful first cause through owned cleanup. Refusal after either commitment or challenge is terminal for that owner and transcript. No PCS, configuration, MMCS, RNG or prover-data clone may supply a convenient replacement authority. No resumed prefix or supplied challenge is selected.

## Complete private relation still required

The full witness must keep one private note, verification key, real signature, nullifier secret and membership path through eligible membership, note owner, the actual PaymentStatement-to-196-byte authorization mapping, stable nullifier, amounts/assets/creation versions, conservation and policy, encrypted delivery and atomic authenticated state consumption. The 2592 byte private verification key is not a signing secret. The input commitment stays private. Matching public statements do not join separate existential witnesses.

This prospective copy relation does not supply missing note/membership/nullifier equations in the isolated signature component, a complete inner effect/authorization/recovery codec, authenticated state, confidential stake eligibility or the first-certificate authority. Payments remain private by default. Bootstrap, durable signer history, complete quorum/rounds and network activation remain blocked by their own contracts. The [complete roadmap](../../docs/delivery-roadmap.md) and its later deferrals remain unchanged.

The next useful selection is a concrete whole-program and phase-integration feasibility decision, including exact private input and public statement correspondence and all resource dimensions. Another tiny copy evaluator would not resolve the present blocker. No new program or source capture is admitted here.

## Review and evidence limits

The inspected integration scope is the actual builder/window traits; ordinary prover/verifier folder definitions and extension assertions; uni-STARK configuration, transcript phases and proof commitment/opening fields; selected original opening-claim assembly and quotient verification; and the current owned producer, context and quotient-kernel boundaries. Prior Keccak, state-event and authorization records are preserved context and immutable data.

This scope does not claim new whole-body review of every vectorized folder, cryptographic dependency, owner/composite backend, MMCS, PCS, FRI, challenger, sampler or full private relation. There is no full executable dependency/feature/license closure and no new root. The retained source manifests and original notices remain identified; this is not a cryptographic library or toolchain audit.

Only stock source identity, baseline Git blob, local target and whitespace checks are selected. All prior compiler/native/model/reference/static/scope admissions remain consumed. No old proof, healthy verifier, normalization, symbolic collector, arithmetic model or Keccak evaluator is replayed.
