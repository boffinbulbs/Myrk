# Private state event consistency

This mathematical specification defines the memory consistency obligation for a possible lowering of the complete signature relation. It derives concrete event ordering from the retained source. A direct finite consistency relation is described and shown equivalent to sequential memory under explicit assumptions. Its dense encoding is refused as an implementation candidate. No new AIR, memory argument, proof system or execution class is activated. The [source record](private-state-sources.json) gives the inspection scope.

## Source semantics before memory representation

The [signature overlay](../signature-overlay/src/air.rs) constrains current and next physical rows under one clock. The constructor fills entire trace banks in several passes. Those host passes are not the protocol's chronological memory operations. For example, a later inverse pass overwrites arithmetic witness cells prepared by an earlier pass. Recording both host writes as sequential constrained updates would describe the constructor rather than the AIR.

A lowering must extract logical reads and updates from the actual equations. Each original physical row supplies a state snapshot. Reads of that snapshot precede its state updates. Any serialized substeps have fixed, constrained identities within that row. Holds are the absence of an update to an existing state coordinate, not permission to select a new value. Arithmetic witness bits and mode overlays need their original equations even when they are not persistent memory addresses.

The following source cases determine required ordering.

| Family | Actual source obligation | Required event semantics |
|---|---|---|
| [Private packed sources](../signature-packed/src/packed.rs) | Held key, signature and note words feed constrained Boolean ports | Initialize each source word once from the same hidden byte arrays. Every routed read returns that word. Source regions remain read only after initialization. |
| [SampleInBall](../signature-storage/src/sampler.rs) and its [constructor](../signature-complete-native/src/build/sample.rs) | A selected old challenge entry feeds a destination copy, then a signed overwrite | Read old `c[j]`, write that old value to `c[i]`, then write the sign to `c[j]`. The case `j == i` is allowed. |
| [NTT](../signature-overlay/src/ntt.rs) | Both operands belong to the preupdate scratch state | Read both butterfly operands before either output write. Preserve partial initialization and all other scratch coordinates. |
| [Matrix accumulation](../signature-storage/src/matrix.rs) | Nine count states describe eight ordered candidate slots | Bind each slot's index to its preceding count. Rejection advances its byte cursor but does not update the accumulator. Accepted updates must consume the actual selected coefficient and old accumulator. |
| [Inverse hints](../signature-overlay/src/hint_rows.rs) | The same normalized inverse coefficient and decoded hint produce held `w1` bytes | Reads must join those actual producers. A native hint output or independently supplied coefficient cannot initialize the result. |

### Sampler alias and rejection

At accepted step $k$, the original sampler has $i=196+k$ and accepts a candidate $j\le i$. Store a challenge coordinate as the pair $(c^+,c^-)$ of mutually exclusive Boolean values. Its canonical residue is $c^++(q-1)c^-$ for $q=8380417$. Let the selected sign be $s$.

The ordered updates are

$$v\gets c[j],\qquad c[i]\gets v,\qquad c[j]\gets(1-s,s).$$

The retained AIR explicitly constrains `OLD_PLUS` and `OLD_MINUS` to the selected current entry. For $j=i$, each coordinate of its combined transition simplifies to the final sign because the old selected coordinate equals the current coordinate. For $j\ne i$, only those two coordinates change. Thus logical address equality is part of the algorithm. It does not justify aliasing unrelated live witness banks.

For a literal specification case, take $k=0$, $i=j=196$, $c[196]=(0,0)$ and $s=1$. The ordered result is $(0,1)$. Copying the old zero after writing the sign instead gives $(0,0)$. This is a manual ordering example, not an executed witness or an accepted bad proof. A rejected candidate produces no challenge write. The original count, activity, candidate bounds, consumed XOF bytes and cursor equations remain mandatory beside the memory relation.

### Butterfly snapshots and physical bank reuse

For a forward butterfly, the original source computes $t=\zeta b\bmod q$, $u=a+t\bmod q$ and $v=a-t\bmod q$ from the same old pair $(a,b)$. Both writes follow both reads. The literal $a=2,b=3,\zeta=5$ gives $t=15,u=17,v=8380404$. Replacing the old $a$ with the newly written $u$ in the second expression gives 2 instead. Range checks, quotient and carry equations remain necessary. Memory consistency alone would not reject a different arithmetic operation whose reads were honestly recorded.

The shared scratch bank starts at zero in the original relation. Later transforms partially reload it. The inverse constructor explicitly starts from the held forward terminal scratch state. It does not clear the whole bank at an inverse boundary. An event conversion must keep untouched coordinates through those boundaries and enforce each selected initialization write.

Logical transform names also differ from physical output bank addresses. The [layout](../signature-overlay/src/layout.rs) maps both `Z6` and `T1_7` to bank six at disjoint lifetimes. From the actual [schedule](../signature-overlay/src/full_program.rs), the last `Z6` matrix read occurs no later than physical row 3329. The replacement `T1_7` output writes occur on rows 3490 through 3521 and are visible in following rows. Its point products begin at row 3554. These are source schedule inequalities, not an executed liveness test. A memory representation using the physical bank address must retain that ordered overwrite. A representation using logical addresses must constrain the exact transfer and retirement instead of silently choosing a fresh initial value.

## Finite event relation

Fix a finite supported program and a finite event count $N<p$, where $p$ is the base field characteristic. This section is a relation over finite tuples, not an implemented AIR layout. Every integer comparison below requires canonical bounded coordinates and an exact constrained comparison in an implementation. Field subtraction is not an integer ordering operation.

An event is

$$E_i=(i,\rho_i,a_i,\tau_i,\kappa_i,b_i,v_i),\qquad 0\le i<N.$$

Here $i$ is a unique event identity, $\rho$ a typed region, $a$ its coordinate, $\tau$ its complete chronological substep, $\kappa$ its kind, $b$ the value before the event and $v$ the value afterward. Values can be fixed width tuples, such as the sampler Boolean pair. Region and coordinate include all semantic distinctions needed to prevent unrelated state from aliasing. For this finite construction, the chronological identities themselves determine a strict total order. A physical row and subslot label must match that order in the operation constraints.

The event table must satisfy all of the following.

1. The actual constrained program produces every event. Its phase, operation, active state, address, read operand and write result are bound to the same witness. It cannot supply an arbitrary internally consistent memory trace instead of performing the signature equations. Counts, maximum event lengths and each missing or unsupported operation refuse.
2. Each declared real address has exactly one initialization event in a fixed prefix, at its fixed address. Its before value is zero. Its after value is either the actual bound hidden source word or the specified initial constant. The source byte decomposition, range and final partial word padding are constrained. No later initialization event is allowed.
3. A read has $b_i=v_i$. A write has the actual program's constrained result as $v_i$. Both kinds must consume the current value as $b_i$. Writes to a source region after initialization refuse.
4. Inactive slots have a distinct padding kind and their own reserved padding region and coordinate. Their tuple has canonical zero data and cannot impersonate a real access. Each padding event is a singleton group. The actual active predicate and fixed slot identity determine whether this rule applies. Padding cannot remove a required event or create a real initialization.
5. A second table $S$ contains exactly the same complete tuples, sorted lexicographically by $(\rho,a,i)$. Within each real address group, the first event is its unique initialization. Every later event has before value equal to its predecessor's after value. Same-address flags, group boundaries and comparisons must be derived from the canonical keys. They cannot be supplied unchecked.
6. The last sorted row does not wrap to the first. Required final reads are ordinary producer bound events and cannot be omitted by declaring a terminal memory root. Any trace padding outside these $N$ events has a separately fixed boundary and no live state effect.

In a full construction, the initialization prefix is a finite typed address declaration, not an untrusted list chosen by the prover. A new region or source layout requires a verifier supported program definition. The original same-note private joins from the [authorization decision](authorization-construction.md) remain necessary at those sources and consumers.

### A direct exact permutation condition

There is an elementary deterministic way to express the complete tuple permutation without a random challenge. Introduce $N^2$ Boolean field variables $P_{j,i}$ and require

$$P_{j,i}(P_{j,i}-1)=0,\qquad \sum_iP_{j,i}=1,\qquad \sum_jP_{j,i}=1,$$

$$S_{j,\ell}=\sum_iP_{j,i}E_{i,\ell}\quad\text{for every tuple coordinate }\ell.$$

Since $N<p$, each Boolean row or column sum is an integer between zero and $N$, strictly below $p$. Its field equality to one implies exactly one selected entry. Thus $P$ is an actual permutation matrix. Every tuple coordinate, including identity, region, address, substep, kind and both values, is copied. No randomized tuple compression, product denominator, supplied digest, hash assumption or independent challenge is used in this abstract condition. The bound $N<p$ is essential to this particular counting argument.

**Conditional consistency proposition.** Suppose all six event requirements and the exact permutation equations hold. Every real read returns the most recent preceding write or initialization to the same address in chronological order. Every update preserves all other addresses.

To prove the proposition, the permutation equations give each chronological tuple exactly one sorted occurrence. Strict key order lists each address's occurrences in its original chronological order. Its first event has the specified initialized value. Induction within that address group gives the current value before the next event from the previous after value. A read preserves it and a write replaces it with the constrained result. Distinct typed addresses have distinct groups. The fixed initialization prefix, no later initialization and no terminal wrap exclude an unbound start or a cyclic justification. Applying this induction to each address proves the claim. Conversely, a correctly initialized finite sequential execution gives a sorted table and its permutation matrix satisfying this relation.

This proposition proves memory consistency conditional on actual event production, bounds, sorting and operation equations. It is not a signature equivalence, polynomial IOP soundness theorem, zero knowledge proof or implemented check. An adversarial operation can satisfy memory consistency while computing the wrong function if the operation equations are missing.

## Dense encoding refusal and remaining construction

The subsequent [exact Keccak fixed wiring relation](keccak-fixed-wiring.md) specializes immutable state references for all 24 rounds and gives a conditional correspondence to the retained round equations. Its direct field materialization is also refused. No copy argument or prover class follows from either specification.

The explicit permutation matrix is a specification baseline, not a viable successor. In this particular encoding it materializes $N^2$ Boolean field cells before event coordinates, sorting or cryptographic arithmetic. Representing the retained 2,547 private source words as separately initialized addresses with at least one read each already gives $N\ge5094$. Its matrix alone has at least

$$5094^2=25948836\ \text{field cells},\qquad 4\cdot25948836=103795344\ \text{field content bytes}.$$

These are manual source and encoding counts, not an allocation, memory peak, wire size or runtime admission. The current necessary raw shape bounds $H\le256,W\le8$ permit at most 2,048 raw cells. The concrete owner remains the fixed smaller Quartic class. This dense construction therefore cannot be compiled into that class by rearranging its cells. The bound applies to materializing this full matrix. Specializing fixed addresses, using another deterministic wiring representation or choosing a different consistency proof changes the construction and requires a new analysis. It is not an information theoretic lower bound for private memory or signatures.

The direct matrix has $N^2$ Boolean equations, $2N$ row and column sum equations and $Nt$ tuple copy equations for $t$ coordinates, before sorting and operation constraints. The displayed equations have degree at most two in their own variables. This is not the combined AIR degree: real comparison encodings, selectors, dataflow, holds and boundaries remain unimplemented. A full height, width, assertion layout, quotient count, prepared domain, masking entropy, LDE, auxiliary data, queries, salts, trees, FRI, simultaneous resources and proof schema cannot be inferred from the permutation equation degree alone. No profile, lookup argument or larger class is selected.

The next construction must reduce the actual representation and bind the full operation event grammar, starting with exact Keccak round state routing. A probabilistic memory or copy argument would need its own complete source, challenge schedule, collision/denominator analysis and theorem correspondence. This specification does not adopt one. Private addresses, sorted keys and activity are witness data too. Exposing them as public sorting metadata could disclose signature sampling behavior. Any added table needs joint hiding and transcript analysis together with all existing observations.

## Required controls and validation status

The following are required future controls, not executed tests:

1. Same-address sampler copy and sign overwrite, distinct-address copy, rejection with no write, completed sampler with no further active write, and mismatched cursor or event subslot.
2. Both butterfly reads before writes, a corrupted modular product, inverse partial initialization and a changed held scratch coordinate.
3. Reused bank six with its real last read and first replacement write, and a premature replacement or fictitious fresh initialization.
4. Changed source word, final word padding, cross-region alias and a write to a read only source region.
5. Missing initialization, duplicate initialization, stale read, changed before value, read that changes state and a missing final read.
6. Duplicated, missing or reordered tuple, omitted identity or value coordinate, unchecked same-address flag, malformed key range and a row or column sum that would wrap without the stated count bound.
7. A padding event impersonating a real event, changed activity, hidden required access and last-to-first state wrap.
8. An internally consistent trace for the wrong operation. It must fail actual operation binding even though its memory relation is consistent.

Validation in this increment consists of source identities, local links and whitespace. Source inspection covers the actual sampler, decoding, NTT and matrix equations and constructors, packing and arithmetic definitions, and the selected ownership and schedule context recorded with this document. No event generator, algebra evaluator, compiler, native test, proof or old program ran. No full source/dependency closure or cryptographic audit is claimed. Original Thorum and upstream attribution and licenses remain unchanged.

Complete private authorization, the [private transition contract](../../docs/private-transition-state.md), confidential stake, authenticated state, recovery, consensus and network activation remain separate requirements. Payments stay private by default, including input commitments, hidden verification keys, paths, amounts and signature intermediates. The [full roadmap](../../docs/delivery-roadmap.md) remains unchanged.
