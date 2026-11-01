# Confidential stake lifecycle and bootstrap boundary

This specification defines the required ownership, eligibility and state connections for confidential checkpoint stake. It introduces no accepting stake verifier, certificate, signer or node. Complete private payment and confidential stake feasibility remain prerequisites for the [ledger and consensus stage](delivery-roadmap.md). The initial spending boundary remains checkpoint finality. Safe, fast locks, governance execution and Aegis keep their separate activation gates.

## Existing source and construction decision

The [transparent stake checker](../crates/thorum-relation-lab/src/stake.rs) directly receives bond openings, nullifier secrets, paths, voting keys and signatures. Its caller supplies snapshot trust, spent bonds, used votes and duty meaning. Individual weight and voting key bindings are public in that laboratory statement. The checker returns a sum without changing any set. It is neither confidential eligibility nor an authenticated stake registry.

The retained [bond note policy](../crates/thorum-relation-lab/src/note.rs) commits a separate voting key and activation, maturity and exclusive unlock epochs. Its constructor checks ordering, and its opening rejects an identical owner and voting key binding. The [ordinary payment checker](../crates/thorum-relation-lab/src/payment.rs) rejects bond inputs and binds output policies through complete note commitments and encrypted delivery. These source properties do not implement registration, reward origin, withdrawal or current snapshot authentication.

The normal lifecycle construction below uses **consumed inputs and newly created bond rights**. Registration is not a second registry entry laid over an otherwise spendable note. Its complete private transition consumes the original input identities and creates restricted bond outputs with conserved native value. A later authorized retirement and withdrawal consumes the bond right before creating ordinary spendable outputs. This is a specification decision. The complete relation, registry update proof, encodings and consensus implementation remain open.

The separate [owner binding](../crates/thorum-owner-binding-proof-lab/src/lib.rs) and [nullifier](../crates/thorum-nullifier-proof-lab/src/lib.rs) proofs do not establish voting permission or this lifecycle. The [signature overlay](../research/signature-overlay/src/lib.rs) derives its 196 public bytes from a `PaymentStatement` through its actual [authorization mapping](../research/signature-complete-native/src/authorization.rs). It has no stake statement adapter or complete hiding signature proof. A supplied stake digest, public key or collection of component successes cannot replace the required same-witness relation.

## Expected context and confidential statement

For epoch $e$, validators obtain a consistent authenticated context

$$C_e=(\text{network},\text{rules},\text{relation},\text{profile},\text{resource class},e,
\text{epoch lineage},\text{eligible state},\text{duty rules},\text{activation state}).$$

These are semantic fields, not a selected wire format. The epoch and eligible state come from the active consensus rules. A proposer cannot choose a convenient root, denominator or verifier profile. A registration, vote or certificate must bind its exact operation, context and effect. Unsupported identities refuse before proof work.

| Operation | Required public or validator owned context | Same private witness connections |
|---|---|---|
| Registration | Eligible input anchor, stable input nullifiers, ordered outputs, delivery binding, fee and active rules | Native values, valid origin and maturity, same note owner and actual authorization, conserved bond and change outputs |
| Epoch eligibility | Authenticated active position snapshot and epoch transition | Registered bond membership, private principal and restrictions, committed voting authority and eligibility interval |
| Checkpoint vote | Canonical conflict slot, exact proposal decision, epoch context and allowed message phase | Same active position and weight, authorized restricted key and actual signature over that vote |
| Certificate | Exact decision, phase/round evidence, snapshot context and bounded contribution/tally evidence | Correct distinct contribution weights and complete eligible denominator under the selected confidential construction |
| Retirement or rotation | Authorized lifecycle effect and its current state dependencies | Owner authority, old right and successor connection, outstanding duty and lock obligations |
| Withdrawal | Accepted retirement, release conditions, stable bond consumption, outputs and recovery data | Same principal, owner authorization, conservation, retained policy and authenticated origin restrictions |

Input commitments, creation versions, indices, paths, amounts, owner keys, signatures and their intermediates remain private. A registry may expose necessary roots and protocol metadata, but it must not turn a private note into a public input identity merely to test eligibility. Public output commitments and ordinary stable nullifiers retain their existing metadata analysis. Per-position weight disclosure in the transparent reference does not select the confidential protocol's public surface.

Voting authority can be delegated to an online service without the owner signing each vote. The registration transition must first bind that authority using the real owner permission. Subsequent eligibility proves the same registered policy and a valid restricted vote signature. The owner spending key stays outside the voting service. Any note information or nullifier material deliberately supplied to that service needs an explicit capability and leakage analysis. Restricted authority cannot redirect principal or rewards, mint assets, alter policy, execute a grant, or sign arbitrary wallet requests.

## Principal lifecycle and atomic state

The stake portion of the [unified state](private-transition-state.md) must distinguish pending bonds, active epoch positions, retirement and release obligations, used contributions and reward rights. Their exact authenticated representation remains unselected. A root label alone does not establish these properties.

| State | Permitted effect | Required exclusion |
|---|---|---|
| Eligible ordinary input | Authorized registration consumes its original stable identity | The same input cannot also fund a payment or another bond |
| Pending bond | Wait for the active rule's origin, maturity, activation and finality conditions | Inclusion alone grants neither active weight nor unrestricted spending |
| Active bond | Supply permitted epoch duties from the fixed eligible snapshot | Principal cannot be spent or copied into an additional active descendant |
| Retiring bond | Stop future eligibility at the defined epoch boundary and satisfy outstanding obligations | A withdrawal request cannot erase authority already counted for an active epoch |
| Released bond right | Owner authorized withdrawal consumes it and creates conserved ordinary outputs | Release does not mint value or reset an existing consumption identity |
| Consumed bond right | Retain the required spent identity and historical evidence | Reopening an old snapshot cannot reactivate it on the selected current lineage |

Registration and an ordinary payment competing for the same input use the same existing input consumption identity. A separate registration index is not an alternative nullifier namespace that lets both succeed. Validation stages effects against a consistent parent and atomically rechecks input absence, policy, snapshot generation and output/delivery availability at commit. At most one competing transition can extend that state. Registration changes the ownership form of existing value, not cumulative issuance.

An active position tree or equivalent authenticated construction must prove that its membership reflects valid, still restricted bond rights. Membership under an arbitrary historical note root is insufficient. A future construction that needs private nonmembership in a spent set must implement that relation; a host lookup with a claimed result is not its proof. The active snapshot must exclude spent ancestors and conflicting descendants rather than rely on an unproved caller set.

An epoch snapshot fixes the eligible positions and applicable policy for its permitted duties. A later withdrawal cannot retroactively make an earlier valid vote invalid or release principal while that authority still counts. Retirement, rotation and handover need deterministic boundaries before implementation. Replacing an online key must not produce two usable authorities for the same position and conflict slot. The old and new position relationship must be enforced through the actual state transition, not hidden by a new commitment or key identifier.

Governance locks, reward restrictions and any later Safe or migration conditions compose with the bond lifecycle. A different operation type cannot discard an outstanding restriction. Exact withdrawal delays, penalties, delegation changes, floor, epoch lengths and key rotation rules are still open selections. An unsupported transition refuses.

## Weight, quorum and consumption identities

For the chosen linear atomic stake policy, each eligible position $b$ has positive native principal $v_b$ and weight $w_b=v_b$. All values and sums require range constraints and checked integer arithmetic. For a partition of the same eligible principal,

$$\sum_i v_i=v\quad\Longrightarrow\quad\sum_i w_i=w(v)=v.$$

An address, key, registration count or rounding per position grants no extra weight. The active snapshot must be formed from nonoverlapping conserved rights. Linear arithmetic does not by itself establish that absence of overlap.

Let $B_e$ be the complete eligible snapshot and $J$ the distinct positions contributing to a certificate. Required quantities are

$$W_e=\sum_{b\in B_e}v_b,\qquad P_J=\sum_{b\in J}v_b,\qquad J\subseteq B_e.$$

Both the numerator and the complete denominator require authenticated, correctly weighted evidence. Proofs for a convenient subset do not establish $W_e$. How to prove those sums while hiding individual principal, and which aggregate information is disclosed, remain construction questions. A public claimed total or a sum of opaque hashes is insufficient.

A selected quorum rule could compare $P_Jq_{\rm den}$ with $W_eq_{\rm num}$ using bounded widened integers, with $W_e>0$ and an explicitly fixed equality rule. No numerical threshold, round protocol, randomness scheme or safety/liveness theorem is selected here. A threshold equation alone does not prove checkpoint safety or independent validator agreement. Missing quorum does not activate a weaker mode.

The following identities have different purposes:

1. A stable note nullifier consumes an existing right. Changing its root, requester, current software version or application cannot reset it. A wrong network request refuses.
2. Registration deduplication follows the actual input consumption and creation of the new bond right. An index can help locate records but grants no new spending authority.
3. A contribution identity prevents counting the same bond twice in one authenticated conflict slot. Owner and delegate, alternate signatures and relay copies must agree on that identity. The slot definition must identify the actual protocol duty and its conflict class. It cannot be chosen separately by a requester.
4. A duty reward identity prevents issuing the same earned entitlement twice. Voting again in a legitimate later round is not automatically an additional reward.

A conflicting decision must not obtain a fresh contribution identity merely by changing proposal bytes, relay identifier, voting key or an untrusted snapshot label. Legitimate phases and rounds need their exact conflict and locking rules; one blanket vote per epoch would also reject valid multi-round protocols. Domain separation and cryptographic derivations remain unselected. The retained transparent vote nullifier binds the immutable note, network, epoch and duty, while omitting the current requester key and snapshot anchor. Its caller must still authenticate the duty and snapshot.

Transport replay of an identical valid message can be idempotent. It contributes weight once and earns a reward at most once. Verifying an already known certificate is not itself a second state transition. Conflicting messages require the selected accountability and round rules rather than silently adding both weights. Required unlinkability across unrelated duties and epochs, deliberate linkage within conflict evidence, and leakage from public aggregates need a joint privacy analysis. No current nullifier formula establishes that analysis.

## Signing, branch changes and rewards

A signer must validate the actual context and proposal before producing a restricted vote. Its durable intent must bind the conflict slot, decision, epoch authority and required prior lock. A ledger reorganization must not erase the signer's knowledge that it already signed a conflicting message. Branch state recovery and signer anti-equivocation recovery are distinct state domains. Restoring a wallet backup on two devices does not grant two copies of a voting right or provide safe coordination.

The [bounded byte journal](../research/state-journal/README.md) does not implement this signer. It lacks authenticated history, rollback protection and a power loss durability protocol. No cryptographic signing step is authorized by its successful synthetic restart test. Persistent signer construction and independent restored-device controls are required before an online service.

Ordinary validators independently check private transactions, work, state and certificates. Stake support cannot legitimize an invalid transaction, missing payload or unsupported profile. A provisional branch change restores the entire ledger state and replays the selected branch consistently. The normal rules cannot roll back finalized history. Epoch handover must bind its predecessor and successor snapshot, completeness and availability. An old epoch vote cannot be relabeled as support under a new denominator.

Duty evidence must bind the permitted role, epoch, slot, decision and accepted block context. A checkpoint vote is not a grant ballot or general spending signature. Neither voting capability nor a governance turnout label proves an earned checkpoint reward.

For the [current subsidy accounting](subsidy-allocation.md), the actual earned amount $e_h$ must be proven and consumed once before the kernel calls `SupplyState::issue_block`:

$$0\le e_h\le K_h,\qquad K_h=\left\lfloor 2S_h/10\right\rfloor.$$

The budget is recomputed from the current staged supply and valid height. Unearned stake remains unissued and creates no later catch-up right. Principal registration, retirement and withdrawal transfer existing value. Rewards are separate newly issued rights with their own authenticated origin and 10080 block maturity under the development target. Maturity cannot be backdated by registration and cannot be confused with principal unbonding. Pool and development credits retain their distinct issuance and spending policies.

## First activation and the bootstrap dependency

The current requirements combine no premine, no genesis subsidy, a separate reward maturity, eligible stake before checkpoint activation, and finalized creating history before normal consumption. If first registration requires an already stake-finalized reward, while the first stake finality requires that registration, increasing work height alone cannot satisfy the missing finality prerequisite. This is a conditional specification dependency. There is no running activation process or observed network deadlock.

The construction decision is to keep **normal registration subject to the full finality and maturity rules**, and keep first activation blocked until a separately versioned bootstrap rule resolves this dependency. No automatic exception is introduced by this document.

| Candidate boundary | Consequence | Remaining obligation |
|---|---|---|
| Apply normal finality eligibility to every first registration with no separate bootstrap | No first eligible stake follows from immature or merely mined rewards | The dependency remains unsatisfied |
| Explicit preactivation rule permitting only restricted registration from valid mature work-origin rights | Could form provisional bond state without authorizing ordinary onward payments | Complete work-history trust, private authorization, origin, fork handling, anti-grinding, eligible-set completeness and first-certificate safety construction |
| Synthetic initialized stake fixture | Can support a separately reviewed laboratory experiment | It is not a no-premine distribution, production genesis or activation rule |

The restricted registration candidate is an unresolved design option. It does not select a PoW confirmation depth, trust theorem, deadline, allocation change, administrator or certificate threshold. Any selected rule must bind one exact bootstrap lineage, full state and payload availability, mature issuance origins, eligible registration set and activation effect. Valid work alone is not a private ownership proof or stake certificate. Separate branches cannot treat conflicting provisional registrations as one globally final distribution.

Until an activation rule is established, no service reports stake finality, grants duties to fabricated stake or issues unearned stake rewards. The first certificate must not be considered trustworthy merely because its signers claim the very snapshot it is supposed to authenticate. The source of initial trust, adversary assumptions, unavailable or zero eligible stake, conflicting first certificates and transition into normal epoch rules require independent review.

An eventual accepted activation must be an atomic one-time state transition under its selected version. It cannot reset old note identities, duplicate principal, mint bootstrap stake, erase restrictions or authorize ordinary payments retroactively without the actual rule. Process restart, a local cache, elapsed time or a wallet label cannot activate it. The retained 120 second monetary reference and 60 second target remain separate versioned profiles.

## Required adversarial evidence

These are required future cases, not executed tests or verified properties of a new implementation.

| Case | Required result |
|---|---|
| Registration and payment consume the same note | Only one valid ordered transition commits |
| Two registrations or owner and delegate reuse one principal | No additional active value or contribution |
| Split principal or many keys | Aggregate eligible weight does not increase |
| Mutated weight or incomplete denominator | Refuse the certificate or tally evidence |
| Voting key from another bond or copied permission | Same registered private policy must authorize the exact vote |
| Network, epoch, snapshot or profile substitution | Refuse despite an isolated valid signature |
| Repeated relay message or repeated certificate verification | Idempotent observation, no duplicate contribution or reward |
| Two conflicting decisions change proposal bytes or relay ID | Same conflict accounting and selected accountability rules apply |
| Rotation creates two live authorities for one slot | Refuse the inconsistent handover |
| Withdrawal races a still-active epoch or governance lock | Principal remains restricted until all applicable obligations release |
| Old snapshot and active descendant both counted | Refuse overlapping principal |
| Unfinalized reorganization | Restore coherent state, retaining independent signer safety obligations |
| Finalized rollback or restored signer loses prior intent | Refuse unsupported recovery or signing, without silently weakening safety |
| Duplicate duty, reward or later catch-up claim | No extra issuance |
| Immature or forged reward origin enters a bond | Refuse every registration or wrapping path |
| Bootstrap has zero eligible stake, unavailable data or competing activation | Remain unactivated without fallback finality |
| Ineligible or incomplete first snapshot signs its own claimed validity | No self-asserted activation authority |
| Alternate wallet, migration, contract or later application strips restrictions | Preserve consumption, origin and policy rules |

## Remaining implementation gate

The next construction must select an exact bootstrap predicate and authenticated eligible-set transition compatible with the consumed bond lifecycle, or demonstrate a precise unresolved dependency. It must then establish the complete confidential relation, aggregate/denominator proof, canonical statement, real signature constraints, certificate rounds, resource feasibility, joint hiding and transcript security, and durable signer/ledger integration. No classical VRF, aggregate signature, replacement authorization primitive or weaker profile is selected.

The existing full signature resource refusal remains in force. Compact native source construction, metadata, component proofs and the journal do not admit full stake proving. No compiler, model, native witness, prover, verifier, RNG, signing service or network operation executes for this specification increment. The [source record](../research/confidential-stake/source-record.json) identifies the reviewed implementation and historical context. Private payments remain mandatory by default throughout the full roadmap.
