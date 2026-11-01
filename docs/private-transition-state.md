# Private transition context and atomic acceptance

This specification defines the semantic boundary between a complete private transition and authenticated ledger state. It implements no verifier, database, consensus service or network node. Complete private authorization and confidential stake feasibility remain prerequisites in the [delivery sequence](delivery-roadmap.md). Missing proof, policy or consensus constructions must produce refusal rather than a reduced acceptance path.

## Existing source boundaries

The [monetary core](../crates/thorum-core/src/accounting.rs) checks bounded issuance and burns and assigns its counters after successful arithmetic. Its callers must authenticate height, earned stake and destinations. It supplies no note, root, spent set, replay protection or durable branch history.

The [transparent payment checker](../crates/thorum-relation-lab/src/payment.rs) receives private witnesses and caller supplied anchors and spent sets. Its canonical statement binds output commitments and every encrypted envelope byte. Its [stake counterpart](../crates/thorum-relation-lab/src/stake.rs) similarly leaves snapshot authentication and set freshness to its caller. Neither mutates a ledger or supplies a private acceptance API.

The [owner binding component](../crates/thorum-owner-binding-proof-lab/src/lib.rs) and [nullifier component](../crates/thorum-nullifier-proof-lab/src/lib.rs) verify against caller provided expected statements and fixed profiles. Their public encoders bind fee, chain, output creation versions, asset, root, outputs, nullifiers and context. These isolated statements neither authenticate root eligibility nor implement global consumption. Public assets and their eight MiB component bounds do not select production visibility or resource limits.

The [signature overlay](../research/signature-overlay/src/lib.rs) derives its 196 public authorization bytes from the exact transparent transaction through the retained [public preprocessing](../research/signature-complete-native/src/authorization.rs). Its native witness boundary is separate from a complete private payment proof. The [full proof feasibility decision](../research/overlay-composition/transport-feasibility.md) remains an architectural refusal. Joining component successes cannot implement the transition below.

## Authenticated state and expected context

Let one consistent ledger snapshot be

$$S_v=(v,C_v,F_v,R_v,N_v,A_v,P_v,G_v,I_v,B_v,D_v,T_v).$$

| Element | Required meaning |
|---|---|
| $v$ | Unique durable publication generation and lineage identity, including parent and ordered block context |
| $C_v$ | Authenticated network, active rule set, relation and resource profiles and activation context |
| $F_v$ | Verified checkpoint and finalized history context |
| $R_v$ | Authenticated anchor history with branch, origin, version and eligibility policy |
| $N_v$ | Consumed stable note identities on this branch |
| $A_v$ | Ordered output commitments and authenticated origin and restriction metadata |
| $P_v$ | Asset, application and spending policy state or its authenticated commitments |
| $G_v$ | Stake registration, duties and used reward or vote rights under the active construction |
| $I_v,B_v$ | Cumulative actual issuance and completed burns |
| $D_v$ | Binding and retention context for encrypted recovery data and other required payloads |
| $T_v$ | Inclusion receipts, ordered effects and durable recovery context |

This tuple defines one logical state, not a chosen encoding or a requirement to publish private balances. Its root representations, snapshot authentication and durable storage engine remain open choices. `SupplyState::new` validates monetary totals and cannot authenticate this tuple.

The validator derives an expected public statement $Q$ from the canonical transaction effect $E$, its own selected profile and authenticated context. A transaction may request an anchor or supported class. It cannot select arbitrary verifier parameters, trust its own root or declare itself cheap. Unknown rule, relation, resource or activation identities refuse before cryptographic work.

| Boundary | Public or verifier owned data | Private witness data |
|---|---|---|
| Protocol context | Network, active rules, relation and profile identity, validity and authenticated anchor context | Private ownership material remains outside context construction |
| Inputs | Anchor reference, stable nullifiers and explicitly required public restrictions | Input commitments, creation versions, indices, paths, note openings and origin witnesses |
| Authorization | Exact effect binding and complete proof | Same note owner, verification key, signature and constrained intermediates |
| Conservation and policy | Explicit public fee or policy information and committed execution effects | Values, assets and policy state to the extent required to remain confidential |
| Outputs and recovery | Ordered output commitments and bound encrypted delivery | Same output openings, recipient material and encryption witness |

The production public surface requires a separate versioned encoding and privacy review. Earlier component disclosure does not make that field public here. Input restrictions, including authenticated reward origin, must be constrained without revealing the selected commitment or private path. An eligible historical root does not by itself prove that every note beneath it is mature or authorized.

## Effect, authorization and verification facts

Let $E$ contain the canonical effecting fields, including its declared protocol context, anchor reference, ordered nullifiers, output and encrypted delivery bindings, fee and supported policy effects. Let $A$ contain the complete published proof and validation envelope. Private signature witnesses and keys are not public authorizing bytes.

An effect identifier is not an authorization result. The signed or proved effect must not depend cyclically on the bytes of its own proof. The actual profile defines which context and effect fields enter authorization. A different proof for the same effect requires its own bounded decoding, canonicality and verification unless an exact matching verification fact exists.

Define the conceptual verification cache key by exact equality of

$$K_{\rm proof}=(\operatorname{Enc}(E),\operatorname{Enc}(A),\operatorname{Enc}(Q),\mathcal V,C_{\rm proof}).$$

Here $\mathcal V$ identifies the validator selected relation, verifier implementation and complete profile, and $C_{\rm proof}$ contains every authenticated context value actually used to derive or check $Q$. `Enc` denotes the eventual canonical encoding, not an implemented codec. Any digest representation requires explicit framing and collision assumptions. A transaction ID, profile label or supplied digest alone cannot replace these bytes and identities.

A cached fact states only that the exact proof was checked against the exact statement and verifier context. Current permission to commit also depends on $S_v$, block ordering, root eligibility, nullifier absence, policy, resources and availability. That permission expires when its state context changes. Proof facts with identical keys may be reused under their implementation compatibility policy, but every state dependent predicate must be rechecked. Changed statement or verifier context requires a new proof check.

Only the actual validator verification path may construct an internal proof fact. An external Boolean, deserialized success token, host callback or independent component result is not proof authority. Crossing a process boundary requires authenticated source bytes and the applicable verification, not trust in a claimed success. No such accepting interface is implemented by this specification.

## Ordered acceptance lifetime

| Stage | Required operation | Consensus effect |
|---|---|---|
| Admission | Bound transport, decoding, canonical structure, supported versions and deterministic resource class | None |
| Snapshot | Obtain consistent $S_v$ and authenticated candidate block, height and checkpoint context | None |
| Statement | Resolve anchor eligibility and selected verifier, then derive $Q$ from exact effect and context | None |
| Verification | Perform complete private proof and applicable independent work, stake and consensus checks | None |
| Preparation | Stage ordered effects, encrypted payloads and checked monetary deltas against the candidate parent | None visible to readers |
| Recheck | Serialize the commit decision and recheck snapshot identity and all state dependent predicates | None if any predicate fails |
| Durable commit | Atomically publish the complete next state and its recoverable commit decision | One branch transition |
| Receipt | Acknowledge the exact durable state and effect identity | Inclusion, separately from finality or spendability |

Relay or mempool reservations are local scheduling aids. They grant no consumption right and cannot indefinitely freeze a note through unauthenticated messages. Resource credits consumed by decoding or cryptographic work are not restored by a failed ledger commit. No aborted proving transcript is resumed.

Preparation must evaluate transactions in deterministic block order against a staged view of the candidate parent's state. It rejects duplicate nullifiers within a transaction and between transactions in the same block. It also enforces active policy, resource totals, restrictions and deterministic output ordering. The initial rule does not allow onward spending of unfinalized newly created outputs.

At commit, the candidate parent and snapshot must still match the state being extended. Check the current active rule and activation context, checkpoint ancestry, anchor eligibility, validity conditions, spent identities, duty or reward consumption, policy versions, resource totals, monetary limits and required payload availability. Arithmetic uses the current staged totals rather than an earlier budget quote. A stale snapshot restarts state validation. It does not silently overwrite a newer root or spent set.

Publication generation is distinct from a note root or block height. Returning to an ancestor's logical contents during rollback must not make a stale attempt's generation current again. The journal and restart protocol must preserve this identity boundary.

Each attempt retains its first actual error and stage. Cleanup cannot replace that cause with a generic failure. A refused attempt discards its staged delta and is terminal. A later request requires a new attempt and current state checks, without resuming a failed proving transcript or resetting private opening authority. Cleanup releases only resources owned by that attempt and cannot remove another owner's files or data.

For nullifiers $U$ and ordered outputs $O$, necessary conditions include

$$|U|=|\operatorname{set}(U)|,\qquad \operatorname{set}(U)\cap N_v=\varnothing,$$

$$N_{v+1}=N_v\cup\operatorname{set}(U),\qquad A_{v+1}=\operatorname{Append}(A_v,O).$$

These equations are consequences of complete authorization and eligibility checks, not substitutes for them. Stable nullifier derivation uses the original committed note and its protocol domain. A new anchor, current version, request network or application must not rename the same old consumption right. A request for the wrong network refuses. Migration consumes the old identity exactly once before creating new rights.

## Monetary rights, origin and restrictions

For each asset $a$, the same private execution must establish

$$\sum\operatorname{inputs}_a+\operatorname{authorizedMint}_a=
\sum\operatorname{outputs}_a+\operatorname{burn}_a+\operatorname{fee}_a.$$

Ordinary payments cannot mint native value. Fees are existing value transferred or destroyed only under the explicit fee policy. They do not constitute fresh subsidy. The policy must account for fee rights and their eventual destination without a second issuance. Production fee allocation remains open.

The separate issuance path authenticates block origin, eligible earned duties, destination credits and duplicate reward prevention before using the [60/20/10/10 accounting rule](subsidy-allocation.md). For actual newly issued value $J$ and completed burn $b$,

$$I_{v+1}=I_v+J,\quad B_{v+1}=B_v+b,\quad 0\le B_{v+1}\le I_{v+1}\le C.$$

The complete ownership state must account for $I_{v+1}-B_{v+1}$. Unearned staking stays unissued. Pool and development credits count as issued at legitimate creation and cannot be issued again when later spent. Their destinations and spending authority need complete policies. Restricted voting authority cannot authorize spending or establish that a reward was earned.

The retained executable schedule remains at 120 seconds. The [60 second target and origin rules](protocol-extensions.md#reward-origin-and-maturity) need their own versioned transition and vectors. Mining and staking rewards require authenticated origin $h_r$, bounded comparison $h\ge h_r$ and $h-h_r\ge10080$ under that target. Creating history must also satisfy the initial checkpoint finality rule. Ordinary later payments do not restart a reward delay. Applications, stake registration and migration cannot erase an immature origin or other restriction.

## Durable state, restart and branch changes

The atomic unit includes nullifiers, notes and metadata, policy and stake changes, supply counters, encrypted data references, receipts and the state lineage they describe. A prepared record alone is not a durable accepted state. Readers observe one complete published snapshot, and a receipt follows its durability point.

Required encrypted data must be bounded, content bound, available and recoverable before the commit can acknowledge its creation. Staged payloads can precede the state commit, but the retention protocol must distinguish unreferenced preparation from durable live data. It cannot remove the only recovery source after a crash or prune it merely because a proof remains valid. A root or descriptor is not evidence that underlying bytes remain available.

The storage design must recover either the complete prior state or the complete committed successor after every interruption. Ambiguous, corrupt or incomplete durable evidence refuses service pending verified recovery. Independently restoring monetary totals, spent sets and note roots is forbidden. Commit markers, flush order, checksums, atomic publication, concurrency and supported filesystem guarantees require a concrete storage design and tests.

Nullifiers accumulate along a valid branch. Replacing an unfinalized branch restores its complete authenticated ancestor state and applies the winning branch in order. It does not selectively clear a nullifier or apply issuance twice. Competing unfinalized branches can contain conflicting candidates, but only the selected valid history determines current state. Finalized history cannot be reverted under ordinary fork handling. A losing branch's receipts and output eligibility must change consistently with its rollback. Relabeling a root or switching software versions cannot simulate a legitimate branch change.

Checkpoint support cannot authorize an invalid private transition. Before confidential stake bootstrap and certificate construction are complete, no service may report stake finality. Safe, fast locks, contracts and later Aegis retain their separate [delivery gates](delivery-roadmap.md). An activation requires the complete applicable state and authorization rules, not a wallet label or a cached acceptance record.

## Required failure and recovery cases

These are specification requirements, not executed tests.

| Case | Required result |
|---|---|
| Same effect, altered proof or public envelope | Exact cache key changes and actual verification is required |
| Same proof, altered expected statement or profile | Prior proof fact is unusable |
| Two submissions verified against one snapshot spend the same nullifier | At most one commit, the other fails current state recheck |
| Duplicate input within one transaction or ordered block | Entire invalid transition refuses without partial publication |
| Snapshot changes while verification runs | No stale commit, rederive and recheck state dependent predicates |
| A previous note root reappears after rollback | Old attempt generation remains stale |
| Anchor from another network, orphaned branch or ineligible history | Refuse despite a valid isolated membership proof |
| Correct note commitment with immature or unfinalized origin | Refuse every supported consumption path |
| Missing, altered or unretained encrypted delivery | No acknowledged creation without the required recovery data |
| Failure after staging data but before commit | Prior state remains visible, orphan preparation follows explicit cleanup policy |
| Storage fails and cleanup also encounters an error | Preserve the original typed cause and affect only owned resources |
| Crash at or after commit decision | Recover one complete state and consistent receipts, never mixed counters and roots |
| Repeated issuance, restored duty or reused reward evidence | Reject duplicate credit and preserve cumulative accounting |
| Unfinalized reorganization | Restore all ancestor components and replay winning effects once |
| Attempted finalized rollback or unsupported upgrade | Refuse outside a separately specified authorized transition |
| Alternate client, migration or application renames an old nullifier | Preserve the original consumption identity and restriction |

## Open construction and implementation gates

The exact canonical envelope, AIR and profile registry, root history window and eligibility evidence, private reward origin encoding, commitment and hash domains, data retention protocol, database transaction mechanism, consensus bootstrap and certificate rules remain unresolved. Production asset visibility, fees, limits and activation policies also require explicit selection. These omissions block accepting implementation, rather than supplying defaults.

A first independent implementation task may develop bounded snapshot and journal mechanics with public synthetic state bytes. It must test actual storage failure and commit ownership without accepting a caller supplied proof verdict or claiming payment authorization. Complete private verification and stake construction must later be integrated through their real checked paths. Any such execution needs its own source and resource review.

The [snapshot journal source review](snapshot-journal.md) develops a bounded publication candidate and identifies the remaining writable recovery ownership gap. Its proposed controls have not executed, and no journal implementation or accepting state transition is supplied by that review.

This increment changes specifications and [source identities](../research/private-transition/source-record.json) only. It executes no cryptographic component, state machine model, compiler, native witness, proof producer, verifier or old test. Source review and documentation checks establish neither a working blockchain nor composed security. The [private transaction requirements](private-transactions.md) and all unresolved hiding, transcript, repeated observation, knowledge and quantum obligations remain applicable.
