# Reward origin at a candidate height

This specification makes reward eligibility depend on the exact consuming candidate and its authenticated history. It adds conditional integer consequences and commit recheck requirements to the [private transition state](private-transition-state.md). It implements no origin database, private verifier, fork switch, wallet or accepting node. The origin encoding, complete same witness proof, authenticated atomic ledger and confidential checkpoint bootstrap remain open construction gates.

The existing rule is unchanged: an applicable mining or staking reward needs an age of at least 10080 blocks at the height of the block that consumes it, and its creating transition must belong to actual finalized history. A successful arithmetic comparison alone supplies neither origin authentication nor permission to spend.

## Candidate context and private origin

Let

$$U=2^{64}-1=18446744073709551615,\qquad M=10080.$$

All admitted heights belong to $\{0,\ldots,U\}$. Let $P$ be the authenticated candidate parent, with height $p$. A successor exists only when $p<U$. Its consuming height is

$$H=\operatorname{checkedAdd}(p,1).$$

`H` must agree with the validator derived candidate and the [preseal job context](preseal-job.md). It is not a wallet height, receipt time, peer supplied claim, parent timestamp or elapsed interval. Using $p$ instead would add an unintended block of delay. Using finalized height instead would add an unintended checkpoint delay. At $p=U$ there is no candidate, rather than a wrapped height zero.

Write the protocol eligibility context conceptually as

$$\eta=(\text{network, active rules, verifier/profile context},P,p,H,F,\mathcal R).$$

Here $F$ identifies actual verified finalized history relevant under the selected rules, $f$ is its height, and $\mathcal R$ denotes the authenticated origin and eligibility context those rules require. These are logical roles, not a new byte encoding or root format. The selected protocol must determine the applicable finality identities and evidence. A node's arbitrary locally newest certificate cannot redefine historical block validity. A candidate must remain compatible with the actual finalized prefix used by the fork and commit rules.

For one input, let $C$ be the SAME hidden original note commitment used by the complete private payment relation. Let its conceptual origin record be

$$r=(C_r,\kappa,b_r,h_r,\rho_r),$$

where $\kappa$ is the authenticated creation class, $b_r$ the creating block identity, $h_r$ its authenticated height and $\rho_r$ the applicable creation policy context. A valid creation or issuance transition assigns this record. A wallet, prover or numeric accounting caller cannot choose a convenient class or height.

The required association includes all of the following.

1. The complete private execution uses $C_r=C$, not merely two separately successful membership proofs.
2. The record belongs to actual authenticated creation history and identifies the same creating transition and height.
3. The creating block is an ancestor of or equal to the actual relevant finalized block $F$.
4. The candidate parent is compatible with that finalized prefix and with the authenticated eligible root and active rules.
5. The creation class has a complete applicable policy. Unsupported or unselected policies refuse before an accepting transition.

Neither $h_r\le f$ nor a supplied origin root proves actual ancestry. A mature origin belonging to another note or an orphaned branch cannot be substituted. No origin leaf layout, hash domain, commitment mechanism or membership circuit is selected here. In particular, the logical block identity above does not specify inserting a final creating block hash into a leaf committed by that block's own header.

Input commitment, creation version, origin witness, amount, asset, membership index and path remain hidden as required by the [private transaction boundary](private-transactions.md). Validators must not ask for or log these secrets to perform a host maturity check. The actual complete proof must join origin, age, ownership, authorization, stable nullifier and all other conditions for the SAME input. Its verifier must derive the expected public context from authenticated state. This document supplies no such proof or callback interface.

## Bounded reward age

For the applicable mining and staking reward classes, the age fragment is

$$H\ge h_r,\qquad d=\operatorname{checkedSub}(H,h_r),\qquad d\ge M.$$

The comparison precedes subtraction. The definition uses admitted integers, without modular field wrap, saturation or an unchecked computation of $h_r+M$. If $H<M$, no nonnegative origin height can satisfy the age fragment. Otherwise its numeric part is equivalently $h_r\le H-M$, with that subtraction also guarded.

Over the admitted height domain, a numeric maturity height exists if and only if

$$h_r\le U-M.$$

Forward: any such height has $H\le U$ and $H-h_r\ge M$, hence $h_r\le U-M$. Reverse: under this inequality, the mathematical integer $H=h_r+M$ lies in the admitted domain and satisfies the age equality. This is an existence statement about integers. It constructs no valid block, finalized origin, work witness or acceptance authority. An implementation must still use checked arithmetic rather than evaluating an unguarded sum.

A complete valid consumption of an applicable reward necessarily supplies the same authenticated origin and satisfies this fragment. Conversely, satisfying the displayed inequalities and the same origin association establishes only this origin and age requirement. It does not establish complete private proof soundness, availability, current unspent status, conservation, work validity or commit permission. No accepted proof, extraction or security theorem follows from the algebra alone.

## Local attempts and proof facts

A local validation attempt additionally owns a consistent snapshot and publication generation. Denote its local context by

$$\chi=(g,\text{snapshot/lineage lease},\eta).$$

The generation $g$ belongs to that database owner. It is not serialized in the preseal job, added to network effect bytes or made a public proof input. Independently restarted nodes must not produce different job bytes merely because their local generations differ. Excluding $g$ from those bytes does not allow a stale owner to commit.

The exact verification fact remains the one defined in the state specification:

$$K_{\rm proof}=(\operatorname{Enc}(E),\operatorname{Enc}(A),\operatorname{Enc}(Q),\mathcal V,C_{\rm proof}).$$

It binds the exact effect, proof envelope, validator expected statement, verifier implementation/profile and authenticated proof context actually used. The canonical encodings and implementation compatibility policy still require construction. A mathematical maturity statement, cached Boolean, deserialized success token or independent component result cannot construct proof authority.

A changed local generation invalidates the old attempt's permission to commit. It does not, by itself, require redoing cryptography for an otherwise exact unchanged $K_{\rm proof}$ if the actual implementation compatibility policy permits reuse. Every current state dependent predicate must still be rechecked in a fresh attempt. If a changed parent, height, finality or rule context changes $Q$ or another key member, the old exact proof fact does not cover the new statement. Any reuse must follow the actual selected verification policy, not an inference from numeric permanence.

This distinction never permits a validator to inspect hidden $h_r$, $C$ or paths outside the actual private verification construction. No new cached eligibility token or accepting state interface is introduced.

## Work selection and branch replacement

The [work policy](child-work-policy.md#work-score-and-branch-context) compares cumulative work only between independently completely valid compatible branches. Its score is not a height comparison or permission to override finalized history. Expected targets come from the actual preceding branch state, not from selected sample weights or candidate claims.

Consequently a validator cannot infer nondecreasing candidate height merely from an increased work score. Consider the following conditional state change: if two independently valid compatible branches yield consuming heights $H_A$ and $H_B$, the permitted selection chooses the latter, and $H_B<H_A$, a reward that passed $H_A-h_r\ge M$ need not pass the new comparison. The case $H_A=10180$, $H_B=10179$, $h_r=100$ changes numeric age from 10080 to 10079.

This is a conditional consequence of those heights. No feasible ASERT history, pair of mined branches, production target profile, counterexample or attack is constructed here. In particular, arbitrary score sequences do not demonstrate reachable branch behavior. Shared parents and branch specific target derivation constrain actual histories and cannot be omitted.

On every permitted branch replacement the state owner must perform these operations.

1. Verify complete branch validity and compatibility with actual finalized ancestry before applying the work comparison.
2. Restore the complete authenticated ancestor state and apply the selected ordered effects, including spent identities, notes and origin restrictions, issuance and burns, receipts, required recovery references and policy state.
3. Publish the resulting state with a fresh local generation. Returning to the same logical note root or height does not revive an old attempt or lease.
4. Derive the new candidate parent and checked consuming height. Recheck the exact proof context and all state dependent origin, finality, spentness, policy, resource and availability conditions at serialized commit.
5. Reject stale preparation without partial publication. A new request requires a fresh attempt, rather than a resumed failed transcript or a reset private opening authority.

If a provisional spend is detached, rollback can restore an input's unspent status on the selected branch. That fact alone does not restore a previously cached permission to spend it. Its actual current origin and candidate conditions still govern. A forbidden finalized rollback is refused, not handled by weakening reward maturity.

## Conditional permanence under a fixed finalized prefix

The following lemmas concern the numeric age only. Assume the SAME fixed maturity rule, an actual authenticated reward origin, its creating block in the verified finalized prefix ending at $F$, and $f\ge h_r$. Write

$$a=\operatorname{checkedSub}(f,h_r).$$

Let an existing compatible candidate have parent height $p\ge f$, with $p<U$, and let $H=p+1$. Over mathematical integers,

$$H-h_r=(p-f)+a+1.$$

Both terms $p-f$ and $a$ are nonnegative. The total equals the admitted difference $H-h_r\le U$, so the proof needs no overflowing intermediate or field reduction.

1. **Conservative sufficient condition.** If $a\ge10080$, every such existing candidate satisfies the numeric reward age. This does not make finalized height the consuming height.
2. **Sharper sufficient condition for the next candidate.** If $a\ge10079$, the extra successor step gives $H-h_r\ge10080$. The reward delay is still 10080. The number 10079 describes the age of the finalized prefix in this lemma, not a new spending threshold.

These are sufficient conditions, not necessary conditions or an additional checkpoint delay. A concrete candidate can satisfy the actual $H$ rule before either finalized age bound holds, provided actual creating history and every other condition are valid. At $f=U$ no admitted parent has a successor. This is a state with no candidate, not vacuous permission to spend.

The lemma assumes actual compatibility with the finalized prefix, fixed rules and a valid candidate height. It supplies no certificate, origin construction, future block existence, privacy guarantee, proof cache reuse or current unspent fact. A rule change or finality conflict requires its separate actual validation. The bound cannot authorize a wallet, host callback or database token to accept a spend.

## Distinct creation and spending policies

A valid mature reward consumed into ordinary payment outputs does not restart the reward delay. The ordinary outputs still require the initial finality of the creating transition rule and complete private authorization before onward spending. This distinction cannot be used to transfer an immature right into an apparently ordinary change, application, asset, migration or stake registration output.

Staking principal and its bonding, unlocking and penalty conditions are separate from a staking reward. Height units here do not replace epoch or policy conditions. Pool and development credits count as issued at legitimate creation under the [allocation rules](subsidy-allocation.md), but their spending and maturity policies remain separate open constructions. This document does not classify them as ordinary payments or mining/staking rewards by default. An unselected policy supplies no fallback authority.

Issuance, origin authentication, finality, numeric age and current spendability remain distinct facts. A valid numeric amount, a block budget quote or a restored accounting total authenticates none of the missing facts.

## Specification cases

These are independently inspectable integer literals and state requirements, not executed validator tests, a state machine run or valid mined fixtures. Numeric success means only the age fragment under its stated premises.

| Case | Parent $p$ | Origin $h_r$ | Candidate $H$ | Required numeric result |
|---|---:|---:|---:|---|
| One block early |10178|100|10179|Age 10079, refuse |
| Exact age |10179|100|10180|Age 10080, other checks still required |
| Future origin |98|100|99|Refuse before subtraction |
| Creation height |99|100|100|Age 0, refuse |
| Exhausted parent |18446744073709551615|100|None|Refuse successor construction |
| Last possible mature height |18446744073709551614|18446744073709541535|18446744073709551615|Age 10080, other checks still required |
| Origin too late |18446744073709551614|18446744073709541536|18446744073709551615|Age 10079, no later admitted height |

For $h_r=100$, finalized heights 10179 and 10180 give the sharper and conservative sufficient bounds respectively. Height 10178 alone gives neither bound: the algebraic minimum parent $p=f$ yields age 10079. This does not assert an accepted chain with that parent exists. A finalized height of $U$ gives no candidate.

| State case | Required boundary |
|---|---|
| A mature origin belongs to another hidden commitment | The SAME input association fails |
| An orphaned creating block has a numerically small height | Numeric order cannot replace authenticated ancestry |
| Required finality or origin evidence is absent at bootstrap | Refuse, without elapsed time or claimed root fallback |
| Conditional valid branch change lowers $H$ across the age boundary | Reevaluate the actual expected context and private age condition |
| Old root and height reappear with a new generation | Prior commit permission stays stale |
| Local generation changes but exact proof key does not | Current commit recheck remains mandatory, cryptographic reuse follows only actual compatibility policy |
| Provisional spend rolls back and input becomes unspent | Reevaluate all current conditions, not an old maturity flag |
| Ordinary output follows valid mature reward consumption | No new reward delay, finality of the creating transition still applies |
| Principal or pool/developer input has no applicable complete policy | No classification or permission from this reward age rule |

## Evidence and implementation gate

The [source record](../research/reward-origin-eligibility/source-record.json) pins eight local contexts at the stated baseline revision. The work arithmetic accepts unverified numeric context. The core and paired accounting components explicitly delegate history, origin and commit authority. Their behavior is inspected as source, not executed here. The two linked policy documents receive explanatory links only. Their baseline hashes remain specific to the baseline revisions rather than describing later worktree bytes.

This increment supplies specifications and conditional integer arguments only. It changes no Rust source, original note or nullifier encoding, hash domain, root version, work rule, subsidy schedule or allocation, resource class or consensus activation. No new origin representation, proof backend or accepting ledger is adopted.

Before implementation can accept any reward, the complete authenticated encoding of creation origin and availability, SAME private cash relation, real validator expected verification, canonical bounded parser, work and checkpoint/bootstrap validity, atomic state publication and recovery, witness privacy and practical recipient completion, resources and independent validation must be supplied. A numeric permanence proof does not close any of those gates. Local multinode experiments, an independent operator testnet and public release retain their separate actual requirements.
