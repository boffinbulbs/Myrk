# Prospective child work policy

This document selects a prospective integer ASERT policy for research at the 60 second child work target. One finite [integer reference](../research/child-work-policy/README.md) checks its arithmetic and numeric timestamp rules. It implements no authenticated history, native node, auxiliary verifier, private transaction acceptance or consensus activation. A production genesis, initial target, easiest target, descriptor registry and actual clock service remain unselected.

The child threshold belongs to the validator's expected context. It cannot be adopted from a candidate job or parent header. The [auxiliary construction](../research/auxiliary-construction/README.md) still requires separate parent template policy, child threshold and any numeric parent winning comparison. Ordinary validators are not implicitly required to run a parent full node.

## Selected research parameters

| Parameter | Prospective rule |
|---|---|
| Work interval `S` | 60 seconds |
| ASERT half life `H` | 172800 seconds |
| Fixed point radix `R` | 65536 |
| Height and timestamp contents | Unsigned 64 bit integers, seconds for time |
| Child target | Positive unsigned 256 bit integer, exact 32 byte little endian contents |
| Initial target `T_initial` | Mandatory authenticated descriptor value, not selected |
| Easiest target `L` | Mandatory authenticated descriptor value, not selected, `1 <= T_initial <= L < 2^256` |
| First work block | Height one, expected target exactly `T_initial` |
| ASERT anchor | The actual first valid work block on the selected lineage |
| Anchor reference time | Its actual parent's time, which is the authenticated genesis time |
| Consensus time lower bound | Strictly greater than the upper median of the preceding at most eleven block times |
| Local future quarantine | Candidate time greater than an available local UTC reading plus 7200 seconds is deferred |

These parameters are a research selection, not a production resource or security profile. The two day half life is retained as an experimental starting value. No inherited hashrate, manipulation resistance, latency or chain security claim follows from another network's use of ASERT.

Every actual work-bearing child height contributes once. A checkpoint, stake vote or later Aegis batch creates no extra work height. The existing monetary core still exports `BLOCK_TARGET_SECONDS=120`. This document changes no subsidy amount, period length, issuance ceiling, allocation, reward maturity or finality rule. Integration of the 60 second target requires a separate versioned monetary transition with its actual integer schedule and vectors.

## Primary correspondence and deliberate differences

The primary [ASERT specification, version 0.6 dated 12 August 2020](https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/) describes a 600 second interval, compact target encoding, upgrade anchor and network-specific exceptions. The pinned [Bitcoin Cash Node implementation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/631badbf64766fa8c2d38f099e937f8c6cb19014/src/pow.cpp) supplies the exact integer polynomial, signed division, anchor parent time and clamping correspondence used here. Original authors, source revisions and MIT notices are recorded with the reference.

This prospective policy changes the interval to 60 seconds, keeps the full target without compact output quantization, and defines an initial height-one anchor contract. It imports no foreign genesis, checkpoint, anchor constants, monetary distribution, network activation, minimum-difficulty reset, disabled retargeting mode or global anchor cache. A candidate timestamp cannot trigger an easier-target exception.

The original C++ calculation assumes an easiest target with its top 32 bits zero. The reference here additionally tests the full 256 bit arithmetic domain using bounded wider intermediates. This is not a claim that the original C++ routine supports those inputs unchanged. The captured Python comparator uses floating point division before conversion to an integer. It is inspected as source and is not executed or imported. The new reference uses exact signed integer division throughout.

## Exact target calculation

Let the anchor have height `h_a=1`, target `T_a=T_initial` and parent timestamp `t_0`. Let the actual preceding child block have height `h_p` and time `t_p`. For a candidate at height `h_p+1 >= 2`, require the anchor and predecessor to belong to the same authenticated lineage and rule set, then define

```text
d_h = h_p - h_a
d_t = t_p - t_0
n   = (d_t - S*(d_h+1))*R
e   = trunc_toward_zero(n/H)
k   = floor(e/R)
f   = e-k*R, with 0 <= f < R
factor = R + floor((195766423245049*f
                  + 971821376*f^2
                  + 5127*f^3
                  + 2^47)/2^48)
P = T_a*factor
T_next = min(L, max(1, floor(P*2^(k-16))))
```

The two divisions have different signed semantics. Truncation toward zero in `e` cannot be replaced by floor division. The later split into `k` and `f` must use floor division or an equivalent arithmetic shift. Neither a real exponential nor floating point approximation is the specified rule. The polynomial is the rule.

The candidate's own timestamp, claimed target and parent network bits do not enter this calculation. They are checked against the independently derived result and applicable time and parent policies. The candidate timestamp influences only descendants after that block has passed the actual complete validation path.

Height one has no prior work anchor. Its expected target is the descriptor's `T_initial`. Only after its actual full validation does it become the anchor for subsequent calculations. Height zero has no work reward or accumulated work under this proposal. Missing genesis, initial target, limit or lineage refuses initialization. It does not select a convenient default or grant bootstrap finality.

Changing a checkpoint does not reset the anchor. A later rule change requires a separately specified transition. At the maximum unsigned height, deriving a successor refuses rather than wrapping. A reorganization that changes the first work block changes anchor identity and invalidates dependent context. Recalculation must use the selected branch, not a cache keyed only by height. Cache identity includes network, rules, genesis and actual anchor block identity.

## Bounded arithmetic and representation

1. Timestamp differences are signed differences of admitted unsigned 64 bit seconds. Height subtraction requires verified order. The height term, subtraction and radix multiplication fit a signed 128 bit intermediate for this domain and the selected interval. Narrow signed 64 bit multiplication is insufficient for every admitted extreme.
2. The polynomial numerator fits unsigned 64 bit arithmetic. It cannot be evaluated in signed 64 bit arithmetic. The factor is smaller than `2^17`, so `T_a*factor` requires at most 273 bits before scaling.
3. Set `s=k-16`. For `s >= 0`, if `bit_length(P)+s > 256`, the mathematical result exceeds every admitted `L` and returns `L` immediately. Otherwise the bounded shift and final comparison are exact. For `s < 0`, if `-s >= bit_length(P)`, the unbounded mathematical result is zero and the clamped result is one. No enormous shift or allocation is necessary.
4. Child target comparison uses the complete exact unsigned integer. No conversion to compact bits and back may discard low bytes. Existing parent header compact bits remain an independent parent policy field.
5. The research reference's direct formula is separately admitted only for shift magnitude at most 512. The full input extremes use the bounded implementation and independent saturation outcomes. This direct comparison scope is not a wider proving class.

These are source bounds and reference arithmetic observations. They do not measure production memory, prove authenticated history or admit the full private signature prover.

## Timestamp semantics and clock assumptions

For a candidate at positive height `h`, take the actual last `min(11,h)` predecessor times, including genesis during startup. Sort this bounded list and choose element `floor(count/2)`. Thus even startup counts use the upper middle value. The candidate time must be strictly greater. It may still be below its immediate parent's outlier time if the median rule permits it. ASERT must therefore retain signed time differences.

The target uses the predecessor's raw time, not the median substituted into the target formula. The median and ASERT have separate purposes. A candidate is not included in its own median window. The [original upper-median implementation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/631badbf64766fa8c2d38f099e937f8c6cb19014/src/chain.h#L238) supplies the precise startup convention used by this proposal.

The numeric future rule is a separate local admission boundary. With an actual available local UTC reading `u`, time `t > u+7200` is deferred. Equality is admitted by this numeric comparison. Missing clock evidence defers processing. No peer-adjusted time, candidate-provided clock, fallback acceptance or elapsed-time finality is selected. Arithmetic must avoid overflowing the addition at the unsigned limit.

Local quarantine is not a permanent consensus-invalid flag. A time value can become admissible later without changing historical work rules. The actual time source, trust, clock-jump behavior, bounded retry queue, deadlines and final commit recheck still need implementation and review. The reference evaluates literal integers only and reads no wall clock. It supplies no clock service or network timeout guarantee.

## Work score and branch context

For each completely validated work-bearing child block with expected threshold `T`, define

```text
work(T) = floor(2^256/(T+1))
W_genesis = 0
W_child = W_parent + work(T)
```

Use the expected child threshold, not peer bits, the numeric work hash or the harder parent threshold. A good individual hash does not earn a larger score than another solution under the same child threshold. `T+1` can require 257 bits. The score is positive and at most `2^255`. At most `2^64-1` positive heights give a sum below `2^319`, which fits a checked 320 bit representation. The selected score is an ordering metric, not a proof of actual miner cost or a PoW trust theorem.

Work comparison applies only after both branches satisfy complete private validity, supported work policy, availability and the authenticated finalized ancestry. Higher work cannot override finalized history or authorize invalid private state. A strictly greater compatible score can select a provisional suffix. Equal scores retain the current valid tip and establish no invalidity or finality for the competitor. The checkpoint protocol must still provide its actual safety and liveness construction.

Restoring a numeric cumulative score or anchor tuple does not authenticate the history that produced it. Restart and reorganization need an authenticated state owner, consistent block and ledger lineage, and replay of the actual rule. The existing byte journal and monetary totals do not provide this authority. No history validator or branch switch executes in the reference.

## Evidence and implementation gate

The single guarded reference checks eighteen independent raw targets from the pinned C++ test table, twelve new 60 second literals, thirty-two direct versus bounded arithmetic cases and four extremes. Eight actual wrong formulas differ and eight restored inputs pass. Twelve median windows, six numeric time classifications, five work-score literals and the 319 bit maximum sum are also checked. The full counts, saved cases and scope are in the [research record](../research/child-work-policy/README.md).

A production descriptor must bind the exact rule, integer semantics, genesis and initial target, easiest target, timestamp and clock policies, supported resource limits and activation. Its canonical encoding and registry mapping remain unselected. A passing arithmetic experiment cannot supply those values or activate a chain.

The next implementation task is a bounded native arithmetic component with independent saved literals, actual full-width operations and explicit unverified context. It needs its own complete source and dependency review, finite guard and adversarial admission. Authenticated history, full private proof feasibility, complete auxiliary binding, confidential eligibility, durable signer state, atomic ledger and network activation remain required. Private payments and hidden inputs remain the default. The 10080 block reward maturity, initial checkpoint finality, normal bond conservation and blocked first-stake bootstrap are unchanged.
