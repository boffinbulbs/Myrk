# Prospective paired 60 second monetary profile

The research profile `kova.monetary.paired60.v1` defines an exact from-genesis monetary comparison at the [60 second work target](child-work-policy.md). It preserves the [120 second accounting reference](../research/emission/README.md), including its `reference_version=2` artifacts, code and historical figures. Neither profile is an activated chain. Production genesis, economic selection, authenticated rules and profile encoding remain open.

The [new integer reference](../research/monetary-paired60/README.md) evaluates this prospective rule without importing or executing the earlier generator, tests or model. Arithmetic consistency does not authenticate issuance, eligible duties, destinations or history. No accepting ledger or proof route is supplied.

## Exact nominal schedule

For a positive new height `h`, define

```text
i = h - 1
j = floor(i / 2)
phase = i mod 2
p = floor(j / 21900) = floor(i / 43800)
S = frozen_old_table[p] if p < 240, otherwise 50000000 atoms
x = 10 * floor(S / 20)
y = S - x
R60(h) = x if phase = 0, otherwise y
R60(0) = 0
```

The exact old table is identified by SHA256 `ab8097f05a6993a38a3666ca5056c0cd30a6609ab2d5c3192a038bf2e27c8f7b` over its canonical `period:atomic` lines. This profile uses the retained integer entries. It does not calculate new rewards with floating point or relabel earlier charts.

| Quantity | Prospective rule |
|---|---|
| Atomic precision and cap | Eight decimals, 6300000000000000 atoms |
| Genesis | Height zero, no reward or distribution |
| Reward period | 43800 positive heights |
| Declining periods | 240 |
| Initial pair | 800000000 atoms at each of heights one and two |
| First long reward | Height 10512001 |
| Long reward | 25000000 atoms per block before cap clipping |
| Pair ordering | Lower amount first, residual amount second |
| Reward maturity | 10080 blocks from each actual issuance origin |

Writing `S=20q+r` gives `x=10q` and `y=10q+r`, with `0<=r<20`. Pair amounts can differ by at most nineteen atoms. The first amount is at most nine atoms below `floor(S/2)`. This small deterministic difference preserves the complete allocation vector across each pair. It is specified protocol arithmetic, not an account balance carried between requests.

For example, old entry one is 1577061117 atoms. Its new pair is 788530550 then 788530567 atoms. Simple equal floor halves lose one atom. Floor/ceiling halves preserve the gross sum but alter the allocation vector. Neither alternative is this profile.

## Per-block allocation and pair correspondence

For each new block, first clip its nominal reward using current cumulative actual issuance `I` and cap `C`, then apply the unchanged [allocation formula](subsidy-allocation.md):

```text
c = min(R60(h), C - I)
K = floor(c / 5)
P = floor(c / 10)
D = floor(c / 10)
M = c - K - P - D
0 <= earned <= K
actual = M + P + D + earned
unearned = K - earned
I_after = I + actual
```

This equals the retained nominal 60/20/10/10 floors with all atomic remainder assigned to the miner. Pool and development amounts count as issued immediately. Their later spending cannot issue them again. Unearned staking creates no outstanding value, reserve, debt or catch-up entitlement. Actual duty evidence and unique reward consumption remain kernel requirements.

Let `A(s)=(M,K,P,D)` denote the four planned amounts for budget `s`. Since `x` is a multiple of ten, both division denominators divide `x`. Therefore

```text
A(x) + A(y) = A(S)
```

The equality holds for each component. It also preserves all miner remainder atoms. For the example above:

| Budget | Miner | Stake budget | Pool | Developer |
|---|---:|---:|---:|---:|
| First new block | 473118330 | 157706110 | 78853055 | 78853055 |
| Second new block | 473118342 | 157706113 | 78853056 | 78853056 |
| Pair total | 946236672 | 315412223 | 157706111 | 157706111 |

For an uncapped pair, earned amounts `e1,e2` give the same total issuance as one old budget with earned amount `e1+e2`. The individual bounds imply `e1+e2<=K_old`. Completed burns compose by their sum. This is numeric correspondence, not a proof that either duty was earned.

For a fully earned pair with any starting remaining capacity `R`, total capped budgets equal `min(S,R)` and their allocation vector equals `A(min(S,R))`. If `R<x`, the first block consumes all remaining capacity. Otherwise the first amount is divisible by ten, so splitting the residual preserves both floors. This establishes the capped correspondence under the full-earning assumption.

## Limits of the correspondence

The pair identity does not make every partially earned cap trajectory equal. Each new height is a separate allocation opportunity, recomputed against actual current issuance. With 100 atoms remaining and zero earned stake, one old block issues 80 and leaves 20. Two new blocks issue 80 then 16 and leave four. The second block has its own ordinary budget. It receives no reserved or reissued entitlement from the first block.

This difference already follows from the retained per-block cap rule when another valid block occurs. The faster cadence changes when that next opportunity occurs. The profile explicitly keeps the per-block rule. It adds no hidden pair reservation, redirected old stake reward or fabricated duty. Arbitrary partially earned time paths are not claimed identical.

Burns increase cumulative completed destruction `B`, reduce outstanding value `I-B`, and never reduce `I` or restore `C-I`. Inputs must obey `0<=B<=I<=C`. An over-budget earned amount, overburn or invalid numeric state refuses before producing a result. Numeric restoration of totals still authenticates no state history.

## Height, time and cap boundaries

After an even number `2m` of new blocks, uncapped nominal issuance equals the old nominal total after `m` blocks. Planned component totals also agree. At `2m+1`, add the first amount of the next pair. Fully earned issuance is the capped nominal total. An analytic prefix sums at most 240 declining entries and a constant tail term. No iteration through an entire chain is required.

The declining phase ends at new height 10512000 and has the same 630720000 nominal seconds and 2367682937882100 nominal atoms as the old declining phase. This is target-time arithmetic, not a prediction of actual block production or bootstrap timing.

Under the old fully earned, no-burn reference assumptions, final capacity before old height 83902342 is 12117900 atoms. The new first half is already larger than that remainder. Thus the new first cap-exhausting height is 167804683, sixty nominal seconds earlier than twice the old height. The last clipped amount and four allocations agree. The following height has positive nominal reward and zero payable capacity. A date, incentive sufficiency or actual launch distribution is not established.

All supported heights are unsigned 64 bit values. Compute `h-1` only after testing for genesis, then divide to obtain the pair index. Do not compute a potentially overflowing `2*old_height`. Maximum height is an odd first-half height with no representable successor. The uncapped analytic prefix needs fewer than ninety bits and fits a future checked `u128`; individual amounts remain bounded. The reference stores wide prefix and height values as decimal strings where JSON number precision would be insufficient.

## Version and authority boundary

This is a new from-genesis research comparison. It does not define a live migration from an existing 120 second chain. A later height-activated transition needs its own authenticated activation, subsidy phase mapping, monetary state rule and independent vectors. No current candidate, wallet label, job codec or local journal generation may select that transition.

A future validator must derive network, active rules and monetary profile from authenticated state. Its selected rule must also bind work policy, expected statement, resource class, treasury destinations, epoch and finality context. A proposed record cannot supply its own expected amounts, target or validity verdict. Unknown profiles refuse. The canonical profile descriptor and complete state construction remain unimplemented.

Each mining or staking credit retains its actual new creating height and authenticated origin. The 10080 block maturity and initial checkpoint finality rule are unchanged. Old paired origin heights cannot backdate new rewards. Ordinary payments do not inherit a new reward delay. Registration, migration, applications and Safe routing cannot erase restrictions. Block counts do not become elapsed-time finality.

Normal bond conservation, confidential eligibility, complete quorum and rounds, durable signer state and the blocked first-stake bootstrap remain required. No premine, administrative mint, transparent fallback, substitute authorization primitive or weaker profile is introduced. The eventual developer retirement remains a separate future hard fork with no automatic sunset or milestone key.

Full private proof and parser feasibility, same-witness authorization, same-header auxiliary binding, authenticated history, atomic ledger and network gates remain open. Private payments and hidden input commitments remain the default. This monetary reference activates none of those capabilities.
