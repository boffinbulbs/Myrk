# Native subsidy allocation

## Current profile and scope

The current native block subsidy profile allocates nominal shares of 60 percent to miners, 20 percent to eligible staking duties, 10 percent to the protocol pool, and 10 percent to development maintenance for the designated project developer. This profile supersedes the earlier 70/30 profile and the separate 60/30/10 research allocation.

These shares apply to native block subsidy. They do not define transaction fee distribution, external mining receipts, protocol pool spending authority, or developer destination authority. Fee allocation remains a separate specification item. No production genesis has been released.

The monetary core calculates the allocation and cumulative issuance. It does not create payout notes, authenticate destinations, implement pool governance, or establish that a stake reward was earned. Those are ledger kernel and protocol requirements.

## Integer allocation and conservation

Let $R(h)$ be the nominal subsidy at height $h$, $C$ the cumulative issuance ceiling, and $I$ cumulative actual issuance before the transition. Every quantity below is a nonnegative integer number of atomic units, with $I\le C$. The available subsidy is

$$
S=\min(R(h),C-I)
$$

The initial floors are

$$
m_0=\left\lfloor\frac{6S}{10}\right\rfloor
\qquad
K=\left\lfloor\frac{2S}{10}\right\rfloor
\qquad
P=\left\lfloor\frac{S}{10}\right\rfloor
\qquad
D=\left\lfloor\frac{S}{10}\right\rfloor
$$

Here $K$ is the staking budget, $P$ the protocol pool allocation, and $D$ the development maintenance allocation. Every atom remaining after the four floors belongs to the miner:

$$
r=S-m_0-K-P-D
\qquad
M=m_0+r
\qquad
M+K+P+D=S
$$

This rule conserves the complete capped budget. The percentages are nominal shares because integer rounding can alter their exact ratios for small amounts. The final available atom belongs to the miner. It does not become a stake, protocol pool, or developer credit.

| Available subsidy | Miner | Staking budget | Protocol pool | Development maintenance |
|---|---:|---:|---:|---:|
| 16 THM | 9.6 THM | 3.2 THM | 1.6 THM | 1.6 THM |
| 10 atoms | 6 atoms | 2 atoms | 1 atom | 1 atom |
| 9 atoms | 8 atoms | 1 atom | 0 atoms | 0 atoms |
| 1 atom | 1 atom | 0 atoms | 0 atoms | 0 atoms |
| 0 atoms | 0 atoms | 0 atoms | 0 atoms | 0 atoms |

## Actual issuance and unearned staking

Let $e$ be explicitly earned stake reward. The valid range and actual issuance are

$$
0\le e\le K
\qquad
A=M+P+D+e
\qquad
I'=I+A\le C
$$

The unearned amount $K-e$ remains unissued. It is not redirected to the miner, protocol pool, developer, or external treasury. It creates no future debt or automatic catch up entitlement. The accounting API validates the amount range. The future kernel must establish the evidence of eligible duties and reject duplicate rewards.

Protocol pool and development maintenance allocations count as issued when the monetary transition is applied, even while unspent. Later grant selection or spending does not issue them a second time. The current core records amounts and supply counters rather than a complete owned balance or payout note system. Destination commitments, authority, recipient encoding, persistence, and rollback require complete kernel rules.

Burns reduce outstanding value and do not reopen the cumulative issuance ceiling. Purchases, reservations, transfers, and announced burns are distinct from completed destruction. The schedule, cumulative ceiling, and height mapping are recorded in [development parameters](parameters.md) and the [reference model](../research/emission/README.md).

## Distinct funding authorities

| Component | Funding source | Authority boundary |
|---|---|---|
| Protocol pool | Native allocation $P$ | Governance and spending construction remain unimplemented |
| Development maintenance | Native allocation $D$ | Allocation is designated for the project developer. Destination and spending authorization remain specification work |
| Operator external treasury | Eligible external mining receipts | Operator custody and reconciliation under its separate policy |
| Eligible staking | Earned part of $K$ | Restricted checkpoint duties with independently validated evidence |

Pool funding does not make a grant ballot valid. A pool ballot does not authorize developer spending or obtain external treasury keys. A checkpoint vote authorizes none of these spending actions. The [pool governance research](governance.md), [checkpoint requirements](checkpoints.md), and [external treasury policy](treasury.md) retain those separate boundaries.

## Temporary development maintenance allocation

The development maintenance allocation is temporary. Its retirement requires a future consensus hard fork after work completion and community handover. The retired 10 percent is to be redistributed to mining and staking in future subsidies. The protocol pool remains at 10 percent unless a separate explicit change modifies it.

Completion criteria, the handover and consensus change process, the activation height, and the successor miner/stake ratio remain unresolved. No exact date, duration, milestone trigger, approval threshold, or successor ratio is defined by the current profile. The implementation contains no automatic sunset, retirement height, or milestone key that can switch the allocation.

Retirement changes only subsidies created under the future rules. Existing legitimately earned credits are unaffected. It does not confiscate or redistribute earlier balances, restore issuance allowance, or let a developer key change consensus allocation. The eventual transition needs a complete versioned specification, conservation vectors, activation boundary tests, compatibility rules, and rollback analysis before deployment.

## Validation requirements

Allocation evidence covers zero subsidy, the first scheduled reward, ordinary rounding, every final budget below ten atoms, cap clipping, maximum supported amounts, unearned staking, exact exhaustion, and burns. Each transition must preserve $M+K+P+D=S$ and actual issuance $A=S-(K-e)$. Invalid earned amounts and arithmetic overflow must fail before persistent state changes.

Future payout integration must additionally bind all four allocations to authorized destinations and the same accepted block context. Arithmetic tests do not establish ownership, valid payment notes, secure protocol pool governance, confidential staking, or network consensus.
