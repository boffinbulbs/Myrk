# Checkpoint consensus

## Roles

Auxiliary proof of work produces candidate blocks. Eligible stake supplies checkpoint support over a valid branch. Ordinary validators continue to reject invalid transactions and proofs independently of stake support.

A staking vote is an automatic protocol message, not an authorization to spend treasury assets or access private payments. Treasury control and governance of software upgrades are separate policies. The [protocol pool governance research](governance.md) defines a separate manual ballot and funding lifecycle.

## Required construction

The complete checkpoint protocol is open research. It must specify eligibility, randomness, quorum assumptions, voting rounds, certificate encoding, branch selection, safety, liveness, and recovery. A checkpoint interval of five blocks is a development parameter. It does not establish a finality guarantee of ten minutes.

Confidential eligibility must bind committed stake, ownership, epoch, chain, referenced state, and authorized voting key. It must reject weight forgery, double counting, reuse after spending, replay across networks, and conflicting use of the same authority. Splitting the same value across many positions must not increase aggregate stake or expected influence.

The randomness construction must address grinding, withholding, and adaptive participants while meeting native PQ requirements. A classical VRF or aggregate certificate cannot be adopted without accounting for its security assumptions.

## Lifecycle and rewards

Specify activation, maturity, bonding/unbonding, key rotation, delegation, reward vesting, equivocation evidence, and penalties. Restricted online voting authority must not be general spending authority.

The current [native subsidy allocation](subsidy-allocation.md) assigns nominal shares of 60 percent to miners, 20 percent to eligible staking, 10 percent to the protocol pool, and 10 percent to temporary development maintenance for the designated project developer. For capped subsidy $S$, the staking budget is $K=\lfloor 2S/10\rfloor$. Atomic remainders belong to the miner, including the final available atom.

Only explicitly earned stake reward within $K$ is issued. The core does not verify the evidence of those duties. Unused staking budget remains unissued and is not redirected to any other allocation. Pool and developer allocations count as issued immediately, even while unspent. The future kernel must bind every allocation to valid authorization, destinations, accepted block context, and atomic persistence. The core does not create payout notes or establish those authorities.

Checkpoint support is separate from pool spending and development maintenance. It cannot retire the developer allocation through an ordinary vote. Retirement requires the future consensus hard fork and handover rules described in the allocation specification. No automatic sunset is implemented.

With no premine, checkpoint activation requires a public bootstrap process that distributes eligible stake. The transition rule and conditions must be audited and simulated before a launch involving real value. Until activated, the node must not report stake finality.

## Adversarial evaluation

Required cases include partitions, unavailable quorum, conflicting votes, hidden stake concentration, long range history, miner/staker disagreement, abrupt work changes, restored signers on multiple devices, withdrawals during reorganization, load from tiny registrations, and stalled finality. Disabling stake checks during a failure is not a preservation of their security guarantee.

The production staking floor and exact withdrawal/penalty rules are not frozen. Development comparisons include participation limited by resources without an extra balance floor, 1 THM, and 10 THM registration floors.
