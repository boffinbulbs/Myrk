# Checkpoint consensus

## Roles

Auxiliary proof of work produces candidate blocks. Eligible stake supplies checkpoint support over a valid branch. Ordinary validators continue to reject invalid transactions and proofs independently of stake support.

A staking vote is an automatic protocol message, not an authorization to spend treasury assets or access private payments. Treasury control and governance of software upgrades are separate policies.

## Required construction

The complete checkpoint protocol is open research. It must specify eligibility, randomness, quorum assumptions, voting rounds, certificate encoding, branch selection, safety, liveness, and recovery. A checkpoint interval of five blocks is a development parameter. It does not establish a finality guarantee of ten minutes.

Confidential eligibility must bind committed stake, ownership, epoch, chain, referenced state, and authorized voting key. It must reject weight forgery, double counting, reuse after spending, replay across networks, and conflicting use of the same authority. Splitting the same value across many positions must not increase aggregate stake or expected influence.

The randomness construction must address grinding, withholding, and adaptive participants while meeting native PQ requirements. A classical VRF or aggregate certificate cannot be adopted without accounting for its security assumptions.

## Lifecycle and rewards

Specify activation, maturity, bonding/unbonding, key rotation, delegation, reward vesting, equivocation evidence, and penalties. Restricted online voting authority must not be general spending authority.

The monetary core applies a nominal 70/30 split: the miner receives floor(7 * capped subsidy / 10) atomic units and the stake budget receives the remainder. This preserves atomic unit conservation, including a final budget of one atom that is entirely allocated to staking. Only explicitly earned stake amounts are issued. The core does not verify the evidence of those duties. Unused stake budget is not redirected to the miner or treasury. The future kernel must bind the accounting call to valid certificate/duty evidence and prevent duplicate application.

With no premine, checkpoint activation requires a public bootstrap process that distributes eligible stake. The transition rule and conditions must be audited and simulated before a launch involving real value. Until activated, the node must not report stake finality.

## Adversarial evaluation

Required cases include partitions, unavailable quorum, conflicting votes, hidden stake concentration, long range history, miner/staker disagreement, abrupt work changes, restored signers on multiple devices, withdrawals during reorganization, load from tiny registrations, and stalled finality. Disabling stake checks during a failure is not a preservation of their security guarantee.

The production staking floor and exact withdrawal/penalty rules are not frozen. Development comparisons include participation limited by resources without an extra balance floor, 1 THM, and 10 THM registration floors.
