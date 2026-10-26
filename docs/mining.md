# Auxiliary work integration

## Operator roles

| Role | Required components |
|---|---|
| Pool operator | Synchronized Thorum node, compatible Zcash full node under operator control, adapter for parent templates and submissions, worker accounting, treasury routing and monitoring |
| Solo mining operator | Both node stacks, equivalent job/commitment/submission integration, compatible Equihash work |
| Pool worker | Compatible miner, pool connection and native payout destination |
| Ordinary validator or staker | Thorum node and relevant staking duties. No requirement to synchronize Zcash |

The first parent profile targets Equihash (200,9) work in Zcash format. Matching an algorithm name alone is insufficient: parameters, personalization, header rules, activated formats and child commitments must match.

## Verification boundary

An auxiliary witness must authenticate the intended child candidate, chain/domain identifiers, supported parent work, relevant parent transaction and authorization commitments, target and treasury destination commitment. Its encoding and resource limits require a dedicated specification and negative vectors.

Zcash transaction formats require careful treatment of both transaction and authorization commitments. The appropriate branches cannot be replaced by an unqualified check of the transaction ID alone. Parent format rules must be pinned to an evaluated version. [Transaction/authorization commitments](https://zips.z.cash/zip-0244), [miner/pool protocol](https://zips.z.cash/zip-0301)

A work result that satisfies the child target need not satisfy the external chain's harder target. A valid child witness also does not prove a winning external candidate was broadcast, accepted, remained canonical, or paid the treasury. Operators separately reconcile actual external receipts through their full nodes.

## Permissionless integration

Independent compatible operators can integrate under common verification rules without a certificate issued by a developer for each job. Treasury destination updates must be versioned and unambiguous for every validating node. A public registry does not automatically supply a secure construction for update governance.

Submit matching solutions to every supported compatible target. Additional auxiliary chains require tested simultaneous commitment and payout compatibility. Arbitrary algorithm or parent switching is outside the initial profile.

Expected external income depends on actual winning work, acceptance, difficulty, liquidity, fees, and settlement policy. Shares and submission acknowledgments are accounting events, not spendable external coins.
