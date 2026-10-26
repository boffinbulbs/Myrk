# Treasury operations

## Custody and purpose

The treasury is project/operator controlled. Independent custodians or a committee requiring threshold approval for spending are not required. Its purposes are disclosed maintenance expenditure and purchases/burns of native THM. This is a centrally controlled financial component, separate from independently verifiable consensus and open mining integration.

One accounting policy covers separate addresses/wallets on each external network. Eligible work must bind the required destination through the supported proof format. Destination authorization and activation rules remain a protocol specification item.

The [native protocol pool research](governance.md) defines a separate funding and spending boundary. Its stake ballots do not authorize control of the operator's external accounts or development maintenance credits. Changing external custody or destination policy requires its own explicit activation rules. The current monetary core calculates native protocol pool and developer allocations, but it does not create payout notes, validate destination authority, or implement pool governance.

## Funds and liabilities

The current [native subsidy profile](subsidy-allocation.md) assigns nominal shares of 60 percent to miners, 20 percent to eligible staking, 10 percent to the protocol pool, and 10 percent to temporary development maintenance for the designated project developer. Atomic remainders belong to the miner. Unearned staking stays unissued. Native protocol pool and developer allocations count as issued immediately, including while unspent. These shares apply to block subsidy and do not define fee distribution or the use of external mining receipts.

Pool worker liabilities, native rewards, protocol pool value, developer credits, and external treasury assets are distinct accounting objects. A mining pool cannot treat unpaid worker balances as a maintenance or purchase budget. A protocol pool grant or checkpoint vote cannot obtain external treasury keys or spend developer credits.

The available execution budget is:

```text
max(0, eligible receipts - execution costs
       - published maintenance budget - reserve top-up)
```

Maintenance/reserve amounts for external receipts need an explicit published policy. No fixed external maintenance or burn percentage is defined by the native subsidy allocation. Native payouts must not depend on successful external trading.

The native developer allocation is temporary and separate from this external budget. Its retirement requires a future consensus hard fork after work completion and community handover. The retired future 10 percent is to be redistributed to mining and staking, while the protocol pool remains at 10 percent absent a separate explicit change. Criteria, process, activation height, and successor miner/stake ratio remain unresolved. Previously legitimate credits are unaffected, and the current code contains no automatic sunset.

## Execution state

Track eligible confirmed receipt, deposit, available funds, pending/partial order, fill, withdrawal, native receipt, burn submission and confirmed burn as distinct durable states. Deduplicate external identifiers. A timeout does not prove that an operation failed.

Mandatory external maturity and conservative confirmation policy are different checks. Expected mining revenue is not budgeted as a received asset. Orphaned blocks, rejected deposits, partial fills, delayed withdrawals and reorganization require explicit reconciliation.

Use restricted exchange permissions where supported, limited hot balances, spending and price limits, destination restrictions, and a pause on unexplained differences. Operator custody and exchanges retain real control. Automation does not make the process trustless.

## Evidence

Publish or deliberately disclose treasury receipts, expenditure, holdings, trade records, withdrawal reconciliation and independently verifiable native burns. Viewing data alone does not prove the absence of liabilities. Ordinary users' private data is outside this disclosure scope.

A native burn consumes authorized owned value and records actual destruction. It does not restore cumulative issuance allowance. Exchange downtime pauses execution, not transaction verification or consensus admission.
