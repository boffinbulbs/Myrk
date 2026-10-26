# Treasury operations

## Custody and purpose

The treasury is project/operator controlled. Independent custodians or a committee requiring threshold approval for spending are not required. Its purposes are disclosed maintenance expenditure and purchases/burns of native THM. This is a centrally controlled financial component, separate from independently verifiable consensus and open mining integration.

One accounting policy covers separate addresses/wallets on each external network. Eligible work must bind the required destination through the supported proof format. Destination authorization and activation rules remain a protocol specification item.

The [native ecosystem fund research](governance.md) defines a separate funding authority. Its stake ballots do not authorize control of the operator's external accounts. Changing external custody or destination policy requires its own explicit activation rules. The current monetary core contains no native treasury allocation or spending implementation.

## Funds and liabilities

Scheduled native subsidy uses a nominal 70/30 allocation: floor(7 * capped subsidy / 10) atomic units for miners and the remainder as the eligible staking budget. Pool worker liabilities and native rewards must remain separate from external receipts owned by the treasury. A pool cannot treat unpaid worker balances as a maintenance or purchase budget.

The available execution budget is:

```text
max(0, eligible receipts - execution costs
       - published maintenance budget - reserve top-up)
```

Maintenance/reserve amounts need an explicit published policy. No fixed percentage is embedded in the initial core. Native payouts must not depend on successful external trading.

## Execution state

Track eligible confirmed receipt, deposit, available funds, pending/partial order, fill, withdrawal, native receipt, burn submission and confirmed burn as distinct durable states. Deduplicate external identifiers. A timeout does not prove that an operation failed.

Mandatory external maturity and conservative confirmation policy are different checks. Expected mining revenue is not budgeted as a received asset. Orphaned blocks, rejected deposits, partial fills, delayed withdrawals and reorganization require explicit reconciliation.

Use restricted exchange permissions where supported, limited hot balances, spending and price limits, destination restrictions, and a pause on unexplained differences. Operator custody and exchanges retain real control. Automation does not make the process trustless.

## Evidence

Publish or deliberately disclose treasury receipts, expenditure, holdings, trade records, withdrawal reconciliation and independently verifiable native burns. Viewing data alone does not prove the absence of liabilities. Ordinary users' private data is outside this disclosure scope.

A native burn consumes authorized owned value and records actual destruction. It does not restore cumulative issuance allowance. Exchange downtime pauses execution, not transaction verification or consensus admission.
