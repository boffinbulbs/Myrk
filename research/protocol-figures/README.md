# Protocol architecture figures

These diagrams describe planned base runtime interfaces and delivery boundaries. They are separate from implemented proof results and measured research charts.

| Figure | Required relationship |
|---|---|
| [Base architecture](figures/base-architecture.svg) | Local wallet, public validation, kernel, work, stake and authenticated storage |
| [Private payment](figures/private-payment-flow.svg) | Local witnesses, encrypted delivery, complete proof validation and payment eligibility |
| [Work and checkpoints](figures/work-checkpoint-flow.svg) | Work validation and eligible stake checkpoint decisions |
| [Wallet Safe](figures/wallet-safe-lifecycle.svg) | Protected funds, delayed withdrawal and restricted cancellation |
| [Development stages](figures/development-stages.svg) | Base feasibility and network milestones with separate later applications and Aegis |

Each figure has transparent light and dark variants with matching geometry and text. The base onward spending rule remains checkpoint finality. Later Aegis has its own [figure record](../aegis/README.md) and activation gates.

Complete private payment and confidential stake remain feasibility gates before ledger integration. An edge names a required interface rather than a working runtime connection. The Safe requires chain enforcement. Ordinary node validation requires no wallet or stake authority.

## Reproduction

```text
python research/protocol-figures/generate_figures.py
python research/protocol-figures/generate_figures.py --check
```

Generation uses the Python standard library. [Fixed data](figure-data.json) defines scope, and the [source record](source_record.json) fingerprints the original generator and outputs. Optional previews use installed renderers and fonts, with no font files distributed.

Definitions and acceptance gates remain in [architecture](../../docs/architecture.md), [private transitions](../../docs/private-transactions.md), [checkpoints](../../docs/checkpoints.md), [the Safe](../../docs/protocol-extensions.md#private-safe) and [delivery stages](../../docs/delivery-roadmap.md). The figures are architectural illustrations rather than performance or security measurements.
