# Accounting and funding diagrams

These transparent light and dark SVGs explain the development accounting reference and separate funding authorities. Production emission parameters remain open before genesis. The retained monetary source and independent vectors remain reproducible.

| Figure | Boundary |
|---|---|
| [Subsidy and supply](figures/subsidy-and-supply.svg) | Capped reward, integer floors, miner remainder, earned stake, actual issuance and outstanding supply |
| [Funding authorities](figures/funding-authorities.svg) | Native protocol pool, temporary development credits, operator external receipts and worker liabilities |

The formulas describe implemented arithmetic. Owned payout notes, duty evidence, destinations, governance and external execution require their separate ledger and service implementations. The diagrams show authority requirements rather than live fund operations.

For capped available subsidy S, the current reference satisfies

$$
M+K+P+D=S,\qquad 0\le e\le K,\qquad A=M+P+D+e.
$$

K is a budget, while e is earned staking issuance. The difference remains unissued. With cumulative issuance I and completed destruction B, outstanding value is I minus B. Completed burns leave the cumulative cap unchanged. The [allocation specification](../../docs/subsidy-allocation.md) supplies the complete definitions and rounding rules.

The [fixed diagram data](figure-data.json) contains explanatory integer examples and source boundaries. It is a presentation record rather than a replacement monetary oracle. Native transfers and protocol pool grants consume existing value. Operator purchases and exchanges have separate custody and reconciliation requirements.

## Reproduction

```text
python research/accounting-figures/generate_figures.py
python research/accounting-figures/generate_figures.py --check
```

The standard library checks exact bytes, XML, coordinates, theme geometry/text equality and contrast. Optional preview arguments use installed Pillow and system fonts. No font files are distributed. The [source record](source_record.json) fingerprints the original generator, fixed data, outputs and accounting source. Historical monetary artifacts and compiled rules remain unchanged.
