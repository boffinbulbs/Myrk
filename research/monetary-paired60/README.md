# Paired 60 second monetary reference

This finite integer reference evaluates the prospective from-genesis profile `kova.monetary.paired60.v1` defined in the [policy](../../docs/monetary-paired60.md). It implements numeric research only. The retained [120 second reference](../emission/README.md), its version 2 data, monetary core, tests and figures are unchanged. No production economic selection, activation, migration or accepting chain is supplied.

Each old scheduled entitlement `S` becomes an ordered pair `10*floor(S/20)` and the residual `S-first`. The first amount is divisible by ten, so the unchanged per-block allocation floors preserve all four old component budgets across a pair. The rule has no mutable carry. The new period is 43800 blocks, initial subsidy is eight coins, tail subsidy is one quarter coin, and the cumulative actual issuance cap remains 63 million coins.

## Independent inputs and scope

The [reference](reference.py) reads the immutable 240 entry `schedule.csv` as data and checks its normalized source and canonical numeric hashes. It imports no earlier model, generator or test. No integer-root or plotting program is rerun. The [manual literals](literals.json) were specified before evaluation and include first/last periods, odd atoms, maximum unsigned values, allocations and the independently saved old cap boundary. The original [MIT notice](licenses/Kova-MIT) is preserved.

Python integers evaluate the new rule. Individual heights and synthetic input amounts are bounded by `u64`. Counter values are bounded by the issuance ceiling. The largest uncapped prefix requires 89 bits in the executed maximum-height case and fewer than 90 bits by the source bound. Prefix evaluation visits at most 240 entries, without iterating through a chain. Height and wide prefix records use decimal strings to preserve JSON integer precision.

The model uses actual input checks and raises specific numeric `Refusal` causes. Those failures are not proof or consensus rejections. The numeric issue function computes unverified output data from supplied totals and earned amounts. It authenticates no duties, destinations, history, root, state restoration or commit permission.

## Recorded validation

One new guarded reference passed under the original Windows 512 MiB process and 512 MiB aggregate job limits, fresh 2 GiB availability, 120 seconds and flags 8960. Peak process private commitment was 10874880 bytes, aggregate job commitment 12181504 bytes and working set 17698816 bytes. All 1643 frozen model/source/fixture/runtime inputs were verified afterward, including existing Python standard-library bytecode. Invocation used `-I -S -B`. The last flag prevents writes, not reads of existing bytecode.

| Actual mathematical controls | Count |
|---|---:|
| Original period entries mapped to exact pairs | 240 |
| Phase boundary comparisons | 960 |
| Previous-period neighbor comparisons | 239 |
| Independent nominal / pair / allocation literals | 13 / 7 / 6 |
| Fully earned capped pairs across all twenty residue classes | 200 |
| Uncapped earned/burn pair comparisons | 180 |
| Actual wrong alternatives and restored checks | 8 each |
| Actual typed numeric refusals | 16 |

Additional checks cover genesis, tail, maximum height, burned-cap refusal, the 20 year declining total and final clipping. The [result](result.json) is 37444 raw bytes, SHA256 `87a343c07ff0334c95a5d1095f6a964eaa92c9954b082c1a4896b173e8d7397b`. A `period_pairs` row contains period, old amount, first amount, second amount and the first, second and old four-component allocations. The [source record](provenance.json) and [validation](validation.json) identify exact inputs and limits.

The wrong alternatives change actual calculations: equal floor halves, unaligned floor/ceiling allocations, swapped phases, incorrect period indexing, premature tail, allocation before clipping, outstanding supply used to reopen capacity, and unearned stake treated as issued. No supplied verdict or callback determines any result.

The model explicitly records a limit of the pair correspondence. With 100 atoms of capacity and no earned stake, two new opportunities issue 80 then 16, while one old opportunity issues 80. No old unearned right is redirected or reserved. The second new height has its own recomputed ordinary budget. Arbitrary partially earned time paths are not identical.

Under fully earned, no-burn reference assumptions, the first exhausting height becomes 167804683, sixty nominal seconds earlier than the doubled old height. Its last clipped reward is the same 12117900 atoms with the same four allocations. These are target-time arithmetic observations, not actual dates, a launch distribution or an incentive security result.

## Evidence inspection and remaining work

Recorded evidence can be inspected without executing the reference:

```text
python -I -S -B research/monetary-paired60/static_check.py
```

The producer creates its result exclusively. Re-execution requires a separately reviewed finite scope and actual external resource admission. No Rust compilation, monetary core test, old model, proof, healthy verifier, native witness, RNG, signing, private owner, ledger or network operation was executed. CI and the job layout are unchanged. These functional checks are not a performance benchmark or toolchain audit.

The next task is a bounded safe native implementation of this exact prospective accounting profile with the independent saved literals and real failure cases. It must remain explicitly unverified numeric data. Production descriptors, genesis, authenticated state and history, private proof feasibility, complete auxiliary binding, confidential stake, durable signer state and network activation remain separate gates.

Reward origin and 10080 block maturity, initial checkpoint finality, normal bond conservation and blocked first-stake bootstrap remain unchanged. There is no developer sunset key, new premine, administrative mint or transparent payment fallback. Private payments and hidden input commitments remain mandatory by default across the complete roadmap.
