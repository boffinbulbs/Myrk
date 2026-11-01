# Child work integer reference

This finite Python reference evaluates the [prospective child work policy](../../docs/child-work-policy.md). It is a public numeric experiment. It runs no node, work solver, hash or Equihash predicate, history validator, private witness, prover, verifier, signer or network service. Its outputs are not authenticated expected context or permission to accept a block.

## Source and independent anchors

The original ASERT algorithm is attributed to Mark Lundeberg, with the specification by freetrader, Jonathan Toomim, Calin Culianu and Mark Lundeberg. The [published specification](https://upgradespecs.bitcoincashnode.org/2020-11-15-asert/) identifies version 0.6 dated 12 August 2020. It was inspected as web text. A raw specification file identity is not claimed.

The pinned Bitcoin Cash Node tag `v28.0.1` resolves to `631badbf64766fa8c2d38f099e937f8c6cb19014`. Eleven original source files total 182896 raw bytes, with exact SHA256 and Git blob identities in [provenance](provenance.json). They include the [calculation](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/631badbf64766fa8c2d38f099e937f8c6cb19014/src/pow.cpp), [raw target cases](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/631badbf64766fa8c2d38f099e937f8c6cb19014/src/test/pow_tests.cpp#L735) and [mainnet parameter definitions](https://github.com/bitcoin-cash-node/bitcoin-cash-node/blob/631badbf64766fa8c2d38f099e937f8c6cb19014/src/chainparams.cpp#L97). No downloaded program, C++ test or original Python generator is executed or imported.

The [eighteen primary cases](primary-cases.json) preserve the original raw-target expectations. Their easiest target is `2^224-1`, which differs from the decoded compact value `0x1d00ffff`. One primary case lies below that raw limit but above the compact encoding's decoded value. This exposes accidental quantization in a successor that must retain the full child target. These original 600 second cases are comparison data, not Kova launch parameters. Original MIT notices are retained in [licenses](licenses/).

The new [reference](reference.py) uses exact integer truncation and two arithmetic forms: an expanded direct polynomial and a Horner polynomial with bounded shifts. They share an input checker. Their agreement is not a comparison of two independently executed production clients or a security theorem. The primary raw literals and simple power-of-two cases supply independent anchors.

## Recorded execution

One newly admitted reference run passed under actual Windows limits of 512 MiB process commitment and 512 MiB aggregate job commitment, fresh 2 GiB availability and a 120 second deadline. It recorded 8667136 bytes of peak process private commitment, 9973760 bytes of peak aggregate job commitment and 14295040 bytes of peak working set. All 964 frozen inputs were verified afterward, including existing standard-library bytecode caches. No old model, proof, verifier, native witness or journal test was replayed.

| Executed arithmetic scope | Count |
|---|---:|
| Pinned independent raw target cases at original spacing | 18 |
| New literal cases at prospective 60 second spacing | 12 |
| Direct versus bounded arithmetic grid | 32 |
| Full target and unsigned-height/time extreme cases | 4 |
| Actual wrong formula alternatives and restored checks | 8 each |
| Upper-median windows, including startup and an outlier | 12 |
| Literal numeric time classifications | 6 |
| Independent work-score literals | 5 |

The saved [result](result.json) contains 66 target cases and is 19194 raw bytes. It also records the 319 bit maximum work sum observation. The [validation record](validation.json) identifies the guard and actual frozen scope. Huge exponent cases use bounded saturation without constructing enormous integers. The direct comparison is restricted to shifts of magnitude at most 512.

The wrong alternatives exercise floor in place of truncation, omitted next-height offset, wrong anchor time, wrong spacing, missing final radix scaling, discarded fraction, and missing lower or upper clamp. Each changes an actual calculation. The model does not supply a verdict to any production API.

These checks cover arithmetic and literal time relations. No actual clock is read. No authenticated ancestry, history splice, reorganization, checkpoint or branch selection is tested. Those remain integration requirements. The source's numeric eligibility label is deliberately limited to the mathematical time comparison.

Recorded source and evidence can be inspected without running the reference:

```text
python -I -S -B research/child-work-policy/static_check.py
```

The reference writes its result through exclusive creation. Re-execution requires a fresh finite scope and actual external guard. No CI job or native replay is added by this increment.

## Remaining implementation

No Cargo root, Rust implementation, full node or consensus activation is selected here. The next bounded native task must implement exact full-width target and work arithmetic, integer overflow behavior and typed unverified context using the saved cases and additional genuine invalid-input controls. Its source, dependencies, licenses, executable, fixtures and finite resource admission must be reviewed independently.

Production genesis, target limits, actual descriptor registry, authenticated ancestry and clock source remain absent. Changing the work interval does not modify the retained 120 second monetary reference. Full private authorization, confidential stake, bootstrap, same-header auxiliary binding, state recovery and network gates remain unchanged. Private payments remain the default.
