# Private authorization component map

The [light diagram](figures/private-authorization-gates-light.svg) and [dark diagram](figures/private-authorization-gates-dark.svg) distinguish published component evidence from the missing complete private authorization relation. Their canvas is transparent, with matching geometry and labels.

Solid relationships describe connections within an implemented component. Dashed relationships describe required future joins. The figure supplies a research map rather than a composed proof or performance measurement.

1. Owner binding connects private verification key preimages to owner fields in the same hidden note, membership, nullifier and conservation relation. A key preimage supplies no signing permission.
2. Separate key sources derive private owner, tr, rho and canonical t1 values. Their public context remains opaque.
3. Joint signature decoding connects its represented signature to canonical response/hint decoding and challenge sampling, with a public diagnostic polynomial.
4. Conditional row computation links matrix streams, transforms, subtraction, hints and private output. Its operands remain conditional inputs.

Complete authorization still needs the exact public transaction connected to private mu, the same key and signature operands across all eight rows, full final challenge equality and the same hidden input owner. Delivery, accepted roots, spent state, policy and composed security retain additional gates. Unpublished experiments are outside this public component map.

The [protocol specification](../../docs/research-target.md#separate-authorization-and-cryptographic-evaluation) and [component index](../../README.md#proof-research-map) identify exact public modules and evidence.

## Reproduction

```text
python research/authorization-figures/generate_figures.py
python research/authorization-figures/generate_figures.py --check
```

The standard library generator checks exact bytes, XML, bounded coordinates, transparency, matching themes and contrast. [Fixed data](figure-data.json) records component scope and the [source record](source_record.json) fingerprints inputs and outputs. It creates no proof. Mathematical fixtures, source guards, namespaces, implementation records and frozen research README files retain their original bytes.
