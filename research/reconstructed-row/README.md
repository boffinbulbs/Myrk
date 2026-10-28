# Conditional reconstructed row references

This corpus independently calculates one complete mathematical ML DSA87 row from private component operands. It covers seven actual matrix streams, sequential modular products and accumulation, shifted t1 transformation, challenge product/subtraction, normalized inverse, same index hint use and exact private 128 byte packing.

The mathematical generator uses Python integers, hashlib and retained public reference oracles. It imports no Rust trace builder, native signer or proof backend. Its stream helper contains independent integer event and carry calculations, with an independently recomputed full state continuation fault. It does not load another large streamed vector corpus.

| Reference object | Coverage |
| --- | --- |
| Retained rows | First and last rows of both retained synthetic key/signature sources |
| Additional inputs | Four canonical endpoint component witnesses |
| Matrix source records | 28 deduplicated genuine matrices, all six full SHAKE128 blocks and 1008 bytes per matrix |
| Full states | 168 complete sponge records and 288 selected Keccak round records |
| Per row arithmetic | Seven accumulator transitions and all 2352 ordered candidate events, exact modular carries, transforms, normalization, 256 hint records and 128 packed bytes |
| False source joins | 13 independently rebuilt false splices, separate from three valid whole input alternatives |
| Bounded stream classes | Eight represented late completion lanes and three unsupported capacities, without a seed preimage claim |
| Unused output fault | One real sixth permutation after a false capacity join, preserving all 840 earlier output bytes and all selected coefficients |
| Proof hash adapters | Complete framed preimages, full SHA3 512 digests and every little endian word for leaf, node and transcript domains |

All polynomial values use canonical normal residues modulo 8380417. Sampled matrix coefficients already represent Ahat in the same odd root ordering as the transformed operands and do not receive another transform. The exact t1 shift is 8192. Its maximum ten bit value maps to q minus one. The inverse includes multiplication by 8347681 before UseHint. Adjacent even coefficients occupy the low nibble of each output byte.

The associated component has 1024 rows, 24794 columns, degree three and 65 public values. The public statement contains a row from zero through seven and an opaque 64 byte context. Context affects the proof transcript but has no canonical transaction mapping. Operands, intermediate arrays and final 128 bytes stay private inside the relation. Their derivation from the same encoded key/signature, complete signature validity, final challenge equality, note ownership and payment authorization are outside this component.

A consistent alternate zhat, chat or hint bank is a different valid component input. A partial substitution of a consumer while its source remains fixed is a false join. The represented injected streams describe bounded control/arithmetic cases and do not assert SHAKE seed preimages. Six block completion is a finite resource profile, not a standard completeness claim for every possible seed.

`source_record.json` records the public retained mathematical inputs, local independent helper and generator hashes, exact generated data hashes and scope. The retained inputs and oracles were already public at revision `061a4ba5a930f8031ea39aa93595311305d07bd8`; that revision does not assert publication of new row implementation code. Project and retained source notices remain in their original locations. No upstream node, wallet or cryptographic implementation is copied into this reference package.

From the repository root:

```text
python research/reconstructed-row/reference_vectors.py
python research/reconstructed-row/reference_vectors.py --check
python research/reconstructed-row/profile_check.py --check
```

The generator resolves the repository root from its installed location. An explicit `--repository-root` supports source staging. Generation reproduces mathematical data, not an actual proof or a verifier result.

The separate `implementation_record.json` pins the final reviewed public source and reference inventory. Its explicit source freeze follows actual implementation validation. The ordinary profile check fails if that record is missing or stale and never regenerates it. The check is Python only and does not invoke Cargo or refresh dependencies. The existing parent hash feature guard separately checks the resolved serial graph in the Rust workflow after dependency fetch. The CI ignored test inventory script is pinned as source without importing or executing it from the reference guard.

Profile/source guards detect changes. Neither they nor the mathematical fixtures establish a complete private signature, full payment, confidential stake, production network or composed post quantum security claim.
