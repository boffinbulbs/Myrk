# Canonical coefficient and hint references

The reusable arithmetic evaluators implement exact fixed parameter coefficient windows and hint application. The [constraint specification](../../docs/coefficient-constraints.md) defines their integer relations, bounds, required private dataflow and implementation limits. The existing complete transparent [signature reference](../signatures/README.md) supplies public synthetic input fixtures and a separately written verification oracle.

`packing_vectors.py` uses explicit five byte formulas, then compares every genuine window with the full decoder's integer unpacking. It records 2602 key windows, including 42 zero, maximal and single bit windows, and 4624 response windows. The 144 response boundary combinations include 49 valid and 95 invalid strict norm pairs. The other 4480 response windows come from the five genuine signatures. Key scaling is exactly $2^{13}t_1$ with canonical maximum $q-1$.

`reference_vectors.py` uses centered remainders to derive decomposition and hint application. The Rust constraints use quotient, remainder, bounded slack and wrap flags. The generator independently checks all recorded results against the complete signature oracle, including each genuine coefficient's actual packed `w1` nibble. The corpus has 322 rounding boundaries with both hint values, 10240 genuine reconstruction coefficients and 169 invalid public diagnostics. `profile.json` records scalar residual bounds and the exact source fixture hash.

The Rust tests construct actual diagnostic AIR rows and test the reusable returned expressions. Bytewise input and result bindings reject field aliases. Further internal faults cover false strict signs, the positive rounding tie, both special edge endpoints, oversized remainders with matching quotient arithmetic, missing and simultaneous wraps, and nonboolean encodings preserving scalar packed values. The full residue comparison is an exhaustive integer function check rather than an exhaustive AIR or proof run.

The diagnostic windows do not parse complete signatures or verify spending authority. A valid response window and hint output can occur within an invalid full signature. These records provide no proof of complete private signature dataflow, signature knowledge, payment confidentiality, quantum composition or production security. Operational signing material is never used by the reference generators.

The hint evaluator additionally has a test only 256 row hiding proof harness. Its fixed profile and 70 byte public diagnostic vector are documented in the specification. Actual verification tests cover honest boundary proofs, fresh repeated witnesses, all 70 public fields, a different transcript profile, canonical transport corruption and eight raw invalid proofs constructed without witness prechecks. The original multiplication proof API remains the crate's external primitive interface. No hint proof entry point is compiled into ordinary library builds.

```text
python research/coefficient-constraints/packing_vectors.py --check
python research/coefficient-constraints/reference_vectors.py --check
python research/coefficient-constraints/profile_check.py
cargo test -p thorum-arithmetic-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-arithmetic-proof-lab --release --locked --offline -- --test-threads=1
```

All generators use the Python standard library. Registry package versions, archive checksums and the existing multiplication proof profile remain unchanged. The [full signature record](../signatures/source_record.json) retains the standard and exact native source revision. Original dependency license notices remain in the repository inventory.
