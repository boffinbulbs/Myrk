# Canonical note proof references

The [note proof laboratory](../../docs/note-proof-lab.md) connects the exact SHA3-512 commitments of four canonical payment openings to bounded integer conservation in one hiding proof. All four commitments remain public in this component. The input commitments identify consumed notes if used directly as a transaction format. The experiment therefore does not establish transaction graph privacy, ownership, membership, nullifiers, authorization, recipient encryption or a production payment format.

For private amounts $a_0,a_1,b_0,b_1$ and public same asset fee $f$, the arithmetic rule is

$$
a_0+a_1=b_0+b_1+f\le2^{64}-1.
$$

Each value is individually an unsigned 64 bit integer. Both complete totals must satisfy the sum bound. The same private amount bits enter the constrained canonical opening bytes and arithmetic equations. The fee's asset in this component does not settle production fee policy.

## Independent reference implementation

The [generator](reference_vectors.py) uses Python standard library code and a direct implementation of all Keccak permutation rounds. It does not import Rust, invoke the proof backend or import another reference generator. Direct permutation outputs match `hashlib.sha3_512` on 222 deterministic messages, including empty input, `abc`, multiple block messages and every byte length from 0 through 216. The selected recipient opening and commitment also match the existing [recipient capability fixture](../relations/recipient_vectors.csv).

The standard is [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), sections 3, 4, 5.1 and 6.1. State lane index is $x+5y$, with little endian bytes within each lane. The permutation has 24 rounds. SHA3-512 has a 72 byte rate and a 1024 bit capacity.

The canonical frame is `u32_be(length) || bytes`. A payment opening has 418 bytes. The commitment message is `F(commitment_domain) || F(opening)`, with 464 bytes. The opening starts at message byte 46. Its amount occupies opening byte range `[129,137)` and commitment message range `[175,183)`, encoded as big endian unsigned 64 bit bytes. The padding is `06` at position 464, zero at positions 465 through 502, and `80` at position 503. Seven absorptions consume the padded 504 byte input.

| Artifact | Content |
|---|---|
| [Complete generator](reference_vectors.py) | Independent framing, Keccak rounds, hash cross checks and exact integer oracle |
| [Single note cases](commitment_vectors.csv) | Four complete openings, commitment preimages and digests for amounts zero, one, maximum and the recipient fixture |
| [Opening offsets](opening_offsets.csv) | Every field frame and value range in the opening and complete commitment message |
| [Sponge blocks](sponge_blocks.csv) | Seven rate blocks and complete states before absorption, after absorption and after permutation |
| [Permutation rounds](keccak_rounds.csv) | All 168 full round result states for the recipient fixture |
| [Byte profile](profile.json) | Complete padded input, exact structural mask, fixed bytes, zero offsets and source convention |
| [Four note cases](combined_vectors.json) | Thirteen cases with all four openings, private amounts and complete public statements |
| [Hash adapter cases](hash_vectors.csv) | Exact leaf, node and application transcript preimages under the distinct note proof domains, with complete digests and little endian words |
| [Profile guard](profile_check.py) | Fixed proof declarations, pinned resolved versions and serial feature checks |

The structural mask constrains framing, domains, encoding version, payment tag and SHA3 padding. It has 172 fixed byte positions, including 81 required zero bytes. A zero mask value identifies a variable parameter position. It does not require that parameter byte to be zero. Chain, creation version, asset and amount bindings are additional relation constraints.

All source values are deliberately public synthetic fixtures. The key bytes preserve the earlier codec test and do not claim honest key generation. The references contain private witness data for tests and must not be used as production wallets, keys, randomizers or transfers.

The hash adapter cases use canonical base field integers `[0,1,2013265920,0x12345678]`, node words `[0,1,2^64-1,0,1,...,12]` and transcript bytes `00` through `3f`. The leaf elements have four little endian bytes, node words have eight little endian bytes, and transcript items have one byte each. Each preimage starts with its framed `thorum.note-proof-lab.` domain and ends with an eight byte big endian element count. The complete new domain digests are generated independently rather than copied from the earlier conservation profile.

## Four note conservation cases

The fixed note order is input 0, input 1, output 0 and output 1. Every case supplies shared public chain and asset identifiers, creation versions `[1,2,3,4]`, fee, context, four complete commitments and four canonical openings. Serial and blinding bytes differ across the four notes, and all four commitments are distinct. The public context is bytes `00` through `3f`. The synthetic asset is byte `a7` repeated 32 times.

| Class | Cases | Expected integer result |
|---|---|---|
| Ordinary and large values | Normal, near maximum | Accept |
| Boundaries | Zero, one entirely paid as fee, 32 bit carry, maximum fee, maximum sum | Accept |
| Overflow | Equal overflowing totals, input overflow, output overflow, fee overflow | Reject |
| Unequal totals | One atom inflation, field modulus alias | Reject |

There are seven accepting and six rejecting integer cases. The ordinary case is $(50,50,60,39)$ with fee one. The near maximum case is $(2^{64}-1001,0,2^{64}-1003,1)$ with fee one. Exact input and fee inclusive output totals are retained as decimal strings so an overflowing total does not depend on a bounded JSON integer representation.

`valid_integer` records only the exact arithmetic classification. It is not an authorization verdict or a full ledger acceptance oracle. The separate public duplicate input check and all remaining payment requirements retain their own validation boundaries.

## Reproduction and evidence boundary

From the repository root, exact reference reproduction requires only Python:

```text
python research/note-proofs/reference_vectors.py --check
python research/note-proofs/profile_check.py
```

Generation without `--check` replaces the artifacts with the deterministically reproduced bytes. The generator's independent integer arithmetic and byte states are reference evidence. The [Rust reference comparisons](../../crates/thorum-note-proof-lab/src/reference.rs) and [actual proof tests](../../crates/thorum-note-proof-lab/src/tests.rs) check separate boundaries.

The component checks use the pinned workspace dependencies:

```text
cargo test -p thorum-note-proof-lab --locked --offline
cargo test -p thorum-note-proof-lab --release --locked --offline
```

The release corpus constructs invalid raw traces without relying on the normal witness precheck, then requires rejection by the actual verifier. This exercises a different boundary from local constraint rejection. Debug builds retain upstream assertions that prevent construction of those deliberately false proofs. Neither path establishes the properties omitted from the complete payment relation.

The local note component release suite passes 10 unit tests and one recipient note integration test. It rejects all 28 deliberately invalid raw proofs through the actual verifier. Independent comparisons cover all thirteen combined integer cases, the complete seven block sponge and 168 permutation round states, and three distinct adapter goldens. The integration test obtains four actual canonical openings and commitments through the recipient capability API. These results demonstrate component agreement, without proving ownership, membership, nullifiers or encryption inside the proof.

The profile guard checks both default and all workspace features and rejects a parallel dependency feature. Its checks concern the fixed experiment configuration rather than a cryptographic security argument. The workspace test profile uses optimization level 2 with debug assertions and overflow checks retained. This policy is separate from source identified release benchmarks.

The fixed hiding profile, source inspection and open composition questions are described in the [laboratory record](../../docs/note-proof-lab.md). The [dependency inventory](../crypto/dependency-inventory.json) retains exact versions and original license notices. A passing reference check or advisory lookup does not establish cryptographic soundness, witness privacy or a composed post quantum security level.

No benchmark result is retained for this note commitment relation. Historical primitive and unbound conservation measurements belong to their recorded source snapshots. A new resource report requires its own source and executable hashes, machine, compiler, parameters, repetitions and raw observations. Reference hashes and informal proving runs do not establish production performance or wallet feasibility.
