# Hidden membership references

The [membership proof laboratory](../../docs/membership-proof-lab.md) defines a fixed depth 32 membership and value conservation relation for four canonical version 2 payment openings. Two private input commitments are derived from private openings and authenticated against one public root. The public data contains two output commitments, shared chain and asset identifiers, two output creation versions, one same asset fee and a 64 byte context. Input commitments, input creation versions, indices and authentication paths are private witness fields.

All witness values and tree data in this directory are deliberately public synthetic test fixtures. They are not wallet keys, randomizers or transfers. The sparse tree contains repeated commitments at multiple positions. These positions do not create independent notes, increase an effective anonymity set or demonstrate anonymity. The fixture is an exact relation test.

For private input commitments $C_0,C_1$, indices $j_0,j_1$, private sibling arrays $S_0,S_1$ and public root $R$, the membership rule is

$$
\operatorname{PathRoot}(\operatorname{Leaf}(C_i),j_i,S_i)=R,
\qquad i\in\{0,1\}.
$$

The direction at level $\ell$ is $(j_i\mathbin{\gg}\ell)\mathbin{\&}1$, with the least significant bit consumed first. The component requires $C_0\ne C_1$. Distinct indices alone do not establish distinct notes.

The AIR enforces distinctness using 32 canonical unsigned 16 bit limbs of each commitment and private field coefficients $z_k$:

$$
\sum_{k=0}^{31}(c_{0,k}-c_{1,k})z_k=1.
$$

Equal commitments make every term zero. A nonzero limb difference is invertible in the base field, whose prime is larger than any limb. The fixture's duplicate commitment case has valid membership and conservation while this equation is unsatisfiable.

For the note amounts and public fee $f$, exact integer conservation is

$$
a_0+a_1=b_0+b_1+f\le2^{64}-1.
$$

Every amount and fee is individually an unsigned 64 bit integer. Shared public asset binding and this same asset fee rule describe the component scope rather than a final production fee policy. Ownership, spend authorization, nullifiers, encrypted delivery and root authentication remain separate requirements of a complete private payment.

## Canonical messages and sponge states

The generator uses Python standard library code. Its framing and note oracle does not import Rust, a proof backend or another reference generator. The Keccak implementation derives rho rotation offsets from the coordinate recurrence, applies all 24 rounds and checks its result against `hashlib.sha3_512` on 222 deterministic messages. The messages include empty input, `abc`, multiple block inputs and every byte length from 0 through 216.

The standard is [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). State lane index is $x+5y$. Bytes within each lane are little endian. SHA3-512 has a 72 byte rate and 1024 bit capacity. The message frame is $F(x)=\operatorname{u32be}(|x|)\mathbin{\|}x$.

| Hash | Message | Bytes before padding | Padded bytes | Absorptions |
|---|---|---:|---:|---:|
| Payment commitment | $F(\text{note-commitment.v2 domain})\mathbin{\|}F(\text{opening})$ | 464 | 504 | 7 |
| Membership leaf | $F(\text{merkle-leaf.v1 domain})\mathbin{\|}F(\text{chain})\mathbin{\|}F(C)$ | 142 | 144 | 2 |
| Membership parent | $F(\text{merkle-node.v1 domain})\mathbin{\|}F(\text{chain})\mathbin{\|}F(L)\mathbin{\|}F(R)$ | 210 | 216 | 3 |

The exact domain prefix is `thorum.relation-lab.`. Both membership domains have 34 bytes. Membership leaf padding is `06` at byte 142 and `80` at byte 143. Parent padding is `06` at byte 210, four zero bytes at 211 through 214 and `80` at byte 215. These are SHA3 suffix and padding bytes rather than framed fields.

The four commitment calculations and two complete depth 32 paths contain

$$
4\cdot7+2\cdot(2+32\cdot3)=224
$$

Keccak permutations. `hash_preimages.json` records each of the 70 complete messages, padded messages and resulting digests. `sponge_blocks.csv` records all 224 full states before absorption, after absorption and after permutation. `keccak_rounds.csv` records every round state for the first note commitment, first input leaf and first parent, with 288 rows. Hash names identify semantic operations. Their file order does not define a proof implementation's row layout.

`hash_vectors.csv` supplies independent full digest goldens for the distinct proof adapter domains `thorum.membership-proof-lab.leaf.v1`, `thorum.membership-proof-lab.node.v1` and `thorum.membership-proof-lab.transcript.v1`. These proof commitment adapters are separate from the canonical note tree hashes. The leaf uses canonical base field integers `[0,1,2013265920,0x12345678]` encoded in four little endian bytes each. Node words are `[0,1,2^64-1,0,1,...,12]` in eight little endian bytes each. Transcript input is bytes `00` through `3f`. Every adapter message starts with its framed domain and ends with an eight byte big endian element count.

## Sparse tree and cases

The empty leaf is the leaf hash of 64 zero commitment bytes under the fixture chain. Empty subtree hashes are derived recursively. This is a deterministic test convention rather than a frozen production empty tree format.

The tree stores commitment $C_0$ at positions zero and $2^{32}-1$. It stores $C_1$ at each position $2^\ell$ for $0\le\ell<32$. There are 34 occupied positions and 592 materialized nodes across all 33 layers. The full tree has $2^{32}$ potential leaf positions, but generation does not enumerate empty subtrees. Both actual input amounts are 50. Output amounts are 60 and 39, with fee one.

| Case class | Count | Component result |
|---|---:|---|
| One distinct input pair exercising each direction bit | 32 | Accept |
| Index with every direction bit set | 1 | Accept |
| Duplicate commitment at distinct positions | 1 | Reject despite valid membership and conservation |
| Changed sibling, index or disconnected input opening | 3 | Reject membership |
| Changed public root | 1 | Reject membership |
| Changed private input creation version | 1 | Reject membership through the changed commitment |
| Changed public output creation version | 1 | Reject statement binding |

All 33 accepting cases have byte identical public statements. The fixture therefore checks that input index and path changes are represented in the private witness without changing these public fields. Equal public statements and successful relation checks do not establish a proof system's witness hiding property, transaction graph privacy or a quantum security level.

`membership_vectors.json` retains separate expected classifications for canonical opening structure, statement bindings, membership, distinct input commitments, exact integer conservation and output commitments. `valid_component` is their conjunction. The duplicate commitment case isolates hidden input distinctness because both paths and the exact integer equation remain valid.

## Reproduction

From the repository root:

```text
python research/membership-proofs/reference_vectors.py --check
python research/membership-proofs/profile_check.py
```

Without `--check`, the generator replaces its deterministic artifacts. It does not create or verify a STARK proof. Agreement with these fixtures and actual proof rejection tests concern different verification boundaries. The profile guard checks fixed declarations and resolved dependency features rather than proving the arithmetic relation or establishing a security level.

The isolated proof interface accepts `Witness::from_openings_and_paths([[u8;418];4], [u32;2], [[[u8;64];32];2])`. Its fixed public statement is `fee`, `chain`, `output_creation_versions`, `asset`, `root`, `output_commitments` and `context`. `prove_membership` constructs proof bytes from the private witness and statement. `verify_membership` receives proof bytes and an independently supplied expected statement. Neither the API nor these fixtures establish the accepted root's ledger authority or permission to spend.

The component fixes 8192 original trace rows, 4595 columns and 392 public base field elements. The hiding extension has 16384 rows and stored degree bits 14. It uses 64 FRI queries, log blowup 3, challenge extension degree four and four random codewords. Proving and proof tests run serially because of resource requirements. These dimensions describe the implementation. They do not measure execution time, peak memory, anonymity or a composed quantum security level.

The component checks use the pinned workspace dependencies:

```text
cargo test -p thorum-membership-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-membership-proof-lab --release --locked --offline -- --test-threads=1
```

The [laboratory record](../../docs/membership-proof-lab.md) documents the exact relation, proof transport and remaining private payment gates. No new benchmark is retained for this component. Earlier measured artifacts retain their original source revisions and workloads.
