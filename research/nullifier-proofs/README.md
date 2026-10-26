# Stable nullifier references

The [nullifier proof laboratory](../../docs/nullifier-proof-lab.md) connects retained input secrets to canonical private note openings, stable public nullifiers, hidden depth 32 membership and exact integer conservation. Input commitments, openings, secret bindings, retained secrets, creation versions, indices and siblings remain private witness fields. Two complete 64 byte nullifiers are public.

All data in this directory are public synthetic relation fixtures. The retained byte patterns are deterministic test inputs rather than wallet secrets. Repeated commitments at distinct sparse tree positions do not create independent notes, establish an anonymity set or demonstrate privacy.

## Exact identity

Let $F(x)=\operatorname{u32be}(|x|)\mathbin\Vert x$, chain identifier $\chi$, retained secret $k_i$ and canonical note commitment $C_i$. The existing version 2 identities are

$$
B_i=\operatorname{SHA3\text{-}512}\bigl(F(D_B)\mathbin\Vert F(\chi)\mathbin\Vert F(k_i)\bigr)
$$

$$
N_i=\operatorname{SHA3\text{-}512}\bigl(F(D_N)\mathbin\Vert F(\chi)\mathbin\Vert F(k_i)\mathbin\Vert F(C_i)\bigr).
$$

The exact domains are `thorum.relation-lab.nullifier-secret-binding.v2` and `thorum.relation-lab.note-nullifier.v2`. Each private $B_i$ equals the secret binding field of its canonical input opening. Each $C_i$ comes from that same opening and enters its hidden membership leaf. The same $k_i$ feeds both messages. Root, private path, transaction context, fee and outputs are absent from the nullifier preimage.

Changing an input's immutable creation version changes its commitment and therefore creates a different note. This component has no authenticated current protocol version field. It cannot establish historical eligibility or network version transitions. Existing version 1 and version 2 codecs, vectors and identities remain separate unchanged records.

## Canonical messages and states

The generator uses Python standard library code without importing Rust, a proof backend or another reference generator. Its Keccak implementation derives rho rotations from the coordinate recurrence and checks full digests against `hashlib.sha3_512`. The deterministic self check has 222 messages, including every byte length from zero through 216. All generated canonical hash messages also receive the comparison.

SHA3 follows [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf). State lane index is $x+5y$. Lane bytes are little endian. The rate is 72 bytes, capacity 1024 bits and permutation length 24 rounds.

| Hash operation | Bytes before padding | Padded bytes | Absorptions |
|---|---:|---:|---:|
| Canonical payment commitment | 464 | 504 | 7 |
| Retained secret binding | 123 | 144 | 2 |
| Stable note nullifier | 181 | 216 | 3 |
| Membership leaf | 142 | 144 | 2 |
| Membership parent | 210 | 216 | 3 |

The binding message's secret occupies `[91,123)`. Its SHA3 suffix is `06` at byte 123, followed by zero bytes through 142 and `80` at 143. The nullifier secret occupies `[81,113)` and commitment occupies `[117,181)`. Nullifier padding is `06` at 181, zero bytes through 214 and `80` at 215. All ranges exclude their upper bounds.

The nullifier commitment bytes 26 and 27 occupy message bytes 143 and 144 across an absorption boundary. The committed opening's binding bytes 32 and 33 occupy outer note commitment message bytes 287 and 288, corresponding to opening bytes 241 and 242. Separate adversarial cases change each boundary byte. Their classifications isolate the resulting digest linkage rather than relying only on malformed standalone hash computations.

The full component contains

$$
4\cdot7+2\cdot(2+3+2+32\cdot3)=234
$$

Keccak permutations across 74 complete hash messages and 5616 real round rows. `hash_preimages.json` records every full preimage, padded message and digest. `sponge_blocks.csv` records all 234 full states before absorption, after absorption and after permutation. `keccak_rounds.csv` records all rounds of the first note, first binding, first nullifier, first leaf and first parent, producing 408 selected states. The file order follows the component's semantic schedule. Hash names identify each operation.

`hash_vectors.csv` contains three independent full digest goldens under `thorum.nullifier-proof-lab.leaf.v1`, `thorum.nullifier-proof-lab.node.v1` and `thorum.nullifier-proof-lab.transcript.v1`. These proof adapters are separate from canonical note, identity and tree hash domains. Base field integers use four little endian bytes, node words use eight little endian bytes and transcript input uses raw bytes. A framed domain starts each adapter preimage and an eight byte big endian element count ends it.

`malformed_messages.json` retains ten altered padded messages. Each altered message has genuine Keccak permutation output but violates its expected framing, version domain or SHA3 padding. The raw padded evaluation is deliberately distinct from hashing a canonical byte message with `hashlib.sha3_512`. It is not an alternative accepted codec.

## Relation cases

`nullifier_vectors.json` contains 64 cases, of which 42 satisfy the component oracle. Each case stores its private synthetic witness, exact public statement, complete 520 element public vector and separate Boolean classifications. `valid_component` is the conjunction of canonical opening structure, public statement bindings, membership, input commitment distinctness, bounded integer equality, output commitments, input secret binding derivation, public nullifier derivation and public nullifier distinctness.

| Case class | Scope |
|---|---|
| Shared authority and hidden paths | All 32 individual direction bits and an index with every bit set |
| Stable identity | Identical inputs under valid different roots, paths and transaction contexts retain both nullifiers |
| Distinct retained authority | A second legitimate secret derives its own input binding and nullifier |
| Invalid retained authority | A wrong secret with its correctly recomputed public nullifier and otherwise valid membership fails the opening binding |
| Shared key linkage | Binding and nullifier computations under different retained keys fail |
| Digest linkage | Independent commitment bytes 143 and 144 and binding bytes 287 and 288 fail their respective connections |
| Canonical domains and chain | Version 1 domains and changed chain inputs fail the version 2 relation |
| Duplicate inputs | Repeated commitment and nullifier at distinct positions fail despite valid paths and arithmetic |
| Public binding | Changed public root, output version or nullifier fails |
| Output authority boundary | A changed output secret binding with its correctly recomputed output commitment remains accepted as opaque committed bytes |
| Integer boundaries | Zero totals, exact maximum totals, fees, equal overflowing totals and imbalance |

The first 33 accepting fixtures have byte identical public statements. The stable root and context variants preserve the existing immutable notes and nullifiers while requiring different public proof bindings. The sparse fixture tree has 34 occupied positions and 592 materialized nodes. Its potential capacity $2^{32}$ is not an effective anonymity measurement.

The output binding case records an explicit scope limit. Only input retained secrets are derived in this component. Output authority, recipient encryption and recovery conditions still require their own constraints.

## Reproduction and interpretation

From the repository root:

```text
python research/nullifier-proofs/reference_vectors.py --check
python research/nullifier-proofs/profile_check.py
cargo test -p thorum-nullifier-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-nullifier-proof-lab --release --locked --offline -- --test-threads=1
```

Without `--check`, the generator replaces its deterministic artifacts. It does not generate a STARK proof. The actual relation tests, invalid raw proof constructions and cryptographic verification are separate evidence. The profile guard checks fixed declarations and resolved dependency features.

The private witness includes four 418 byte canonical openings, two retained 32 byte secrets, two `u32` indices and two depth 32 sibling arrays. The public vector contains fee bits, chain, output creation versions, shared asset, root, two output commitments, two nullifiers and context. It contains no input commitment, input creation version, index, path or secret.

A stable nullifier is a deterministic spent identity. Its derivation does not establish ownership or permission to spend. Accepted roots, persistent spent state, atomic consumption, concurrency and branch rollback remain ledger work. Private payments by default remain the required wallet path, with ownership, recipient delivery and the remaining complete payment constraints as implementation gates.

The keyed hash construction has no formal PRF or sender unlinkability claim here. The full STARK and hash composition has no numerical quantum security claim. These fixtures do not measure witness hiding, metadata leakage, timing, memory, throughput or effective anonymity. Existing benchmark records retain their original revisions and workloads.
