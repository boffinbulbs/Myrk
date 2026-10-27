# Private owner key preimage binding references

This corpus extends the existing hidden membership and stable nullifier relation with two private key hash preimages. Each input's complete 2592 byte encoding hashes to the exact owner field inside that same canonical private note opening. Keys and owner hashes remain private. The public statement retains its existing 520 field values.

This is preimage binding rather than authorization. Public verification keys may be freely distributed. Knowing one, hashing it or proving knowledge of its hash preimage does not establish permission to spend. A complete private ownership relation still needs a valid signature for the exact reviewed transaction under the same hidden key and note.

## Existing identity and exact byte positions

The source authority is `crates/thorum-relation-lab/src/note.rs`, function `key_binding`. It rejects lengths other than 2592 and returns unframed `SHA3-512(public_key)`. There is no chain field, application domain or length prefix inside that hash. Existing owner bytes and note identities are unchanged. The exact revision, source digest and retained vector digest are recorded in [source_record.json](source_record.json).

For input opening $O_i$ and its private key bytes $K_i$, the new condition is

$$
\operatorname{SHA3\text{-}512}(K_i)=O_i[141,205),
\qquad |K_i|=2592.
$$

The opening enters the existing complete note commitment

$$
C_i=\operatorname{SHA3\text{-}512}
\left(F(\texttt{thorum.relation-lab.note-commitment.v2})\mathbin\Vert F(O_i)\right),
$$

where $F(x)=\operatorname{u32be}(|x|)\mathbin\Vert x$. The owner field consequently occupies outer commitment message bytes $[187,251)$. Its digest bytes 28 and 29 occupy outer bytes 215 and 216 across an absorption boundary, corresponding to opening bytes 169 and 170. Separate hostile cases change each byte while recomputing the correct note commitment, both membership paths, common root and stable nullifier.

The retained nullifier relations are unchanged:

$$
B_i=H(\texttt{nullifier-secret-binding.v2},\chi,k_i),
\qquad
N_i=H(\texttt{note-nullifier.v2},\chi,k_i,C_i),
$$

with the exact existing `thorum.relation-lab.` domains and framed fields. The same opening still supplies owner binding, nullifier binding, commitment and amount. The private membership paths and exact conservation remain linked to those same commitments.

## Unframed SHA3 and complete states

Each 2592 byte key is exactly 36 rate blocks of 72 bytes. SHA3-512 requires an additional complete padding block: `06` at byte 2592, zeros through 2662 and `80` at 2663. The padded message therefore has 2664 bytes and 37 permutations. This exact rate boundary cannot use the padding layout of a truncated 2591 byte message or a framed key.

SHA3 begins from a zero 1600 bit state. Each absorption XORs nine rate lanes and preserves all capacity lanes, followed by all 24 rounds. Lane index is $x+5y$ with little endian lane bytes. The manual Python Keccak implementation derives rho offsets independently and compares every canonical digest with `hashlib.sha3_512`.

The schedule is four canonical note hashes followed, for each input, by one owner hash, one retained secret binding, one nullifier, one leaf and 32 parent hashes. It contains

$$
4\cdot7+2\cdot(37+2+3+2+32\cdot3)=308
$$

Keccak permutations, 76 full hash messages and 7392 real round rows. This fits the original 8192 row design without reducing membership depth. These are analytical dimensions rather than proving time, memory or security measurements.

`hash_preimages.json` retains every full message, padded message and digest. `sponge_blocks.csv` retains all 308 full states before absorption, after absorption and after permutation. `keccak_rounds.csv` records both complete owner hashes and selected existing note, binding, nullifier, leaf and parent rounds, totaling 2184 states. `hash_vectors.csv` contains three independent complete adapter goldens under `thorum.owner-binding-proof-lab.leaf.v1`, `thorum.owner-binding-proof-lab.node.v1` and `thorum.owner-binding-proof-lab.transcript.v1`.

## Cases and retained identities

`owner_binding_vectors.json` contains 85 cases, including 46 satisfying cases. The first 64 are the unchanged old nullifier corpus with the matching synthetic key preimages supplied privately. Its original 42 accepting cases retain the same public statements, commitments, nullifiers, openings and verdicts.

`retained_v2_identities.json` separately retains the original baseline openings, four commitments, root, public nullifiers and complete public vector. Its source vector file is pinned by SHA256 `09648ca4131bd77ab07592461c89e2fc164d2c76218613f328a5e0a1aba84368`. Changing the proof relation or proof adapter namespace does not change those immutable version 2 identities. Existing version 1 files remain untouched.

Additional cases cover distinct and reused key preimages, changed key bindings creating different notes, zero byte preimages, substituted keys, swapped keys, crosswired owner fields, every selected boundary byte, truncated hashes, added framing, chain or domain prefixes, SHAKE substitution, malformed padding and broken capacity continuity. Their note commitments, nullifiers and common roots are rebuilt independently where required, isolating the owner connection rather than an unrelated membership failure.

The zero byte case explicitly records the scope limit: an exact hash preimage is not signing key provenance or signature evidence. The output owner binding case remains accepted as opaque committed bytes, because this component derives only the two input owner hashes.

`altered_owner_hashes.json` retains genuine standalone permutation outputs under altered suffix, padding or capacity rules. These are not alternative accepted SHA3 encodings. `fixed_shape_rejections.json` records three inputs outside the fixed shape of two exact 2592 byte arrays. Host rejection of those shapes is distinct from cryptographic rejection of an invalid composed proof.

All keys, openings, paths and secrets in these files are deliberately public synthetic fixtures. They are not production keys, signatures or entropy evidence. The repeated commitments in the sparse tree do not establish an anonymity set.

## Private and public boundaries

The witness adds `owner_public_keys_hex` to the existing openings, retained secrets, indices and paths. These field names describe public synthetic fixtures rather than a wallet serialization API. The fixed witness constructor receives four 418 byte openings, two exact 2592 byte keys, two retained 32 byte nullifier secrets, two indices and two depth 32 sibling arrays.

The public vector remains 64 fee bits, 32 chain bytes, eight output version bytes, 32 asset bytes, 64 root bytes, 128 output commitment bytes, 128 nullifier bytes and 64 context bytes. It has no input commitment, input creation version, key, owner binding, index, path or retained secret.

The context remains opaque and does not authenticate the signed transaction. Root eligibility, global unspentness, atomic nullifier consumption, encrypted delivery and complete owner authorization remain separate gates. The new hash connection does not grant spending permission to a nullifier or viewing delegate who knows the public key.

## Reproduction and next constraints

```text
python research/owner-bindings/reference_vectors.py --check
python research/owner-bindings/profile_check.py
cargo test -p thorum-owner-binding-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-owner-binding-proof-lab --release --locked --offline -- --test-threads=1
```

The generator uses only Python standard library code, imports neither Rust nor a proof backend and runs no prover. Reference classification, actual AIR checks and real invalid proof rejection are separate boundaries. No performance, independent audit, complete zero knowledge or quantum knowledge soundness claim follows from these fixtures.

The Rust comparisons match all 76 message encodings, all 308 complete sponge transitions, 2184 selected round states, three adapter goldens, all 85 public vectors and all retained version 2 identities. Fourteen release unit tests and one recipient integration test pass, including eight raw false proof rejections. Nine selected debug constraint and reference tests also pass. The [component validation record](../../docs/owner-binding-proof-lab.md) distinguishes those results from complete signature authorization and ledger acceptance.

Canonical decoding, strict `z` norm and canonical hint rules remain required signature constraints, using the same hidden key and signature bytes throughout later verification. Decoding alone still cannot authorize a transaction. Complete private payment and confidential stake gates, hidden inputs, stable nullifiers and private payments by default remain unchanged. The [laboratory record](../../docs/owner-binding-proof-lab.md) defines the implemented boundary and remaining verification obligations.
