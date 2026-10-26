# Transparent relation encoding evidence

The [local relation laboratory](../../docs/relation-lab.md) checks synthetic plaintext witnesses. This evidence tests exact encodings and digests. It is not a zero knowledge proof, protocol security argument, production address format, or complete wallet recovery implementation.

`reference_vectors.py` uses only Python standard library integer encodings and `hashlib.sha3_512`. It does not import the Rust implementation or run its backend to construct expected outputs. The Rust [encoding test](../../crates/thorum-relation-lab/tests/reference_encodings.rs) compares each complete private opening, key binding, 64 byte commitment, nullifier, vote nullifier, Merkle leaf and depth three root with the retained CSV.

The deterministic bytes are public synthetic fixtures. The public key sized byte patterns are hashing inputs, without a corresponding signing key or signature. The secret and blinding patterns must never be used with real value.

## Exact fixture definition

1. A field is encoded as its four byte unsigned big endian length followed by the exact field bytes.
2. Hash fields are a framed domain followed by each framed input. Every digest retains all 64 SHA3-512 output bytes.
3. The chain bytes run from 0 through 31. Owner bytes are `i mod 251` for indices 0 through 2591. Voting bytes are `250 - (i mod 251)` over the same indices.
4. Nullifier secret bytes are `5b`, serial bytes `d3`, and blinding bytes `c4`, each repeated 32 times. The format is unsigned 16 bit version 1 and the creation version is unsigned 32 bit version 1.
5. The payment asset is `a7` repeated 32 times and its amount is 123456789012345 atoms. The bond uses the zero native asset identifier and 987654321 atoms, with activation epoch 5, maturity epoch 7 and exclusive unlock epoch 20.
6. The vote nullifier uses epoch 9 and duty identifier `39` repeated 32 times. It does not depend on the selected Merkle root or current protocol version.
7. The membership path uses index 5 at depth 3, with sibling bytes `10`, `20` and `30` repeated 64 times at successive levels. An index bit of one places the sibling on the left.

The [relation specification](../../docs/relation-lab.md) defines all opening fields and domain strings. The payload includes the nullifier secret for exact recipient delivery in this local experiment. A sender with that secret can recognize the later nullifier. Recipient capabilities that hide it from the sender remain a production privacy gate.

## Reproduction

```text
python research/relations/reference_vectors.py
python research/relations/reference_vectors.py --check
cargo test -p thorum-relation-lab --locked --offline --test reference_encodings
```

Generation rewrites the CSV. Check mode compares exact bytes without modifying the artifact. No randomness, timings, remote sources or private credentials enter generation.
