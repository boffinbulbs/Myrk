# Transparent relation encoding evidence

The [local relation laboratory](../../docs/relation-lab.md) checks synthetic plaintext witnesses. This evidence tests exact encodings and digests. It is not a zero knowledge proof, protocol security argument, production address format, or complete wallet recovery implementation.

`reference_vectors.py` uses only Python standard library integer encodings and `hashlib.sha3_512`. It does not import the Rust implementation or run its backend to construct expected outputs. The Rust [encoding test](../../crates/thorum-relation-lab/tests/reference_encodings.rs) compares each complete private opening, key binding, 64 byte commitment, nullifier, vote nullifier, Merkle leaf and depth three root with the retained CSV.

The deterministic bytes are public synthetic fixtures. The public key sized byte patterns are hashing inputs, without a corresponding signing key or signature. The secret and blinding patterns must never be used with real value.

## Legacy v1 fixture definition

1. A field is encoded as its four byte unsigned big endian length followed by the exact field bytes.
2. Hash fields are a framed domain followed by each framed input. Every digest retains all 64 SHA3-512 output bytes.
3. The chain bytes run from 0 through 31. Owner bytes are `i mod 251` for indices 0 through 2591. Voting bytes are `250 - (i mod 251)` over the same indices.
4. Nullifier secret bytes are `5b`, serial bytes `d3`, and blinding bytes `c4`, each repeated 32 times. The format is unsigned 16 bit version 1 and the creation version is unsigned 32 bit version 1.
5. The payment asset is `a7` repeated 32 times and its amount is 123456789012345 atoms. The bond uses the zero native asset identifier and 987654321 atoms, with activation epoch 5, maturity epoch 7 and exclusive unlock epoch 20.
6. The vote nullifier uses epoch 9 and duty identifier `39` repeated 32 times. It does not depend on the selected Merkle root or current protocol version.
7. The membership path uses index 5 at depth 3, with sibling bytes `10`, `20` and `30` repeated 64 times at successive levels. An index bit of one places the sibling on the left.

The [relation specification](../../docs/relation-lab.md) defines all opening fields and domain strings. The legacy v1 payload includes the nullifier secret, so its sender can recognize the later nullifier. The original script, CSV and expected digests remain unchanged. Compatibility with this laboratory profile is not approval for a production private format.

## Recipient v2 evidence

The separate `recipient_vectors.py` independently constructs the [v2 CSV](recipient_vectors.csv). The [Rust comparison](../../crates/thorum-relation-lab/tests/reference_capability.rs) checks the complete public capability, payment and bond openings, commitments, spend and vote nullifiers, Merkle leaves and roots, and typed recovery of both policies. V2 uses the same synthetic chain, owner and voting patterns, amounts, serial, blinding, path and epochs defined above.

The synthetic KEM public key is 1,536 zero polynomial encoding bytes followed by the 32 byte sequence from 0 through 31. This is a canonical codec input without a claim of honest key generation or a corresponding secret. Functional encryption and recipient spending tests use generated keys separately.

V2 uses distinct domains for its public capability, recipient key binding, secret binding, opening, commitment, spend nullifier and vote nullifier. The owner key binding remains full SHA3-512 of the supplied public key. The private opening replaces the v1 actual secret field with the full 64 byte recipient encryption key binding. It contains the recipient secret binding but not the actual nullifier secret. The exact field and domain definitions are in [recipient capability and recovery](../../docs/recipient-capability.md).

| Artifact | Legacy v1 bytes | Recipient v2 bytes |
|---|---:|---:|
| Public capability | Not defined | 1,797 |
| Payment private opening | 386 | 418 |
| Bond private opening | 490 | 522 |
| Payment encrypted envelope | 2,004 | 2,036 |
| Bond encrypted envelope | 2,108 | 2,140 |

These are analytical encoding lengths for the retained profiles. Envelope lengths add the existing 1,618 byte experimental overhead. They exclude proofs, transaction framing, authorization, membership, network transport and any future address presentation. They are not throughput or latency measurements.

The retained recipient secret remains a separate authority. Capability construction proves no real world identity, and its consistency cannot prevent substitution of a complete valid capability through an unauthenticated channel. Omitting the secret from v2 delivery does not establish formal nullifier pseudorandomness, full sender unlinkability or anonymous discovery.

## Reproduction

```text
python research/relations/reference_vectors.py
python research/relations/reference_vectors.py --check
cargo test -p thorum-relation-lab --locked --offline --test reference_encodings
python research/relations/recipient_vectors.py
python research/relations/recipient_vectors.py --check
cargo test -p thorum-relation-lab --locked --offline --test reference_capability
```

Generation rewrites the CSV. Check mode compares exact bytes without modifying the artifact. No randomness, timings, remote sources or private credentials enter generation.
