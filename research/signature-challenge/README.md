# Represented signature and challenge references

These public retained and synthetic fixtures exercise canonical signature decoding and sparse challenge derivation from the same represented byte string. Canonicality plus sampling is narrower than full signature validity or spending permission. The generator imports no node source, native implementation, proof backend or private artifact. Source provenance and original notices remain in the existing [signature research](../signatures/README.md) and [official vector notice](../crypto/vectors/UPSTREAM-NOTICE.txt).

Reproduction uses the standard Python library:

```text
python research/signature-challenge/reference_vectors.py
python research/signature-challenge/reference_vectors.py --check
python research/signature-challenge/profile_check.py
```

The 124 case corpus is reconstructed directly from public `research/signatures/cases.json` and `synthetic_authorization.json`, with exact z word and sparse hint mutations. Deduplication retains the first occurrence of each of 123 strings. A represented prefix A plus canonical tail B supplies the final partial relation acceptance case. The final corpus has 63 canonical and 61 noncanonical strings.

Independent byte windows check strict z norms, hint cut ranges and monotonicity, ordering within each polynomial and zero padding. The public complete signature decoder independently checks those classifications and decoded private z/h outputs. The public sparse sampler and complete signature reference independently agree on the bounded challenge polynomial and byte cursor for each seed. The joined string is accepted only for this limited relation and is not labeled a valid complete signature.

`source_record.json` pins public inputs, both public reference oracles and this generator. `hash_vectors.csv` independently derives all three complete SHA3-512 adapter digests from the signature challenge namespaces. `profile.json` retains the fixed 512 row, 16650 column layout and 32768 member transport cap. Raw field payload is 34099200 bytes, randomized payload 68214784 bytes and main LDE payload 545718272 bytes. These analytical dimensions exclude other allocations and provide no measured performance claim.

The source change guard and actual proof tests provide separate implementation checks. Reference agreement alone does not establish proof soundness, zero knowledge, complete private authorization, confidential stake or a production transaction route.

The [joint constraint specification](../../docs/signature-challenge.md) defines the exact scope and source connections. The implementation reuses the parent challenge AIR and the arithmetic crate's response decoder. The new workspace dependency intentionally updates the lock file while retaining the registry package set and original license texts. Earlier advisory evidence retains its recorded date and source lock hash.

Component checks run serially:

```text
cargo test -p thorum-hash-proof-lab challenge_sampler::signature:: --locked --offline -- --test-threads=1
cargo test -p thorum-hash-proof-lab challenge_sampler::signature:: --release --locked --offline -- --test-threads=1
cargo test -p thorum-hash-proof-lab --test signature_challenge --release --locked --offline -- --test-threads=1
```
