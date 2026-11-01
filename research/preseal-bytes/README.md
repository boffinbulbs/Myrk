# Bounded unverified preseal bytes

This isolated diagnostic implements the complete outer [preseal job format](../../docs/preseal-job.md) for public synthetic bytes. It constructs, parses and hashes actual ordered effect, authorization, recovery and policy bytes. Every returned object remains unverified. It provides no payment, proof, expected state, mining or consensus acceptance interface.

## Byte and ownership contract

1. `parse` first admits at most 65536 input bytes. A private checked cursor requires the exact magic, version, fixed widths, nonzero target, bounded fields, at most four records, reserved kind values and complete input consumption. A private serializer compares the actual parsed values against the borrowed input with a sticky mismatch and exact end check. No second canonical output vector is constructed by parsing.
2. `UnverifiedJob` retains its actual immutable borrowed bytes. Context fields and at most four record descriptors borrow those bytes. This bounds downstream parser storage. It does not bound the caller's upstream allocation or establish immutable external files.
3. `encode` admits all typed source lengths and computes the complete total before requesting one output reservation. It emits the actual context and ordered records into one private vector. It checks the exact output length and unchanged vector capacity. Requested capacity, observed capacity and process allocations are different quantities.
4. The laboratory limits are 1024 policy bytes and 4096 bytes for each effect, authorization and recovery field. The maximum constructible job is `610+1024+4*(86+3*4096)=51130` bytes. These are public synthetic limits, not a production resource profile or a private proof class.
5. SHA3-512 consumes the actual canonical job and exact framed domains from the specification. Record identities derive from the same parsed context and actual effect, authorization and recovery associations. No supplied aggregate root, expected hash, callback or success token is accepted.
6. Descriptor values and reserved kinds remain unverified labels. A nonzero target is a syntax check, not an authenticated difficulty policy. Inner effect canonicality, authorization validity, recovery correctness and treasury authority are not checked. Arbitrary altered authorization bytes are explicitly exercised as unverified data.

The default library is empty. The `diagnostics` feature enables only this component and its exact SHA3 dependency. No keys, RNG, encryption, signing, prover, verifier, PCS, MMCS, challenger, private opening flags, ledger or network instances occur.

Exact registry artifacts, selected features and original licenses are recorded in provenance and retained in [licenses](licenses/). RustCrypto supplies the SHA3, Keccak, digest, fixed array and sponge implementations. The type number and configuration crates retain their own original notices. No upstream algorithm is copied or modified. The selected source path review is not a cryptographic library audit. Local unsafe code is forbidden, while retained dependency internals include unsafe array and byte conversions.

## Independent fixture and recorded validation

The [reference](reference.py) independently frames explicit public literals and uses Python's stock `hashlib` SHA3-512 implementation. It imports no candidate code. Its [927 byte fixture](fixtures/synthetic-job.bin) contains two labelled records with empty and nonempty recovery data and a literal treasury policy. These labels are not real payment or stake objects. Five saved [identities](fixtures/identities.json) are compared with the actual Rust output. The reference also checks a saved empty SHA3 literal, manual encoding anchors and four wrong encoding alternatives. The actual reference constructor was `_hashlib`, separate from RustCrypto.

One ignored release native diagnostic passed under an actual 512 MiB process limit and 512 MiB aggregate job limit, fresh 2 GiB availability and a 120 second deadline. The [native output](results/native.txt), [validation record](validation.json) and [source and dependency provenance](provenance.json) record the scope.

| Executed scope | Count |
|---|---:|
| Independent complete job and record identity matches | 5 |
| Independently mutated nonempty context or record frames | 22 |
| Record order and effect, authorization or recovery association alternatives | 4 |
| Fixed width refusals | 18 |
| Variable length refusals, including maximum unsigned length | 14 |
| Truncated fixture prefixes | 927 |

The same run checks complete builder equality, empty record syntax, the actual 51130 byte maximum, builder limits, count and kind errors, wrong magic and version, zero target, trailing input, reversed length order, checked integer overflow, source borrowing, sticky comparison and changed authorization identity with unchanged effect identity. It observes requested and actual fixture vector capacity of 927 bytes. Allocation failure is not forced. Maximum total is a source contents count, not measured peak memory or serialized private proof size.

The native run reports 0.00 seconds at the test harness precision, 1302528 bytes of peak process private commitment and 2240512 bytes of peak aggregate job commitment. These small figures do not admit full signature proving. All 2546 frozen source, artifact, runtime, fixture and executable inputs were verified afterward. The independent reference, lock preparation, metadata, formatting, default compilation, strict diagnostic lint and release test compilation each ran once under separate guards. No previous proof, verifier, witness, journal or algebra reference was replayed.

Recorded evidence can be inspected without running either producer:

```text
python -I -B research/preseal-bytes/static_check.py
```

Compilation commands are:

```text
cargo check --manifest-path research/preseal-bytes/Cargo.toml --release --lib --locked --offline --jobs 1
cargo clippy --manifest-path research/preseal-bytes/Cargo.toml --release --features diagnostics --tests --locked --offline --jobs 1 -- -D warnings
cargo test --manifest-path research/preseal-bytes/Cargo.toml --release --features diagnostics --lib --no-run --locked --offline --jobs 1
```

Execution requires a separate finite resource admission and the actual external guard recorded in provenance. The ignored diagnostic and exclusive reference outputs are not routine replay targets. No workflow or job layout changes accompany this component.

## Integration boundary

The active class registry, actual inner effect and recovery schemas, complete private proof and parser, authenticated expected state, child difficulty rule, live parent profile and complete auxiliary witness remain absent. Hashing invalid proof bytes does not verify them. Job identities do not replace stable nullifiers or current owner generation and lineage checks at atomic commit.

Complete auxiliary binding still requires the same parent header to authenticate both transaction and authorization paths from the actual canonical carrier. Parent template policy, child threshold and a parent winning claim need distinct enforcement. The existing header diagnostic cannot be relabelled as all auxiliary shares. No complete independent carrier, paths, history component, header and expected child job tuple exists yet.

Private payments remain the default. Same hidden witness ownership, confidential stake, bootstrap, atomic authenticated state, durable signer history, recovery, full security composition and network activation retain their gates. The full signature resource and transport refusals remain unchanged. This component is a byte construction substrate, not a working blockchain.
