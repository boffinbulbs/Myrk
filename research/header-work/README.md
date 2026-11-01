# Fixed parent header work

This isolated diagnostic validates the actual Equihash `(200,9)` solution and whole-header SHA256d difficulty filter of one exact 1487 byte Zcash-format header. The saved mainnet genesis header passes and its actual digest matches an independently pinned parent client constant. This is a header work component. Complete auxiliary child binding, authenticated parent history and Kova state acceptance remain separate requirements.

## Byte and policy contract

1. `ExpectedWork::new` expands explicit policy-owned compact target bits. Negative, zero and nonzero overflow values refuse. In this diagnostic the target is independently saved fixture policy. A future node must derive expected difficulty from preceding authenticated state and active rules.
2. `verify_header` borrows exactly 1487 bytes, checks signed little endian version at least four, requires the exact minimal solution prefix `fd4005` and compares the header's raw `nBits` with that context before entering either cryptographic operation.
3. The actual published `equihash::is_valid_solution` receives fixed parameters `(200,9)`, input bytes `0..108`, nonce bytes `108..140` and solution bytes `143..1487`. It computes personalized BLAKE2b leaves and checks collisions, subtree order, distinct indices and the zero root. Solver features are disabled.
4. Two actual SHA-256 invocations hash the entire header. The result is compared with the expanded target as a little endian integer, including equality. Display reversal is confined to the test's known block identity comparison.
5. Errors preserve the original Equihash error in `WorkError::Equihash`. Its default-feature-disabled upstream type does not implement `std::error::Error`, so no nested `source()` interface is claimed. No caller hash, Boolean verdict, callback or cached success token replaces verification.

The default library exports no diagnostic module. The `diagnostics` feature enables the isolated implementation. It has no ledger, proof, private witness, RNG, network or signing imports.

## Independent data and provenance

The binary [fixture](fixtures/mainnet-genesis.bin) is the exact hexadecimal decoding of [Zebra's saved mainnet genesis block](https://github.com/ZcashFoundation/zebra/blob/f72dc18766be63574f17510ee35e61ff2abfe2ae/zebra-test/src/vectors/block-main-0-000-000.txt). It contains 1692 bytes. Only its first 1487 bytes enter the positive verifier. The full block is also tested as an invalid header length.

The independently pinned [Zcash C++ genesis constants](https://github.com/zcash/zcash/blob/558f686599586f55def3db86955d74d3be44605e/src/chainparams.cpp#L333) specify `nBits=0x1f07ffff` and assert block hash `00040fe8ec8471911baa1db1266ea15dd06b4a8a5c453883c000b031973dce08`. The candidate does not generate either expected value. Zebra supplies independent client data, but its Equihash path uses the same library family. This is not a comparison against a second independently executed Equihash implementation.

The actual published artifacts are pinned in [Cargo.lock](Cargo.lock) and [provenance.json](provenance.json). The published Equihash 0.3.0 artifact is distinct from the earlier [Git source selection](../work-authentication/README.md). Its actual package source and archive checksums were checked before compilation. No upstream algorithm is copied or patched. Source review covered the selected verifier, decoder, parameter, hash and buffering call paths. It is not a cryptographic dependency audit. Original fixture and reference notices are retained in [licenses](licenses/).

## Recorded validation

One ignored release diagnostic passed under actual Windows process and aggregate job limits of 512 MiB, at least 2 GiB available memory and a 120 second deadline. The [saved native output](results/native.txt) and [validation record](validation.json) distinguish executed checks from source inspection.

| Executed scope | Count |
|---|---:|
| Actual positive header calls, including restored original input | 2 |
| Length, signed version, minimal prefix and policy refusals before cryptographic entry | 15 |
| Compact-target literal cases | 14 |
| Numeric target comparisons, including actual saved hash against target one | 5 |
| Actual fixed `(200,9)` Equihash mutation rejections | 10 |
| Independent packed-index encoding literals | 8 |

The Equihash controls change input fields, nonce boundaries, solution boundaries and admitted version values. Two further controls create actual duplicate indices and reverse a valid leaf pair. Their original upstream causes identify duplicate indices and incorrect subtree order. These are genuine fixed-profile rejections, not the smaller upstream `(96,5)` negative vectors. The bit framing helper is tested against a saved literal separately from work validity.

Metadata refusal counters measure calls into the two cryptographic entry points. They do not count global allocations or internal hash operations. The insufficient-work branch after a valid solution under another target was not forced. The actual comparator is checked with independent numeric literals and the real saved digest against target one. Changing header target bytes also changes the Equihash input.

Formatting, offline default library checking, strict release Clippy and release test compilation passed. The native peak process commit was 1290240 bytes and aggregate job peak was 2232320 bytes. These small measured peaks are specific to this diagnostic. The recursive verifier owns hash and index vectors, with 512 logical indices, 2048 cursor bytes and an upstream request for 8192 index-capacity bytes. Requested capacity, actual allocation, simultaneous ownership, allocator transients, stack and library costs remain distinct.

Reproduction compiles the ignored diagnostic without executing it:

```text
cargo test --manifest-path research/header-work/Cargo.toml --release --features diagnostics --lib --no-run --locked --offline --jobs 1
cargo clippy --manifest-path research/header-work/Cargo.toml --release --features diagnostics --tests --locked --offline --jobs 1 -- -D warnings
python -I -S research/header-work/static_check.py
```

Native execution requires a fresh finite external resource admission. CI inspects recorded evidence and compilation. It does not replay the ignored verifier diagnostic.

## Integration boundary

A valid parent header does not bind a Kova child candidate, network or treasury destination. Complete auxiliary work must authenticate the applicable parent transaction and authorization commitments under an exact active parent profile. Transaction identity alone is insufficient. See the [mining specification](../../docs/mining.md) and [confidential stake bootstrap dependency](../../docs/confidential-stake.md#first-activation-and-the-bootstrap-dependency).

The predicate also supplies no parent difficulty adjustment, timestamp policy, cumulative work, fork choice, external submission or receipt, private payment proof, eligible stake or activation certificate. The fixture is public parent data and is not a Kova genesis distribution. Payments remain private by default. Full private proof feasibility, same-witness state joins, confidential stake, consensus, recovery and network activation retain their existing gates.
