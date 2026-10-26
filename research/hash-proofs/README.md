# SHA3 and SHAKE primitive references

This directory records independent byte and state vectors for a standalone hash proof component. The component accepts one private input and publishes its mode, input length, output length, output bytes and context. Its public hash results are an explicit primitive experiment boundary. They are not a production private payment envelope or evidence of owner permission.

The existing version 2 owner binding is unframed `SHA3-512(pk)` over all 2592 encoded ML-DSA-87 public key bytes. The same public key also enters `SHAKE256(pk,64)` as `tr`. These are distinct computations. Knowing a public verification key, proving knowledge of it or reopening its hash does not authorize a transaction. The complete private relation still needs a valid private signature for the exact authorized statement, connected to the same note's owner binding without publishing the key or signature.

## Exact functions

The functions follow [NIST FIPS 202](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf), with the following exact modes:

| Mode code | Function | Rate in bytes | Delimited suffix | Output length |
|---|---|---:|---:|---|
| 1 | SHA3-512 | 72 | `06` | Exactly 64 |
| 2 | SHAKE128 | 168 | `1f` | 1 through 840 |
| 3 | SHAKE256 | 136 | `1f` | 1 through 840 |

All input lengths are between zero and 2592 bytes. The input is unframed. A suffix byte follows the last input byte, zeros fill the final rate block and the high bit of that block's final byte is set. When the suffix and final bit occupy the same byte, the result is `86` for SHA3-512 or `9f` for SHAKE. An input whose length is an exact multiple of the rate requires an additional padding block.

The 1600 bit state begins at zero. Each absorption XORs the message block into the rate portion and preserves the capacity. Every block applies all 24 rounds. Lane index is $x+5y$ with little endian lane bytes. The first output bytes come from the final absorption's state. Additional XOF output applies another complete permutation without adding input, preserving all rate and capacity bytes as its preimage. Output is the concatenated rate portions, truncated to the declared length.

For input length $n$, rate $r$ and positive output length $o$, the stage count is

$$
A=\left\lfloor\frac{n}{r}\right\rfloor+1,
\qquad
Q=\left\lceil\frac{o}{r}\right\rceil-1,
\qquad
P=A+Q.
$$

The supported domain requires at most 37 permutations. This maximum occurs for the 2592 byte SHA3-512 input, whose exact rate multiple requires the final padding block. The corresponding SHAKE128 maximum input and output needs 20 permutations. SHAKE256 needs 26.

## Independent oracle and cases

The generator imports Python standard library modules. It imports neither Rust, another reference generator nor a proof backend. Its manual Keccak implementation derives rho rotations from the coordinate recurrence. Every canonical result is checked against `hashlib.sha3_512`, `hashlib.shake_128` or `hashlib.shake_256`. The deterministic self check includes 2409 mode, input length and output length combinations.

`hash_relation_vectors.json` has 89 classified cases, including 66 satisfying cases. It covers these input lengths for every mode:

```text
0, 1, 71, 72, 73, 135, 136, 137, 167, 168, 169, 2592
```

Each XOF additionally covers these output lengths:

```text
1, 63, 64, 135, 136, 137, 167, 168, 169, 839, 840
```

The main rejection cases have supported mode and length shapes. They alter output bytes, private input, declared input length, mode, suffix, terminal padding, zero padding, rate, squeeze state, squeeze capacity or squeeze absorption. The altered sponge cases use genuine permutation calculations under the wrong transition rules. Their outputs fail the expected canonical function. These oracle classifications are distinct from actual AIR or cryptographic proof rejection.

`api_rejections.json` has eight additional malformed statement cases: mode zero or four, input length 2593, SHAKE output length zero or 841, SHA3 output length 63 or 65 and nonzero output padding. Empty XOF prefixes exist mathematically but are outside this component's supported API.

Each case supplies a private synthetic `input_hex`, exact public statement, complete 913 element public vector and independent classifications for shape, private input length agreement and output computation. The public vector order is mode byte, four big endian input length bytes, four big endian output length bytes, 840 output bytes with zero inactive padding and 64 context bytes. `valid_component` is the conjunction of its recorded conditions. Public output padding is part of the statement rather than a hidden witness channel.

## Authorization foundation examples

`source_public_key.json` copies only the public key from the repository's existing selected official ML-DSA-87 key generation case. It records the source file digest, upstream commit, original case coordinates and public key digest. No signing key or signature is copied into this record. Its source attribution remains the existing [selected vector record](../crypto/vectors/README.md).

`application_inputs.json` constructs an independent synthetic payment statement with one input and one output, using the existing canonical framing $F(x)=\operatorname{u32be}(|x|)\mathbin\Vert x$. The envelope has the required structural lengths and magic, but its KEM ciphertext, note ciphertext and tag are synthetic byte patterns. Their cryptographic validity is not asserted. The record retains complete transaction, application digest and authorization context bytes for review.

The six application hash cases are:

| Input | Hash computation | Scope |
|---|---|---|
| Selected public key, 2592 bytes | SHA3-512 to 64 bytes | Existing unframed owner binding computation |
| Same public key, 2592 bytes | SHAKE256 to 64 bytes | ML-DSA `tr` computation |
| Framed synthetic canonical transaction | SHA3-512 to 64 bytes | Existing application authorization digest framing |
| `tr || 00 || 29 || context41 || A196`, 303 bytes | SHAKE256 to 64 bytes | Exact pure contextual ML-DSA message input |
| `rho32 || column0 || row0`, 34 bytes | SHAKE128 to 840 bytes | Five output block matrix stream prefix |
| `mu64 || synthetic encoded w1`, 1088 bytes | SHAKE256 to 64 bytes | Challenge hash input length and byte ordering |

The 41 byte FIPS context is `Thorum crypto laboratory authorization v1`. Its one byte hexadecimal length is `29`. The application authorization input has 196 bytes and includes the framed 80 byte crypto context and 64 byte application digest. This is pure contextual ML-DSA, distinct from the HashML-DSA interface.

These standalone cases do not constrain signature decoding, strict norm bounds, hint decoding, rejection sampling, matrix generation, challenge sampling, NTT arithmetic, ring reductions, `UseHint`, reconstructed `w1` or signature challenge equality. A bounded XOF prefix does not guarantee that every rejection sampler finishes within it. The synthetic `w1` bytes do not demonstrate polynomial or signature validity. Hashing a transaction example does not connect that transaction to another component's expected statement, ciphertexts or private inputs.

## Full state records and adapter goldens

`hash_preimages.json` identifies eleven selected traces. `sponge_stages.csv` retains all 158 selected full transitions, including the 200 byte states before absorption, after absorption and after permutation. A squeeze stage has zero input bytes and an unchanged absorbed state. `keccak_rounds.csv` records all 24 round states for each stage of the owner public key hash, contextual `mu` hash and five block matrix prefix, with 1080 rows.

The selected traces include all six application examples, same byte suffix and padding boundaries for all modes, and maximum input and output XOF cases. Complete input, padded input and output bytes are retained. The trace records establish deterministic expected computations rather than performance, privacy or security levels.

`hash_vectors.csv` supplies three full digest goldens for `thorum.hash-proof-lab.leaf.v1`, `thorum.hash-proof-lab.node.v1` and `thorum.hash-proof-lab.transcript.v1`. These proof adapter domains are separate from the unframed primitive inputs. Adapter fields and final element counts retain their exact encodings.

## Reproduction and limits

```text
python research/hash-proofs/reference_vectors.py --check
```

Without `--check`, the generator replaces its deterministic outputs. It does not create a proof. A successful oracle comparison does not establish cryptographic soundness or a correct relation implementation. Actual AIR comparison, valid proof generation, invalid raw proof rejection and complete composition review remain separate evidence.

Private payments by default and hidden input commitments remain the protocol targets. A standalone public hash proof is not the private ownership relation. Complete owner authorization must keep keys, signatures and owner bindings inside the composed private proof. No benchmark, independent audit, formal PRF result, quantum knowledge bound or production payment capability follows from these fixtures.
