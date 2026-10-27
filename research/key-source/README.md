# Private key source references

This corpus independently calculates canonical ML DSA87 key decoding, SHA3 512 owner digests, SHAKE256 tr digests and exact source lifetimes for two ordered private input slots. It contains public synthetic test data. Key bytes and derived outputs are private banks in the associated relation, without public owner tags.

The generator uses Python integer arithmetic, the standard library hash implementation and retained mathematical reference oracles. It imports no Rust trace builder, native signer or proof backend. Reference reproduction is separate from an actual constraint check, cryptographic verification or an independent security review.

| Reference object | Coverage |
| --- | --- |
| Key encodings and ordered pairs | 13 distinct encodings and 14 pairs, including equal keys and complete slot permutation |
| Canonical decoding | Every 2592 byte key, its 32 byte rho and all 2048 ten bit t1 coefficients |
| Full hash states | 741 complete sponge records and 17784 round records |
| Hash schedule | Two slots, 114 meaningful permutations, four Keccak rounds per physical row and 4096 logical positions |
| Source windows | All 512 ten byte t1 decode windows across the two slots |
| Private lifetimes | One legal key bank reload and exact producer, write and retained output boundaries |
| Hostile calculations | Eight fully recomputed hash faults and nine source or lifetime rejection targets |
| Padding | An independently calculated complete zero input permutation and all four final row slots |
| Proof hash adapters | Complete leaf, node and transcript preimages, all 512 digest bits and all eight little endian words per digest |

The owner hash consumes 36 complete 72 byte input blocks and a separate full padding block. The tr hash consumes 19 complete 136 byte blocks and an eight byte tail with its exact suffix and terminal padding. Every 200 byte sponge continuation retains the full capacity. Each t1 event reads ten exact key bytes and decodes eight coefficients. No host key equality result replaces these source relationships.

Equal keys in distinct ordered slots and a complete exchange of both keys and their corresponding outputs are valid inputs to this limited relation. A represented rho from one retained key and tail from another is also a valid canonical encoding. Such examples do not establish legitimate note ownership or signature authorization. Partial source, output or lifetime substitutions must fail the actual relation.

The declared diagnostic profile has 1024 rows, 20168 columns, degree four and a 64 byte opaque context as its only public vector. Context affects the proof transcript but has no canonical transaction mapping in this component. The relation does not verify a complete signature, connect a hidden input note, authorize spending or establish complete private payment or confidential stake feasibility.

The retained input data and mathematical sources are unchanged at public commits `061a4ba5a930f8031ea39aa93595311305d07bd8` and `a586c32004f9ef499a855caf4c9574976ad6bd25`. Those identifiers describe the existing reference inputs, without asserting a public revision of new key source code. `source_record.json` records the exact original source hashes. Project and retained source license notices remain in their existing locations.

From the repository root:

```text
python research/key-source/reference_vectors.py
python research/key-source/reference_vectors.py --check
```

The repository root is resolved from the installed `research/key-source` location. An explicit `--repository-root` is available for staging. Every fixture is regenerated from retained public inputs. The full vector file is retained without reducing the canonical byte, pair, hash, round or hostile coverage.
