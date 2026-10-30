# Owned initial hash sources

This laboratory constructs the initial hash source pass from one owned private witness and its immutable canonical transaction. The new hash cursor and retained decoding state write into the same physical destination. Complete chronological construction, polynomial commitment integration and private payment proofs remain unfinished.

## Source ownership

Witness, Statement and BoundInputs are fresh local nominal types. Private constructor children borrow their fields within the same owner scope. Public authorization bytes derive only from the retained canonical transaction mapper. No old opaque object conversion, private getter or caller supplied hash result is exposed.

The retained build body is unchanged. Its new private children supply the hash cursor, a bounded diagnostic reference and the decoding state. The decoder keeps its original state transition while omitting the unused diagnostic prefix allocator. adaptation.json and reference-adaptation.patch record source origins and explicit changes. Recompiling the same source does not transfer earlier nominal type measurements.

## Initial source transition

For the source state K, current private message M and four actual Keccak rounds per physical row, construction preserves

$$
R_r=\operatorname{Emit}(K_r,M_r),\qquad
K_{r+1}=\operatorname{Advance}(K_r,M_r).
$$

Current hash banks are written before their terminal output is latched. The following row exposes the new value.

| Bank | Producing row | First visible row |
| --- | ---: | ---: |
| Key seed RHO | 0 | 1 |
| Challenge XOF first 136 bytes | 5 | 6 |
| Challenge XOF second 136 bytes | 11 | 12 |
| Verification key owner binding | 233 | 234 |
| Verification key digest TR | 353 | 354 |
| Transaction authorization digest MU | 371 | 372 |
| Private note commitment | 413 | 414 |

The cursor writes only [0, CLOCK) and [MESSAGE, T1), totaling 13780 field columns. It clears those ranges on reuse and preserves all 29396 outside columns. Decoding then writes its separate 7092 column interval, preserving the hash output and all remaining columns. Both cursors use the same owned raw sources.

The initial pass contains 69 logical source permutations followed by one cached genuine zero input permutation. Each logical trace supplies six physical rows from its 24 real round rows. The old cache is dropped before a replacement is generated. A wrong destination size or exhausted cursor refuses before generation, state advance or row writes.

After row 413, held source banks persist and message/output fields remain zero. The genuine dummy round slices are a provisional baseline for later matrix and final hash replacements. The final physical row uses rounds 4 through 7. This cursor is not a complete row source and performs no final wrap update.

## Bounded reference and composition controls

The retained full writer indexes the complete height. A short prefix call would be invalid. The diagnostic therefore uses an explicit private six row block destination adaptation, with separate source banks, state and caches. Its equations and global source positions follow the original writer. The reference never consumes candidate messages, states or cached traces. Shared kernels make this a constructor equivalence reference, rather than independent cryptography.

The fixed B0 diagnostic compares every owned field through all 8192 positions and checks outside preservation. It then composes decoding in the same row and checks the hash regions again. The reference prepares 1366 blocks, with two valid rows in the final block. Fifteen boundary checkpoints check all 560 source bank bytes against retained independent values and one new challenge XOF reference. Destination errors, exhaustion and detected/restored comparator corruptions have bounded observations. Comparator corruptions are equality checks, not proof rejection.

Each cursor generates 69 source traces and one dummy trace. The combined 140 wrapper calls are distinct from the pinned generator's internal work. Each wrapper computes a 24 round input trace and a separate 24 round zero padding trace before returning 32 allocated rows. Thus 280 internal round trace computations follow from the pinned source. They are not separately instrumented or interpreted as backend proofs.

## Independent challenge reference

The only new independent reference computation is

$$
\mathrm{XOF}_{272}=\operatorname{SHAKE256}(\sigma[0:64],272).
$$

It uses the received 64 byte challenge seed without another application prefix. The first source absorb block has SHAKE suffix 0x1f and rate 136. The second source block only squeezes. A separately guarded CPython 3.14.5 and OpenSSL 3.0.20 computation supplies the 272 expected bytes. Other bank goldens are selected from retained reference data and are not recomputed during this preparation.

The scalar expression is reproducible from fixtures-hash.json:

```python
import hashlib
import json
from pathlib import Path

fixture = json.loads(Path("fixtures-hash.json").read_text())
seed = bytes.fromhex(fixture["signature_hex"])[:64]
expected = hashlib.shake_256(seed).digest(272)
assert expected.hex() == fixture["expected"]["challenge_xof272_hex"]
```

Source identities, implementation version and exact reference input are retained with the fixture. CI checks saved provenance and values without repeating this independent hash computation or the native diagnostic.

## Execution and remaining work

validation.json records the selected diagnostic outcome and resource limits. Its scope separates partial source construction, independent bytes, logical comparison positions and generator calls. No complete signature trace, AIR evaluation, commitment, opening or backend proof is supplied by this laboratory.

The selected native integration test passes with 24 observations. Both cursors emit 8192 rows from the same owner, with 15 independent bank checkpoints and the expected generation and refusal controls. Peak aggregate commit is 4567040 bytes under the unchanged 512 MiB process and aggregate limits. The separately guarded scalar reference also completes. These are Windows component measurements.

Later composition must replace the provisional matrix and final rows, connect actual source XOF values to sampling, preserve transform and accumulator overlaps, and implement checked masked random access. Complete main, quotient and auxiliary ownership, transcript configuration, single opening lifetime and transport limits remain separate work. Current full resource refusals stay unchanged.

The complete private payment relation still needs the same hidden eligible note in ownership, membership, stable nullifiers, unspent state, restrictions, conservation and encrypted delivery. Generator equality does not establish full privacy, quantum or knowledge security, or payment authority.

Use Rust 1.94.1 and the committed lockfile. Format the seven new Rust files explicitly with edition 2021 and skip_children=true. Default and selected diagnostic libraries have separate strict lint checks. The unchanged guard bounds process and aggregate commit to 512 MiB, requires 2 GiB available memory and enforces a 120 second deadline. Native execution is disabled by default. The new source is MIT licensed with retained attribution and dependency licenses preserved.
