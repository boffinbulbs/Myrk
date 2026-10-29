# Private verifier resource accounting

This analysis applies the stored quartic experiment's profile to the complete native signature relation's dimensions. It is static field payload arithmetic. The native relation has not been proved with this backend. The current storage policy rejects its dimensions and byte count before construction.

The [record](record.json) retains exact source identities, the measured small layout crosscheck and the conditional native calculation. [The model](model.py) constructs integers and small metadata only. It never allocates a native trace, starts a prover or changes resource admission.

## Shape equations

Let $N$ be the raw trace height, $W$ its width, $k=4$ the number of random columns, $e=4$ the extension degree and $B=8$ the LDE blowup. The field encoding occupies $s=4$ bytes. These are the retained synthetic experiment settings. They are not selected chain security parameters.

Main preparation has shape $2N\times(W+k)$. Each raw row is followed by $W+2k$ actual random fields in the retained flat append and reshape order. Consequently,

$$
S_{\mathrm{raw}}=sNW,\qquad
S_{\mathrm{prepared}}=2sN(W+k),\qquad
D_{\mathrm{main}}=N(W+2k).
$$

The retained degree four profile has eight coupled quotient chunks. All ten commitment matrices have height $L=2NB$. Their widths are $W+k$ for main, $e+k$ for each quotient chunk and $e+k$ for the separate randomization polynomial. Therefore,

$$
S_{\mathrm{commitments}}=sL\bigl(W+k+9(e+k)\bigr),\qquad
S_{\mathrm{files}}=S_{\mathrm{prepared}}+S_{\mathrm{commitments}}.
$$

The prepared file remains owned by the construction directory in the tested implementation. Its bytes are included even after commitment construction finishes. These expressions count field file contents. File system allocation, operating system cache and resident memory have separate costs.

| Field payload | Completed small proof | Conditional native shape |
| :--- | ---: | ---: |
| Raw trace | 2,048 bytes | 1,803,845,632 bytes |
| Prepared source | 12,288 bytes | 3,607,953,408 bytes |
| Ten commitment files | 1,277,952 bytes | 28,901,376,000 bytes |
| All eleven field files | 1,290,240 bytes | 32,509,329,408 bytes |
| Largest explicit output column | 16,384 bytes | 524,288 bytes |

The small column is an explicit buffer length, not a total prover memory bound. Input and output DFT vectors, implementation scratch and twiddle tables can overlap. The raw matrix is consumed by main preparation and is not retained by that commitment call after preparation returns.

## Access and computation costs

The present ordinary construction reads one checked source window per scalar and seeks to each scalar output position. Its main source read count is

$$
R_{\mathrm{main}}=2N(W+k).
$$

For the native shape this is 901,988,352 checked scalar windows, each using the descriptor lock, length check, seek and canonical decoding. The ten commitment files require 7,225,344,000 scalar field writes. These are source level call counts, not measured physical disk operations or runtime estimates. A larger memory allowance would leave this access pattern impractical to assess without a separate batching design and measurements.

The quotient domain has $8N$ rows. With $C$ constraints per row, $8NC$ counts scalar constraint positions. The native record gives $C=205201$, yielding 13,448,052,736 positions. Vectorization can evaluate several positions together. This product is not an instruction count or a prediction of elapsed time.

## Remaining resident and transport payloads

The separate randomization input contains $2N(e+k)$ fields. Prepared quotient arrays and their coupled mask arrays each contain $8N(e+k)$ fields. The ten base commitment salt matrices contain $10L\times16$ fields. The main, quotient batch and separate randomization commitments each retain one binary digest tree with $2L-1$ digests of 64 bytes. Those three trees exclude all later FRI commitments.

For the native shape, base commitment salt contents alone occupy 83,886,080 bytes and those digest contents occupy 50,331,456 bytes. These figures exclude allocator overhead and are not added into a claimed simultaneous peak. Opening reductions, FRI, AIR expressions, query structures and serialization remain outside this model.

At 64 distinct query indices, main row values alone contain

$$
P_{\mathrm{main}}=64(W+k)s=14{,}093{,}568\ \mathrm{bytes}
$$

under a canonical four byte field encoding. Query deduplication may change the distinct count. This is not the serialized proof size. It omits salts, siblings, quotient and randomization rows, FRI and framing. Two extension field claims per main column add 1,761,696 bytes of field payload. JSON and other transport encodings have additional costs. The existing 2 MiB proof transport test ceiling is not a supported native profile.

## Integration gates

1. Batched input and output access must retain physical row order, exact masks, RNG continuation and unchanged verifier behavior. Synthetic injected failures must leave consistent storage ownership and no fabricated field values.
2. Construction must admit all stages together, including actual temporary storage, DFT scratch, salts, digests, quotient evaluation, reductions and proof transport. Field counts alone do not authorize a larger process.
3. A narrower relation or another proven representation needs its own same witness binding and adversarial tests. Splitting private relations without constraining their joins does not preserve the existing statement.
4. Native proof integration requires a separate finite profile, measured resource bounds and a complete proof accepted by the retained verifier. The current result supplies no native backend proof or private payment admission.
5. Security analysis must cover hiding, knowledge, field and hash assumptions, the quantum model and complete ledger composition. Resource compatibility does not establish those properties.

## Reproduction

From the repository root:

```text
python research/storage-pcs/resources/model.py --check
python -m unittest discover -s research/storage-pcs/resources -p test_model.py -v
```

The tests compare computed file shapes, byte totals and random draw counts against all three completed small proof records. A tiny independently enumerated layout checks physical scalar counts. Invalid dimensions are rejected, and the recorded native dimensions remain outside both the existing shape and byte limits.
