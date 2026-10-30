# Owned final sponge construction

This component reconstructs the final challenge digest from actual held MU bytes and the completed private W1 bank. It extends the same signature source owner through nine final sponge blocks. No expected challenge or caller preimage enters the candidate state machine.

## Final input and full state carry

The unpadded input is 64 MU bytes followed by 1,024 W1 bytes. The rate is 136 bytes, so eight full input blocks are followed by one padding block. The ninth block begins with 0x1f and ends with 0x80.

For the full 200 byte state, the retained construction follows

$$
S_0=0,\qquad S_{j+1}=\operatorname{Keccak}_{24}
\left(S_j\oplus\operatorname{Extend}_{200}(M_j)\right).
$$

Only the 136 rate bytes are absorbed. Capacity lanes retain the complete previous permutation state between blocks. Four rounds occupy each physical row, giving six rows per block. The first 64 output bytes of the ninth block form the terminal digest without an extra squeeze permutation.

## Temporal ownership

Final rows are 5316 through 5369. The overlay owns `[0,10532)` and `[16271,18959)` only during that interval. These bands contain the four round slots, message bits and output bits. Message and output tails beyond the rate are zero. MU, W1, source words, clock, ports, arithmetic banks and activity remain owned by the real prefix.

Outside the final interval the actual upstream row passes through unchanged. Its retained zero-input dummy resumes at row 5370 and supplies the final row's proper phase. The overlay does not retain the terminal digest in those rows or generate a replacement dummy.

## Reference and diagnostic boundary

The bounded reference explicitly adapts the original global writer to a six-row window and independent full state. Saved MU and W1 populate only the current block's source fields. Nine reference permutations are real work. Shared helper equality is supplemented by the saved independent 64 byte terminal digest. Independent final intermediate states are unavailable in the inspected fixture schema.

A fixed diagnostic also compares terminal bytes with this exact owner's raw signature prefix. It is not execution of the AIR's packed source-port equality. Complete clock and packed-port rows, whole AIR execution and proof integration remain separate gates. No signature or payment acceptor is added by this component.

## Recorded execution

One explicit integration test passed on Windows with Rust 1.94.1, producing 47 synced observations across 8,192 source rows and nine reference windows. Comparisons covered 713,880 final owned fields, 9,792 actual MU/W1 bytes, 9,072 message bytes, 900 input state limbs and 256 continuing capacity limbs. All 1,728 output tail bytes were zero. The terminal 64 bytes matched saved references and this exact owner's raw signature prefix as a diagnostic.

The walk preserved 352,983,912 fields outside the temporal mask. Two earlier genuine source snapshots checked 26,440 restored dummy fields at rows 5370 and 8191. Six comparator corruptions were detected and restored. These source snapshots and comparator controls are distinct from independent hash goldens or AIR rejection tests.

Generation counters report 415 candidate calls and nine reference calls. The pinned generator implies 848 internal round traces. Candidate forward, inverse and hint work remains 16 bodies, eight bodies and 65,536 logical encodings respectively. These internal counts are source inferences. Three logical caches can overlap during reference generation, alongside the six-row reference buffer. Normal public transaction preprocessing remains outside generator counts.

The external guard enforced 512 MiB process and aggregate limits, a 120 second deadline and at least 2 GiB immediately available. Actual kernel peaks were 5,951,488 process private commit bytes and 7,245,824 aggregate commit bytes. Available memory before launch was 7,598,944,256 bytes. There was no timeout, output limit or guard termination. These are component construction measurements.

## Implementation scope

The source and explicit diagnostic compile under default and selected feature profiles. Default complete construction and actual proof resource class refusals remain. Full hiding authorization, private ledger joins and security profile validation remain unfinished.

`static_check.py` checks saved identities, dependency scope, literal aliases and recorded observations. It does not rerun hashes, native construction or proofs. CI compiles the explicit diagnostic without repeating its finite local execution. Original source origins, extraction changes and MIT attribution are retained.

```text
python -I -S research/signature-final-source/static_check.py
cargo test --locked --release --manifest-path research/signature-final-source/Cargo.toml --features final-controls --test final --no-run
```

Any further native attempt needs a fresh reviewed process and aggregate resource admission.
