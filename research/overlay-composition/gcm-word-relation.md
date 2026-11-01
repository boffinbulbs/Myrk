# Whole GCM software word relation

This source and mathematical specification defines a finite Boolean relation for the complete retained 64-bit portable AES-256-GCM path. It covers key expansion, every payload block, tag generation, padding and source identity. It proves correspondence to that literal software path under explicit configuration assumptions. It does not claim correspondence to an executed hardware backend, implement an AIR or admit a private payment proof. The [source record](gcm-word-sources.json) states the inspected scope and remaining closure.

This refines the [encrypted output boundary](encrypted-output-boundary.md). The relation's AES key must ultimately be the actual same-opening KEM/KDF result. Treating the key as an input to this mathematical subrelation does not authorize a caller to choose a replacement key or supply an encryption verdict.

## Fixed source configuration and Boolean words

Fix one of the retained portable source configurations, compact or noncompact, as part of the mathematical program. It is not a prover-supplied flag. Both cases below refer to their exact pinned `aes` 0.9.1 source branches. No compiler flag, machine backend, production descriptor or execution class is selected by this specification.

Represent each `u64` value by 64 Boolean variables over a prime field of characteristic greater than three. Represent each byte by its eight Boolean bits. Do not pack a whole 64-bit integer into one field element and infer integer equality from that residue.

Use the following elementary equations, with a new immutable output for every operation and every updated array version.

| Source operation | Exact bit relation |
|---|---|
| Boolean value | $b(b-1)=0$ |
| XOR | $z=x+y-2xy$ |
| AND | $z=xy$ |
| OR | $z=x+y-xy$ |
| NOT | $z=1-x$ |
| Constant mask, copy, fixed shift or rotation | Fixed coordinate identities and constant zero bits |
| Full adder | Boolean $s,c$ with $x+y+u=s+2c$ |

All full-adder integers lie between zero and three, below the characteristic. Their equations therefore establish exact binary addition. A source wrapping operation discards its high carry by definition. It does **not** impose the zero-overflow rule used for monetary accounting. Conversely, truncating an integer is not equality of unconstrained field residues.

For an ordinary `Wrapping<u64>` multiplication in the portable POLYVAL helper, form the 64 shifted partial-product bit rows, add them from a zero accumulator with these adders, and retain the low 64 bits. This fixed construction reproduces the literal wrapping integer product. The subsequent masks and XORs remain separate source operations. It does not replace that helper with an assumed carryless product oracle.

Every constant loop is unrolled in actual source order. Every read refers to the latest prior version of its array coordinate. Snapshot locals in `mix_columns`, `sub_bytes`, `delta_swap` and `xor_columns` retain their original values when later writes occur. These are mathematical wire identities, not an implemented long-distance copy constraint or trusted host map. The [placement obligations](two-phase-wire-binding.md) remain necessary for any local-row AIR.

## Complete portable key expansion

The retained 64-bit implementation stores a four-block state as eight `u64` words and the AES-256 expanded key as 120 `u64` words. Initially the first 16 key bytes are repeated across the four input blocks and bitsliced into key words 0 through 7. The second 16 bytes are similarly placed in words 8 through 15.

Preserve the exact subsequent schedule:

1. Set the source offset to 8 and round-constant index to zero.
2. Perform the source `memshift32` copy into the next eight-word group and advance the offset by eight.
3. Apply the pinned `sub_bytes` assignment network, then `sub_bytes_nots`, then `add_round_constant_bit`, then `xor_columns` with previous-key distance 16 and rotation distance 28.
4. Advance the round-constant index. At seven, stop this expansion loop.
5. Otherwise copy into the next group, advance by eight, apply `sub_bytes` and `sub_bytes_nots`, then `xor_columns` with distance 16 and rotation distance 12. Return to step 2.

There are seven first expansions and six second expansions, plus the two initial groups, giving fifteen eight-word groups. The source then applies its exact compact or noncompact inverse row transforms. Finally it applies `sub_bytes_nots` to every group from 1 through 14. None of those transformations may be omitted because a high-level AES description uses a different key representation.

The substitution helper reads internal names `u7=state[0]` through `u0=state[7]`. Its pinned straight-line AND/XOR assignment list, followed by `state[0]=s7` through `state[7]=s0`, defines all substitution gates. Each assignment is expanded with the elementary bit equations above. It is not a free substituted byte or a table lookup supplied by a witness.

`sub_bytes_nots` complements word planes 0, 1, 5 and 6. The encryption loop intentionally omits those four complements from each substitution and accounts for them in the expanded keys. Adding ordinary S-box complements again on every encryption round changes the literal program.

## Coordinates, all encryption rounds and block separation

For block $b$, AES column $c$, row $r$ and byte bit $p$, the retained bitslice permutation has

$$W_p[16r+4c+b]=\operatorname{bit}_p(X_b[4c+r]),\qquad
0\le b,c,r<4,\quad0\le p<8.$$

The source's byte reorder and three `delta_swap_2` stages exchange disjoint index coordinates to obtain this permutation. Its inverse performs the corresponding swaps and writes the bytes back. Thus all 512 input bits and output bits have exact fixed coordinates. No byte-endian convention is inferred from a host integer conversion.

Start encryption by bitslicing all four blocks and XORing key group zero. The noncompact branch then applies the exact mixed-round sequence `1,2,3,0` three times, followed by mixed round `1`. These thirteen stages use key groups 1 through 13. Perform its terminal `shift_rows_2`, then the final substitution and key group 14, with no final MixColumns. The compact branch has its actual alternating mixed-round and `shift_rows_2` order, including the shift before the final loop break. The final substitution, final key group and inverse bitslice are retained in both cases.

The `define_mix_columns` expansion snapshots all eight old words before writing any new word. Rotations, masks and helper selection for each numbered mixed round are exactly those of the pinned source. Reusing an updated output word as another operand would define a different program.

The four input blocks are independent under this network. After bitslicing, the block label is the word bit position modulo four. All row/column rotations and shifts in the encryption and key helpers are multiples of four. Their masks are constant across each four-bit block-label group. Substitution is bitwise at each position, expanded keys are replicated across block labels, and NOT/add-key operations do not mix labels. The operations therefore preserve block separation and commute with permutations of the four block labels. Applying the inverse bitslice gives the same single-block function in every output position.

This establishes both independence from other batch inputs and equality of the per-block function across batch positions. It matters because the retained single-block wrapper fills block zero with the requested input and the other three blocks with **zero**, while the parallel wrapper receives four actual inputs. It does not repeat the requested input into all four slots. The separation argument lets the complete counter path use either wrapper without changing its visible bytes. This is a structural source argument, not a four-lane test execution or a theorem about an arbitrary AES implementation.

## Every payload and tag block

For the ordinary scope, the input arrays have key 32 bytes, nonce 12 bytes, AAD 1789 bytes and plaintext 418 bytes. The lengths are fixed mathematical instance parameters, not accepted peer resource claims. All bytes are Boolean decomposed and bound to their exact upstream sources.

Let $E_k$ denote the literal portable encryption just defined. Require

$$H=E_k(0^{128}),\qquad J_0=\operatorname{nonce}\Vert\operatorname{BE32}(1),\qquad M=E_k(J_0).$$

For payload blocks zero through 25, XOR the full plaintext block with $E_k(\operatorname{nonce}\Vert\operatorname{BE32}(i+2))$. Block 26 uses the first two keystream bytes with the final two plaintext bytes. The source's temporary block has zeroes in its other input positions. Its unused output bytes are internal and are not appended to the ciphertext.

The actual CTR adapter uses sequential counter generation for both single and parallel calls, so block separation establishes this same byte sequence for its grouping and tail paths. All requested counters are between 1 and 28. There is no wrap in this fixed instance. A proof relation cannot replace the big endian suffix with a little endian counter or skip the mask block.

These requirements cover the logical 29 AES requests, the entire 418-byte ciphertext body and the common expanded key. The source's batching can evaluate extra lanes. No count of executed backend blocks, CPU operations or allocation is inferred.

## Full represented GHASH relation

Form an ordered list of 140 blocks: all full AAD blocks and its own zero-padded tail, all ciphertext-body blocks and its own zero-padded tail, then the two big endian 64-bit **bit lengths**. The ciphertext tag is absent from this list. With the fixed lengths, there are 112 AAD blocks, 27 body blocks and one length block.

Let $B$ reverse the sixteen bytes of a block. Let $D$ be the literal `FieldElement::mulx` operation: little endian 128-bit shift left, discard the high bit, then XOR the previous high bit into positions 0, 121, 126 and 127. Let $\mu$ be the exact portable `FieldElement` multiplication: pinned `bmul`/bit reversal/Karatsuba product followed by the ordered `mont_reduce` transform recorded in the [construction boundary](encrypted-output-boundary.md).

Define

$$h'=D(B(H)),\qquad Y_0=0,\qquad Y_{t+1}=\mu(Y_t\oplus B(A_t),h'),\quad0\le t<140.$$

Require the final sixteen-byte tag to be $B(Y_{140})\oplus M$. The public ciphertext array is the exact 418-byte body followed by this tag. Neither $H$ nor $h'$ is required nonzero. The original computation has no division by either value, and the relation must not introduce one.

For the portable state, the parallel-update adapter processes blocks sequentially, so this recurrence also matches its four-block calls. For the target-dependent R/F implementation, the source expands powers of its represented key and aggregates four unreduced products before one reduction. Establishing equality to this recurrence still needs the actual carryless-intrinsic and representation argument. The polynomial's name or the existence of an R/F paper does not supply that proof.

## Both correspondence directions

Fix the source configuration, all input byte lengths and the exact static operation list above. Assume its fixed copies and input bindings are actual mathematical identities. An honest portable execution supplies an assignment by recording every source operation and updated array version. The bit equations reproduce its Boolean and wrapping arithmetic and therefore satisfy the relation through the complete ciphertext and tag.

Conversely, process the fixed operation list in order. Every Boolean gate has a unique output for its prior inputs. Fixed routing gives the same source bits. Full adders and retained low word bits reproduce the precise wrapping arithmetic. Array reads use their actual preceding versions. Induction therefore fixes all key expansion, encryption, padding, represented products, accumulator and output values to the literal portable source execution. Block separation and the actual adapters give the same complete GCM byte sequence. Thus satisfying the relation implies that portable path's actual output, not merely agreement on an honest test vector.

This proposition is about the fully expanded mathematical relation. It does not assert that a host list index, source hash, compiler or proposed AIR enforces those copies. It is not a theorem about the current hardware dispatch, an accepted existing proof, AEAD security, knowledge extraction or zero knowledge. No graph generator, constraint checker or cipher executed in this increment.

The key, AAD, nonce and plaintext must also be linked to the same actual KEM/KDF/commitment/output-context witness described by the [common payment relation](private-witness-join.md). A separate witness satisfying GCM under a different key or plaintext cannot authorize delivery. This specification does not fill the sixteen-stream KEM finite sampling/completeness gap.

## Execution and resource decision

The portable correspondence is now explicit, but complete proof implementation remains refused. Hardware AES key expansion/intrinsic semantics and compact/noncompact semantic compatibility with a selected runtime remain separate obligations. R/F carryless multiplication and represented-power aggregation likewise need complete correspondence. No CPU backend or forced source flag was selected or executed.

An actual layout must retain all source versions, key bits, substitution and word-product intermediates, accumulators, padding and terminal outputs, or implement a separately justified constrained memory/copy scheme. Key material alone has 120 physical `u64` words in this source representation. Treating a word operation as one field equation or discarding source versions does not account for those objects.

No combined $H/W/PV$, assertion count/order/degree, prepared trace, LDE, normalized quotient/chunks/coupled masks, auxiliary copy phase, claims, duplicate query rows, salts, trees, FRI, entropy, buffers, descriptors, leases, simultaneous memory or complete transport/schema is selected here. Elementary degree two does not select eight quotient chunks or a proving profile. Existing small owner and resource refusals remain unchanged. No cap, class or authorization/encryption primitive is changed.

The next useful evaluation would be one **whole-GCM** finite reference, only after a complete source, literal, control, ownership and resource plan and fresh admission. It must compute the actual equations and both maps, use independently fixed complete expected data, and distinguish portable correspondence from machine backend claims. It cannot be an isolated S-box/block/GF or sampler-prefix demonstration. No such program or runtime is admitted by this document.

## Evidence and remaining gates

New inspection covers the AES-256 portable key expansion, complete encryption and its invoked substitution, bit-routing, mixing and key helpers, software wrapper, actual CTR/cipher tails and portable/target-dispatched POLYVAL source boundaries. AES-128/192, decryption, VAES/ARM paths and unrelated features are outside the selected portable relation. Some hardware paths were only partially inspected. Source pins are not claims of complete transitive body/feature/license review or a library/toolchain audit.

The retained AES-GCM 0.11.1 test source contains complete vectors attributed to NIST CAVS. It was read as data only. It is a retained upstream copy, not a direct new NIST artifact identity or a second executed implementation. No expected outputs were computed by a candidate or old test.

Original RustCrypto dual licenses, Alexandre Adomnicai attribution for the fixsliced source, BearSSL/Thomas Pornin attribution for portable multiplication and HPCrypt attribution in the target path remain preserved. Source/Git identity, local-target and whitespace checks are the only checks selected here.

Full private authorization/parser, confidential stake/bootstrap, authenticated eligibility/origin, durable signing, atomic ledger and network gates remain. Payments remain private by default and the [complete roadmap](../../docs/delivery-roadmap.md) retains its launch requirements and later deferrals.
