# Owned signature source construction

This laboratory extracts the decoding state transition from the complete packed signature constructor. A fresh cohesive source version owns raw verification key, signature and note bytes together with the immutable canonical public transaction. The real retained AIR and constructor modules compile in that same ownership scope.

The implemented decoder writes a defined subset of a physical row. Complete streamed construction, hiding proofs and private payment integration remain unfinished.

## Nominal ownership

Witness, Statement and BoundInputs are local nominal types with private fields. Public authorization values derive from the actual canonical transaction mapper. The producer borrows the same owned raw source without cloning it or accepting decoded operands. No conversion from earlier opaque witness objects, private getters or caller callbacks is exposed.

The copied build body remains unchanged. Its sole structural addition is a private producer child under the diagnostic feature. That child legally shares the retained decoding module and its parent owner. Other constraint modules use their exact pinned source paths. adaptation.json records origins and changes. Equal source bytes do not make the old and new Rust declarations interchangeable or transfer earlier execution results.

## Partial row transition

For private sources w and the current decoding state S, row construction follows

$$
D_r=\operatorname{Emit}(S_r,w,r),\qquad
S_{r+1}=\operatorname{Advance}(S_r,w,r).
$$

The current row contains the state before its update. Source bytes and range auxiliaries appear on the instruction row. Newly decoded key coefficients, signature coefficients and hint history become visible on the following row.

The decoder owns the contiguous interval [T1, SIGN_BITS), containing 7092 field columns. Each call clears that interval before writing current values, including dormant auxiliaries. All other columns remain untouched. The cursor is private and advances once per accepted destination. A malformed row or exhausted cursor leaves the destination and state unchanged.

The last key coefficient update is at row 255, the last hint update at row 74 and the last signature coefficient update at row 447. Their complete held banks are visible at rows 256, 75 and 448 respectively. Hint activity, sorted segments, bounds, complements and unused source padding retain their exact encoding rules. Canonical residue arithmetic uses modulus 8380417.

This is not a complete row source. Hash, sampling, transforms, matrix accumulation, inverse transforms, final hashing, source ports and clocks still need their own state extraction and composition. Their row schedules overlap. In particular, inverse initialization begins while later accumulator blocks are still completing point subtraction. A global phase barrier would change the relation.

## Source equivalence controls

The diagnostic feature uses the unchanged retained decoding loop once on a zeroed prefix of 449 actual width rows. Its 77544096 byte buffer preserves the original internal state through row 448. All state changing branches have ended by then. For this decoding subset alone, later reference rows are equal to row 448.

Each new cursor still advances through all 8192 physical positions. Every owned column is compared with the corresponding retained prefix row or its stable terminal row. Nonzero poison detects stale auxiliaries, while an outside sentinel verifies the subset write boundary. The oracle preserves source behavior. It is not independent cryptography or an AIR verdict.

Two traversals run serially with one reference buffer live at a time. The baseline uses the retained synthetic key B, signature B0 and note N_B. The second changes only the first packed signature coefficient pair to its two exact legal encoding endpoints. That changed source is not asserted to be a valid signature. Independent retained key coefficients, signed signature coefficients and hint bits supplement the source oracle. The endpoint residues have explicit boundary expectations.

Further controls cover seven actual encoding refusals, destination shape errors, exhaustion without writes and detected/restored comparison corruptions. Comparison corruption controls test the equivalence observer. They are distinct from proof rejection. Bounded observations retain actual outcomes without returning private rows. Each selected run requires fresh result paths and one test thread.

The selected scope and actual guard outcome are recorded in validation.json. No complete signature trace, Keccak permutation, symbolic AIR, commitment, PCS opening or backend proof belongs to these decoding controls.

All three selected groups pass with 15 observations. The two main walks emit 16384 partial decoding rows and check 11776 terminal reference values. Two further emissions verify cursor recovery after destination errors. The kernel records 80711680 bytes of peak aggregate commit under the unchanged 512 MiB process and aggregate limits. These measurements concern the partial decoding diagnostic on Windows.

## Remaining integration

Sequential emission does not implement the random access masked views required by quotient construction and polynomial commitments. Main, quotient and auxiliary data need one explicit reservation and opening lifetime, exact target configuration checks and complete transcript binding. Current full width, field and transport refusals remain unchanged.

The completed private payment relation must connect the same hidden eligible note to ownership, stable nullifiers, unspent state, restrictions, conservation and encrypted delivery. Source equivalence does not establish those joins or full system privacy and post quantum security.

## Reproduction

Use Rust 1.94.1 and the committed lockfile. Format the five new Rust files explicitly with edition 2021 and skip_children=true. This preserves the exact retained source files and their measured identities. The default library and the selected decode-controls library and integration target have separate strict lint checks. Automatic integration discovery, library tests and doctests are disabled. No old test module is selected.

The unchanged small Windows guard enforces 512 MiB process and aggregate commit limits, at least 2 GiB available memory and a 120 second deadline. Native execution remains disabled. A diagnostic feature is not permission to construct or prove the full signature relation.

provenance.json records source, registry, feature and execution identities. Fixtures select existing synthetic sources and independent values without generating signatures. The new source is MIT licensed. Original dependencies, retained code and source notices keep their attribution and licenses.
