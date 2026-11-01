# Whole Keccak fixed wiring integer reference

This laboratory evaluates the complete [24 round relation](../overlay-composition/keccak-fixed-wiring.md) as a new integer graph. Two independently retained full state vectors match in every lane. Integer transcriptions check the original round equations and both witness map directions. It executes neither the original Rust AIR nor a production field implementation, prover or private payment verifier.

## Computation and independent data

The graph contains 155,136 operation nodes, 308,736 variable references and 156,736 Boolean values including inputs. Its references are immutable producer identities. The actual builder and evaluator count thirteen graph builds and sixteen full graph assignments in the sole run. Four reverse mappings additionally reconstruct missing intermediate nodes from accepted integer column records and check every graph equation. This does not implement fixed references across rows of an AIR.

The two 25 lane expected states are frozen literals from RustCrypto `keccak` 0.2.2's [XKCP attributed source](evidence/xkcp.rs). The first is the permutation of zero and the second is the permutation of that first state. The program checks all 50 words against that source before evaluating the candidate. It also checks 25 rotation entries, 24 round words and all 1,536 bits of the retained [constant table](evidence/constants.rs). Four manual coordinate anchors and a complete 1,600 coordinate bijection check cover the rotation view. This is a retained source copy, not a newly captured original XKCP artifact or a second executed cryptographic library.

The integer column checker preserves the original preimage, round flag, export, Boolean, parity cubic, theta reconstruction, chi, special lane, iota and round transition equations. Both allowed final export values produce the same permutation output. A full auxiliary witness bijection is not claimed. The equation transcription and graph share elementary Boolean arithmetic. Independent expected outputs provide the separate full state anchors.

## Actual controls

1. Both complete primary vectors, two graph to column maps and four column to graph maps passed, including both final export values.
2. Nine actual row or boundary changes refused with their first numeric causes. They cover flags, preimage, next round input, iota, special lane bits, theta and parity bitness, limb order and an unrelated expected final state. All nine original data restorations passed.
3. Actual nonbit graph values and a forward reference refused. Four malformed word inputs refused for shape, sign, width and Boolean type. These are Python numeric errors, not Rust verifier errors.
4. Six actual alternative computations changed axes, rotation direction, rotation indexing, round constants, ANDNOT operand order and chi's neighbor update order. Each failed the same nontrivial primary output comparison. Six fresh computations with the original equations restored that output.
5. A complete assignment starting with a nonboolean value satisfies all gate equalities modulo the base prime when Boolean equations are omitted. The actual bit checker rejects it. A fresh original assignment then passes. This is a mathematical control for the missing equations, not an accepted proof attack.

## Recorded execution

The sole reference ran with CPython 3.14.5 using isolated mode, disabled site loading and no new bytecode writes. Existing standard library bytecode was included in the freeze because the no-write option does not prevent reads. All 1,701 frozen source, fixture, license, runtime and guard inputs verified unchanged after execution, before publication records were added.

The original external Windows guard installed and read back separate 536,870,912 byte process and aggregate job limits, required at least 2,147,483,648 available bytes and enforced a 120 second deadline. Actual flags were 8960. Process private commit peaked at 42,188,800 bytes, aggregate job commit at 43,483,136 and working memory at 46,895,104. These are this integer diagnostic's observations, not benchmarks or full proving memory estimates. The guard's Rust test summary mode was unused. There is no claimed Rust test count.

The raw [result](results/result.json), [captured output](results/reference.txt), [validation](validation.json) and [source identities](provenance.json) record the scope. A separate [saved evidence inspector](static_check.py) checks those records without importing or running the arithmetic reference:

```text
python -I -S -B research/keccak-fixed-reference/static_check.py
```

Reproducing the reference itself needs a fresh output location, complete source and fixture review and the retained resource guard. Its output uses exclusive creation. No previous model, producer, native test, proof or healthy verifier was rerun. Attribution and original license bytes are retained in [NOTICE.md](NOTICE.md).

## Architecture boundary

Directly materializing the graph still exceeds the current proving class and uses more field cells than the original 24 round column segment. The measured small process does not admit its graph as a proof trace. A complete constrained placement and copy construction, matching verifier, full private relation and bounded proof schema remain absent. The [construction decision](../overlay-composition/authorization-construction.md) and [state consistency contract](../overlay-composition/private-state-events.md) remain in force.

Sponge message binding, rates and padding, the full signature schedule, joint hiding, authenticated oracle compilation, actual Fiat Shamir assumptions and complete private payment joins are separate. No security level, privacy simulator, stake activation, ledger acceptance or network capability follows. Payments remain private by default and the [full roadmap](../../docs/delivery-roadmap.md) is unchanged.
