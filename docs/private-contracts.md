# Private programmable applications

Myrk targets its own general programmable private application system. The objective includes private smart contracts, confidential assets, escrow and the Safe under one authenticated ledger. EVM bytecode, Ethereum account semantics and Ethereum tooling compatibility are not prerequisites. No VM, instruction set, compiler, gas schedule or production contract proof class is implemented or selected by this document.

The [minimum private cash release](minimal-launch.md) can precede contract activation. The complete functionality remains in the [architecture](architecture.md) and [delivery roadmap](delivery-roadmap.md).

## Common execution relation

A supported program executes deterministically over its actual private inputs and prior private state. Its proof binds the program/rule version, supported resource profile, expected authenticated state and the exact public transition effects. Those effects include the commitments, stable consumption identities, declared fees, encrypted delivery and any other public outputs required by the active rules. Code visibility and each public field's leakage require explicit specification rather than a blanket claim of invisible execution.

The same hidden values must connect note membership, ownership, real authorization, program operands, amounts/assets, policy checks and the resulting encrypted output state. Public statement equality cannot join unrelated existential witnesses. A host result, supplied digest, external oracle callback or separately accepting component cannot stand in for constrained execution.

The kernel enforces one global spent state, conservation, reward maturity, bond restrictions, eligible history and atomic commit/rollback across payments and calls. A contract has only explicitly defined capabilities. It cannot mint without an authorized issuance rule, spend another owner's notes, bypass Safe recovery restrictions or turn arbitrary data into authenticated state.

## Required construction before implementation

| Boundary | Required decision and evidence |
|---|---|
| Program identity | Canonical program and version descriptors bound to the actual supported verifier, not peer-selected instructions or a caller hash |
| Private state and memory | Constrained addresses, values, ordering, versions, initialization and read-after-write/copy consistency, with terminal and padding semantics |
| Determinism | Exact integer/field operations, ranges, errors, call order, state access and rejection behavior shared by independent implementations |
| Resource accounting | Bounded computation, memory, proof generation, validation, transport and storage, with a specified fee/resource policy and failure atomicity |
| Private calls and composition | Same-source arguments/results and explicit inter-program rights, with no detached proof join or unconstrained hidden state substitution |
| Public effects and availability | Actual canonical effects and encrypted payloads bound to the proof and retained for recipient recovery and node validation |
| Compiler and proving correspondence | Constructive witness mapping and an accepted-relation argument for the exact program semantics, matching verifier/schema and applicable soundness/privacy/knowledge assumptions |
| Upgrades | Unsupported classes rejected, reviewed activation, old-note semantics and stable spent identities preserved, migration and rollback rules tested |

No local width reduction may hide extra trace height, overlapping live banks, omitted operations, larger retained LDE/query contents or a weaker security profile. Host word packing and streaming do not establish a feasible contract proving class. General programmability remains a construction target until its actual matching constraints, resources and verifier are complete.

## Application sequence

The first application milestone remains private timed escrow and confidential asset policy under the common ledger. It must reject conflicting release/refund paths, incorrect expiry, unauthorized issuance, asset substitution, range violations and malformed proofs. These templates provide concrete language/runtime test cases. They do not by themselves establish the full general programmable system.

The [Safe](private-safe.md) adds versioned protected rights, authenticated request origin, delayed completion and restricted cancellation to a committed protected destination. Consensus implementation precedes its wallet interface. Ordinary payment notes cannot become protected merely because a client displays a Safe balance.

Subsequent programmable features are delivered through explicit supported versions with compatible authority, data availability and recovery rules. Deferring their activation keeps the full architectural target while allowing a complete private native-payment chain to be evaluated first.
