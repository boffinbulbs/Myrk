# Architecture

## Component boundaries

Thorum uses one ledger and one set of native conservation and authorization rules. Payment, asset, application, and staking transitions must share compatible ownership, nullifier, commitment, and rollback semantics.

| Component | Responsibility | Evidence required |
|---|---|---|
| Wallet and executor | Discover notes, construct witnesses, execute private application logic, encrypt recovery data | Local reconstruction, restricted key handling, recovery and leakage tests |
| Private proof relation | Bind ownership, asset/value policy, nullifiers, ciphertext commitments and resulting state | Formal relation, adversarial vectors, security analysis and review |
| Validation kernel | Canonical decoding, proof verification, resource limits, global uniqueness and state transitions | Independent validation agreement and rejection vectors |
| Monetary accounting | Scheduled allocation, actual issuance, cumulative cap, completed burns | Integer boundaries, conservation and reference vectors |
| Work adapter | Construct and authenticate child commitments within supported parent jobs | Acceptance of the same work, malformed witness rejection, compatible operator integration |
| Checkpoint consensus | Select eligible support and finalize a valid branch | Explicit assumptions, quorum/liveness rules and adversarial simulations |
| Storage and synchronization | Persist authenticated state and perform consistent rollback | Crash/restart, branch change, pruning and recovery tests |

## State separation

The monetary module owns a narrow accounting transition. A future chain state additionally needs authenticated commitment roots, spent nullifier state, asset policy, execution commitments, block identity/order, and finalized checkpoint context. Passing an amount to an accounting function does not authorize its creation or destruction.

State changes are atomic at the kernel boundary. Failed decoding, authorization, proofs, limits, or checkpoint checks must leave persisted state unchanged. Branch rollback restores monetary counters and private ledger roots from the same state version.

## Cryptographic evaluation

Primitive and backend evaluation targets include ML-DSA authorization, ML-KEM key establishment, authenticated symmetric encryption, and zero knowledge STARK execution. No executable cryptographic evaluation or integrated backend is present in the initial workspace. These targets do not define a complete private protocol.

Evaluation must include recipient anonymity, ciphertext binding, commitment hiding/binding, unique nullifiers, value ranges, execution soundness, quantum model assumptions, and confidential stake eligibility. Public key exposure and historical ciphertext retention are part of the threat model.

The protocol cannot inherit a complete security claim from a primitive's standardization or from a proof engine. Exact versions, parameters, composition, and known limitations need recorded analysis. Primitive/key upgrades require versioned migration rules without an administrative mint or spending bypass.

Primary specifications: [ML-DSA](https://csrc.nist.gov/pubs/fips/204/final), [ML-KEM](https://csrc.nist.gov/pubs/fips/203/final).

## Research gates

The private transaction relation and private stake construction must be demonstrated and reviewed before dependent production interfaces are frozen. No classical voting or eligibility mechanism based on curves can silently satisfy a post quantum native authorization requirement.
