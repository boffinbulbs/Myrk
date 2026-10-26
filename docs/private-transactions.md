# Private transaction relation

This document defines the complete private transaction requirements. The workspace implements isolated proof components without a complete private payment system.

The [local relation laboratory](relation-lab.md) makes a bounded subset executable with transparent witnesses. The [proof feasibility record](proof-feasibility.md) distinguishes those native checks from the hiding and knowledge soundness requirements of a private proof. Neither record establishes a production private transaction format.

The [hidden membership component](membership-proof-lab.md) proves canonical note commitments, common root membership, distinct private input commitments and exact amount conservation in one hiding proof. Both input commitments, creation versions, indices and fixed depth 32 paths remain private. Its statement exposes the root, shared asset, chain, fee, two output commitments, output creation versions, context and fixed shape. Ownership, stable nullifiers, authenticated eligible roots, recipient encryption and ledger state transitions remain outside that component. These obligations and the separate confidential stake gate remain open before kernel integration.

## Public boundary

The verifier receives a canonical versioned transaction envelope, resource class, fee information, relevant state roots, nullifiers, output commitments, encrypted data commitments, application identifiers where public, and a transition proof. Exact encoding and visibility remain part of the construction work.

The production envelope must exclude input commitments, input creation versions, indices and authentication paths. Shared public asset and same asset fee choices in the membership laboratory are explicit component visibility and arithmetic boundaries. They do not freeze production asset visibility or native fee policy. The accepted root must come from authenticated eligible state, with specified history and branch rules.

Private witnesses contain owned notes, openings, authorization material, confidential values/assets, private application state, and execution inputs. They must not be transmitted to validators or an unrestricted remote proving service.

## Required relation

For every asset a, a valid ordinary transition must enforce:

```text
sum(inputs[a]) + authorized_mint[a]
    = sum(outputs[a]) + burn[a] + fee[a]
```

Fees belong to the native asset under the fee policy. Ordinary transactions cannot mint the native asset. Native issuance has a distinct path authorized by the kernel and constrained by height, allocation, eligible duties, and cumulative issuance.

The proof must also establish:

1. Every input is an existing eligible note under the referenced state.
2. The transition is authorized by the correct ownership/application policy.
3. Values and intermediate arithmetic remain within their specified ranges.
4. Nullifiers bind to owned inputs and the protocol domain.
5. Output commitments, asset policies, encrypted data commitments and public outputs match the same execution.
6. Contract execution follows its metered program and state rules.

The kernel separately rejects globally spent or duplicated nullifiers, invalid state context, noncanonical encodings, and resource excess. A valid isolated proof does not waive these checks.

## Applications

The first contract relations are timed escrow and confidential assets. Escrow must bind release/refund authorization and expiry to a single spendable state. Asset policy must distinguish ordinary transfers from authorized minting and destruction.

## Privacy evaluation

Measure linkage exposed through timing, fees, resource classes, ciphertext shape, application identifiers, note discovery, staking, and network observation. A recipient still knows its own payment details. Plaintext disclosed to a third party cannot be revoked.

No public payment mode or mandatory global viewing authority is part of the transaction design. Dedicated disclosure capabilities must be narrower than spending authority and have explicitly documented scope.
