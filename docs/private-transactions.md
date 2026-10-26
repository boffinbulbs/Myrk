# Private transaction relation

This document defines required relations, not an implemented privacy proof system.

## Public boundary

The verifier receives a canonical versioned transaction envelope, resource class, fee information, relevant state roots, nullifiers, output commitments, encrypted-data commitments, application identifiers where public, and a transition proof. Exact encoding and visibility remain part of the construction work.

Private witnesses contain owned notes, openings, authorization material, confidential values/assets, private application state, and execution inputs. They must not be transmitted to validators or an unrestricted remote proving service.

## Required relation

For every asset a, a valid ordinary transition must enforce:

```text
sum(inputs[a]) + authorized_mint[a]
    = sum(outputs[a]) + burn[a] + fee[a]
```

Fees belong to the native asset under the fee policy. Ordinary transactions cannot mint the native asset. Native issuance has a distinct kernel-authorized path constrained by height, allocation, eligible duties, and cumulative issuance.

The proof must also establish:

1. Every input is an existing eligible note under the referenced state.
2. The transition is authorized by the correct ownership/application policy.
3. Values and intermediate arithmetic remain within their specified ranges.
4. Nullifiers bind to owned inputs and the protocol domain.
5. Output commitments, asset policies, encrypted-data commitments and public outputs match the same execution.
6. Contract execution follows its metered program and state rules.

The kernel separately rejects globally spent or duplicated nullifiers, invalid state context, noncanonical encodings, and resource excess. A valid isolated proof does not waive these checks.

## Applications

The first contract relations are timed escrow and confidential assets. Escrow must bind release/refund authorization and expiry to a single spendable state. Asset policy must distinguish ordinary transfers from authorized minting and destruction.

## Privacy evaluation

Measure linkage exposed through timing, fees, resource classes, ciphertext shape, application identifiers, note discovery, staking, and network observation. A recipient still knows its own payment details. Plaintext disclosed to a third party cannot be revoked.

No public payment mode or mandatory global viewing authority is part of the transaction design. Dedicated disclosure capabilities must be narrower than spending authority and have explicitly documented scope.
