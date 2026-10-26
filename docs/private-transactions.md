# Private transaction relation

This document defines the complete private transaction requirements. The workspace implements isolated proof components without a complete private payment system.

The [local relation laboratory](relation-lab.md) makes a bounded subset executable with transparent witnesses. The [proof feasibility record](proof-feasibility.md) distinguishes those native checks from the hiding and knowledge soundness requirements of a private proof. Neither record establishes a production private transaction format.

The [hidden membership component](membership-proof-lab.md) proves canonical note commitments, common root membership, distinct private input commitments and exact amount conservation in one hiding proof. Both input commitments, creation versions, indices and fixed depth 32 paths remain private. Its statement exposes the root, shared asset, chain, fee, two output commitments, output creation versions, context and fixed shape. Stable nullifiers remain outside that earlier component.

The [nullifier component](nullifier-proof-lab.md) additionally constrains two input secret bindings and stable public nullifiers from the same private retained secrets and canonical commitments. Input commitments, secrets, bindings and paths remain private. The identities exclude root and context, while the proof binds the complete expected public statement. Possession of a nullifier secret remains distinct from owner permission. Authenticated eligible roots, global spent state, private owner authorization, recipient encryption and complete ledger transitions remain open, alongside the separate confidential stake gate before kernel integration.

The separate [hash component](hash-proof-lab.md) adds exact SHA3 and SHAKE computations as a foundation for constrained signature verification. Its bounded private inputs produce public hash outputs in a primitive experiment, without a payment acceptance route. It does not link an owner key to a note, verify a signature or authorize a transaction. The future complete relation must retain owner keys, owner bindings, `tr`, `mu` and signatures as internal private witnesses and verify the same authorized transaction against the same hidden note. Publishing those intermediate values or revealing input commitments cannot substitute for that relation.

The separate [arithmetic component](arithmetic-proof-lab.md) constrains exact canonical multiplication under the ML-DSA modulus, with operands and result public only in its isolated harness. It is a prerequisite for later private NTT arithmetic rather than a signature or owner proof. Future composition must keep operands, derived matrices and signature intermediates internal and constrain their connections to the same authorized transaction. The complete private relation and ledger gates remain unchanged.

## Public boundary

The verifier receives a canonical versioned transaction envelope, resource class, fee information, relevant state roots, nullifiers, output commitments, encrypted data commitments, application identifiers where public, and a transition proof. Exact encoding and visibility remain part of the construction work.

The production envelope must exclude input commitments, input creation versions, indices, authentication paths and retained nullifier secrets. Shared public asset and same asset fee choices in the membership and nullifier laboratories are explicit component visibility and arithmetic boundaries. They do not freeze production asset visibility or native fee policy. The accepted root must come from authenticated eligible state, with specified history and branch rules.

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

Stable nullifier derivation does not establish global uniqueness of acceptance. The kernel must atomically check and consume nullifiers against persistent branch state, including concurrent submissions, repeated inputs within a block, restart and rollback. Changing a root or current network version cannot reset the identity of an existing note. Changing an immutable committed creation version instead creates a different note.

## Applications

The first contract relations are timed escrow and confidential assets. Escrow must bind release/refund authorization and expiry to a single spendable state. Asset policy must distinguish ordinary transfers from authorized minting and destruction.

## Privacy evaluation

Measure linkage exposed through timing, fees, resource classes, ciphertext shape, application identifiers, note discovery, staking, and network observation. A recipient still knows its own payment details. Plaintext disclosed to a third party cannot be revoked.

No public payment mode or mandatory global viewing authority is part of the transaction design. Dedicated disclosure capabilities must be narrower than spending authority and have explicitly documented scope.

Sharing a reused capability's nullifier secret grants tracking authority over notes whose commitments are known to the recipient, without necessarily granting spending authority. The experimental keyed hash requires known binding image, chosen commitment, repeated secret and quantum query analysis. Successful relation tests do not supply that argument or a sender unlinkability result.
