# Security status

Thorum is at the reference implementation and protocol research stage. The repository does not contain a production network or an independently audited private transaction or checkpoint construction.

The monetary module checks amount arithmetic and supply transitions. It does not prove transaction ownership, private value conservation, eligible stake, valid block order, canonical parent acceptance, or recovery data availability. These are separate kernel and protocol requirements.

The relation laboratory checks ownership, conservation and stake eligibility locally with plaintext witnesses and externally supplied state. It produces no privacy proof, consensus certificate or persistent state change. Legacy v1 senders know output nullifier secrets. V2 recipient capabilities exclude that secret from sender construction and note delivery, without establishing a formal unlinkability result. Stake statements still expose claims. Plaintext private openings and encryption witnesses must not be transmitted to validators or remote services. These experiments do not complete the private payment or confidential stake feasibility gates.

The original [hiding proof laboratory](docs/proof-lab.md) generates actual STARK proofs for bounded conservation over four private u64 amounts. Its public verifier receives only proof bytes and an expected fee and context. Those amounts have no linkage to ledger notes, ownership, nullifiers, encryption or asset policy.

The [canonical note proof laboratory](docs/note-proof-lab.md) constrains four exact v2 payment commitment computations and the same private amount bits in one hiding proof. Its statement exposes both input commitments and both output commitments. Direct transaction publication would therefore identify consumed notes and expose their relationship to the outputs. The shared public asset, per note versions, fee, context and fixed two input, two output shape remain observable. Hidden amounts and commitment openings do not establish transaction graph privacy.

The earlier note component does not prove ownership, authorization, membership, nullifier derivation or uniqueness, recipient encryption or ledger acceptance. Its public equal commitment rejection prevents duplicate counting only within that statement. The [membership proof laboratory](docs/membership-proof-lab.md) adds two private depth 32 paths under one public root, hides both input commitments and creation versions, and enforces distinct hidden input commitments with conservation inside the proof. Root, shared asset, fee, chain, output versions, two output commitments, context and fixed shape remain public.

Committed owner, nullifier secret and recipient key bindings remain opaque private bytes rather than constrained authority derivations. Hidden membership does not prove that a root is eligible ledger state, that a note is owned or unspent, or that the same note was not consumed by another transaction. Within proof commitment distinctness does not replace stable nullifiers or persistent spent state. Ownership, authorization, nullifier binding, replay protection, authenticated root selection, encrypted delivery and whole payment composition remain unresolved. Complete private payment and confidential stake feasibility are both required before kernel integration. The standard wallet payment path remains private by default, without a transparent fallback. Exact `p3-* 0.8.0` adoption remains confined to the isolated proof laboratories and does not select a consensus backend.

Fixed depth 32 describes potential tree capacity, without establishing an effective anonymity set. The independent sparse fixture deliberately repeats synthetic commitments at multiple positions. Those positions are not independent notes, and successful fixture checks do not establish transaction graph privacy or metadata protection. Proof size, root selection, timing, wallet queries and network observations require their own analysis and measurements.

The inspected backend uses statistical hiding with fresh private proving randomness, both hiding commitment layers and a checked masking budget. This does not establish perfect zero knowledge, a complete quantum knowledge bound or independent review of the local hash composition. Application transcript chaining and Merkle hashing use full SHA3-512 outputs, while upstream fixed transcript metadata includes Keccak256 fingerprints. Proof hiding supplies no memory erasure guarantee. Private amounts, traces, RNG state and prover data must not enter logs. Verification limits proof bytes and structure before backend checks, but the byte cap is not a measured peak memory bound.

The experimental dependency graph includes `paste 1.0.15`, which has the informational unmaintained notice `RUSTSEC-2024-0436` and no patched version in that advisory. This maintenance limitation remains part of dependency evaluation. Advisory checks and source inspection are dated evidence with recorded scope. Independent security review remains required. [RustSec maintenance advisory](https://rustsec.org/advisories/RUSTSEC-2024-0436.html).

Recipient capability consistency does not authenticate the intended person or service. Substitution of a complete valid capability remains an application routing threat. Typed recovery requires an authenticated expected commitment and the recipient's separate nullifier authority. Exported nullifier backups are secret material without storage encryption in this API. A voting delegate given shared nullifier authority can track other disclosed openings under that capability, even without spending keys. Static recipient encryption keys do not provide forward secrecy.

## Security sensitive changes

Review must cover malformed inputs, arithmetic boundaries, state rollback, duplicate application, encoding canonicality, replay across networks, and resource exhaustion. Cryptographic changes must identify the exact construction and security model.

Record verified results separately from intended properties. Do not describe primitive selection, successful unit tests, or analytical calculations as a cryptographic audit.

## Reporting

A private reporting endpoint has not been configured. Repository operators must establish and publish a monitored private reporting channel before accepting sensitive disclosures or operating a public test network. Exploit details should not be placed in public issues before a coordinated reporting route exists.

There are no supported production versions or release security guarantees at this stage.
