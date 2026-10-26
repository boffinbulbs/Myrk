# Implementation milestones

## Initial executable boundary

The current executable scope is deterministic monetary accounting under the [60/20/10/10 subsidy profile](subsidy-allocation.md), an isolated [primitive laboratory](crypto-lab.md), a [transparent relation laboratory](relation-lab.md), and two isolated hiding proof laboratories, with reference vectors and reproducible research artifacts. The [recipient capability laboratory](recipient-capability.md) adds a distinct v2 sender interface and typed local recovery while retaining legacy v1 bytes. Transparent relation checkers receive private inputs directly. The [original proof laboratory](proof-lab.md) constrains unbound integer conservation. The [canonical note proof laboratory](note-proof-lab.md) connects four exact SHA3-512 note commitment computations and their private amount bits to conservation in the same proof. Ownership, membership, nullifiers and recipient encryption remain unproved. The workspace does not implement complete private payments, confidential stake, a private transaction system or an active consensus network.

The note component publishes all four commitments, including both inputs, with a shared public asset, per note creation versions, fee, context and fixed shape. Direct transaction use would reveal note consumption and input to output linkage. Complete payment feasibility requires an authenticated hidden input membership construction and stable nullifiers, or a separately justified alternative. This component is not the production private transaction format.

## Milestones and evidence

| Milestone | Deliverable | Acceptance evidence |
|---|---|---|
| Accounting | Atomic units, frozen subsidy table, 60/20/10/10 allocation, miner rounding, cap, actual issuance and burns | Boundary/rejection/conservation tests and independent vectors |
| Primitive feasibility laboratory | Isolated operations for signing, verification, encapsulation, decapsulation and authenticated encryption | Exact backend versions and parameters, real primitive operations, altered input rejection, reproducible size and cost measurements |
| Transparent relation research | Local note, membership, authorization, conservation, encryption and stake eligibility checks | Plaintext witness boundary, independent encoding vectors and adversarial fixtures, no substitution for a hiding proof |
| Recipient capability laboratory | Public sender capability, KEM key binding, v2 opening without the actual nullifier secret, and strict typed recovery | Preserved v1 bytes, separate receiver authority, canonical and context rejection cases, exact recovery and later authorized local consumption |
| Isolated hiding proof component | Fixed binary AIR for four private u64 amounts, bounded conservation, public fee and opaque context | Actual proof verification, invalid raw proof rejection, independent vectors, exact profile checks and bounded canonical transport |
| Canonical note proof component | Exact SHA3-512 for four canonical payment openings linked to the same private amount conservation constraints | Independent full sponge states, amount binding, malformed encoding and raw proof rejection, fixed profile and explicit public input commitment leakage |
| Private transition feasibility | One fully specified and executable private payment relation | Authorization, ranges, conservation, nullifier binding, malformed proof rejection, measured costs and security rationale |
| Private stake feasibility | Confidential eligible weight and checkpoint support | No duplicate weight/reuse, epoch/domain binding, PQ assumptions, bounded certificates and adversarial simulations |
| Ledger kernel | State roots, global nullifiers, canonical decoding, fees, issuance integration and rollback | Independent node agreement, inflation rejection, replay rejection and atomic persistence |
| Applications | Timed escrow and confidential asset policy | Successful release/refund, race rejection and unauthorized mint/burn rejection |
| Mining and finality | Supported parent adapter, AuxPoW, difficulty, branch selection and stake lifecycle | Compatible results from the same work, tamper/replay rejection, partition/reorg/hash change tests |
| Private network integration | Independent server nodes after ledger, mining and finality integration, with peering, synchronization and a defined wallet RPC boundary | Agreement across independent instances, persistence/restart, partitions/reconnection, reorganizations and work/checkpoint interaction |
| Wallet and recovery | Private Send, local validation/proving, restricted voting, backup/restore and metadata controls | Measurements on named hardware, restore/pruning/reorg tests and observer leakage report |
| Treasury simulation | Durable receipts, orders, withdrawals, reconciliation and native burns | Restart/deduplication correctness, failure cases and no consumption of worker funds |
| Protocol pool governance research | Separate pool state and spending rules, private eligible stake ballots, verifiable tally, desktop flow and grant payment lifecycle | Snapshot/weight/duplicate vote proofs, quorum and capture simulations, bounded spending, malformed proposal rejection and private data review |
| Combined synthetic demonstration | Payment, escrow, assets, recovery, auxiliary work, confidential stake and simulated treasury execution | One reproducible checklist with valid and invalid cases, durable reconciliation and no real funds |
| Public test network | Independent operators, pools and adversarial trials | Reproduced validation, payouts, resource limits, concentration/availability observations |
| Release evaluation | Independent composition/implementation reviews and reproducible distributions | Material findings resolved and relevant checks repeated |

The primitive laboratory is a narrower prerequisite to relation feasibility. A successful signature, KEM round trip, or authenticated encryption test establishes only the tested primitive behavior. Conformance claims require applicable reference vectors and recorded coverage. The isolated proof components establish separate evidence for unbound integer conservation and canonical note value linkage. Neither proves complete private payments, confidential stake eligibility, recipient anonymity, complete protocol proof soundness, or a composed post quantum security argument.

Both complete private payment feasibility and confidential stake feasibility must pass before ledger kernel integration can satisfy its milestone. The two feasibility tracks may progress independently. Neither can be replaced by monetary tests, a primitive laboratory result or either isolated proof component. Their exact constructions, assumptions, malformed input behavior, and measured resource requirements must be recorded before dependent interfaces are frozen.

## First application demonstration

The first application demonstration must execute timed private escrow and confidential asset transitions through the common ledger relation. Escrow release and refund must consume the same spending right under the canonical expiry boundary. Asset issuance, transfer, and burn must preserve per asset conservation and policy authority. Local execution and proof generation must be reproducible, with rejection cases for conflicting escrow paths, expired release, unauthorized minting, asset substitution, range violations, and malformed proofs.

## Combined demonstration checklist

The first complete demonstration must cover all of the following in a controlled environment. This checklist records required evidence and is not a claim that the demonstration exists.

1. A private native payment with change, local witness and proof construction, authorized consumption, conservation, recipient recovery, and rejection of a repeated spend.
2. Private escrow release and expiry/refund using one committed spending right, with canonical boundary and conflicting submission tests.
3. Confidential fungible asset issuance, transfer, and burn under an explicit policy, including rejection of unauthorized inflation and asset substitution.
4. Recovery of private notes and application state from declared backup material and retained encrypted data, including missing or corrupted data and branch changes.
5. Acceptance of a valid auxiliary witness and rejection of altered commitments, unsupported parent context, malformed encodings, and replayed work.
6. Confidential eligible stake with chain, epoch, and state binding, with rejection of reused weight after spending, withdrawal, delegation changes, or reorganization.
7. A mock treasury cycle covering receipt, deposit, purchase, partial execution, withdrawal, native receipt, and burn. Restart, duplicate events, failed operations, and reconciliation must preserve worker liabilities and distinguish completed burns from orders or announcements.

Treasury execution in this demonstration uses synthetic records or a sandbox with no real funds. It does not place live orders, transfer external assets, or require production spending keys. Every checklist item must retain its input fixtures, exact reproduction commands, expected valid and invalid outcomes, raw results, and implementation versions. The demonstration does not replace independent review or establish production privacy.

The combined demonstration uses the current 60/20/10/10 monetary profile, including immediate issuance of pool and developer allocations and unissued unearned staking budget. Pool governance remains separately gated. A complete grant system is not a prerequisite for the core demonstration, but accounting for the pool allocation is. Developer credits and external treasury assets retain separate authority boundaries.

## Measurement discipline

Separate analytical schedule projections from measured code performance. Record workload, machine, operating system, toolchain, dependency versions, parameters, repetitions, resource use and uncertainty. Retain raw data and generation commands for published figures.

The [private protocol research specification](research-target.md) defines the formal relations and privacy evaluation gates. The [pool governance specification](governance.md) records unimplemented pool spending and voting requirements. The monetary core calculates pool and developer amounts but does not create payout notes or authenticate destinations. Transparent local reference checks remain research evidence rather than private proof validation.

The [backend feasibility record](proof-feasibility.md) retains exact source versions, source inspection and isolated component adoption, with unresolved complete relation hiding, primitive coverage, knowledge soundness and quantum model requirements. Both proof laboratories pin `p3-* 0.8.0` for their inspected statistical hiding configurations. The note component additionally constrains the SHA3 permutation through the exact `p3-keccak-air` release. This does not select a consensus backend or establish a fixed quantum security level. Legacy v1 senders know output nullifier secrets and can recognize future consumption. V2 capability construction keeps that secret out of the sender interface and provides strict typed local recovery. This removes deliberate secret disclosure in that interface without proving unlinkability, nullifier pseudorandomness, recipient identity, confidential stake, or composed quantum privacy.

Preserving v1 bytes and vectors is laboratory compatibility evidence. A production privacy default must exclude sender known v1 notes or specify an explicit migration. Changing the current protocol version cannot reinterpret an existing note's encoding or reset its nullifier.

Authenticated capability routing, public capability reuse, note discovery, secret backup, private proof integration, and production wallet recovery remain separate gates. Complete capability substitution is not prevented by internal consistency. A static KEM key does not establish forward secrecy. Key rotation creates a different capability while old note recovery still requires the old committed capability and retained authority. Sharing a capability's nullifier secret with a restricted voting service can grant tracking authority across notes using that secret without granting spending authority. Neither laboratory format implements the `thm` production address encoding.

Historical primitive and unbound conservation benchmarks retain their original source and machine provenance. Neither measures the canonical note proof component. Proof resource reports must separately record the actual profile, workload, raw observations, source revision and measurement limits.

## Proof component checks

The release suites include invalid raw proofs constructed without the normal witness precheck. Independent reference and profile checks cover separate boundaries from cryptographic proof verification. The [original proof record](proof-lab.md) and [canonical note record](note-proof-lab.md) define their exact scope. The new component's profile is `thorum.note-proof-lab.v2-payment.sha3-512.serial.p3-0.8.0.v1`, with 1024 original rows, 4262 columns, 64 FRI queries and log blowup 3.

The workspace test profile uses optimization level 2 while retaining debug assertions and overflow checks. This keeps the larger constraint corpus practical without disabling upstream debug validation. Release tests separately construct deliberately invalid proofs after bypassing the local precheck. This execution policy is not benchmark evidence and must not be used to reinterpret retained release measurements.

```text
cargo test -p thorum-proof-lab --release --locked --offline
cargo test -p thorum-note-proof-lab --locked --offline
cargo test -p thorum-note-proof-lab --release --locked --offline
python research/proofs/reference_vectors.py --check
python research/proofs/profile_check.py
python research/note-proofs/reference_vectors.py --check
python research/note-proofs/profile_check.py
```

## Node and desktop integration

The intended deliverable is a complete chain with node software and a desktop wallet. The private network integration milestone follows ledger, mining and finality integration and precedes final desktop wallet integration and public network trials. It does not exist yet. Component proofs precede authenticated state validation, durable persistence, rollback and network synchronization.

Private server trials must use independent node instances and cover peering, initial and ongoing synchronization, persistence and restart, inconsistent peers, partitions and reconnection, reorganizations, resource limits and work/checkpoint interaction. The node RPC and wallet trust boundary must be defined and tested. Independent nodes must agree on valid and rejected transitions and recover the same durable state after restart or a branch change. Starting one process on a server is not sufficient acceptance evidence.

The Qt desktop wallet target includes a local validation node, local witness construction and proving, private payments by default, restricted staking and voting authority, scoped viewing, encrypted backups and recovery. The `thm` address namespace, node resource controls and production codec remain specification work. Escrow, confidential assets and governance depend on the same reviewed ledger and authority boundaries. Wallet integration and public network claims remain subject to the milestones above.

## Release gates

Private PQ transaction and staking constructions must pass their feasibility and review gates before production interfaces that depend on them are frozen. The bootstrap, genesis, difficulty, finality, withdrawal and recovery rules need complete specifications. Source licenses and dependency notices must be inventoried. No release date or security audit completion is implied by a development milestone.

The temporary developer allocation requires a future consensus hard fork for retirement after work completion and community handover. The future miner/stake redistribution, completion criteria, change process, and activation height remain undefined. The pool share stays at 10 percent absent a separate explicit change, and existing legitimately earned credits remain unaffected. No automatic sunset, milestone key, or retirement height is implemented. No production genesis has been released.
