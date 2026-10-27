# Implementation milestones

The [development stages and feature boundaries](delivery-roadmap.md) define the delivery sequence. Private authorization and confidential stake remain current feasibility gates. The Safe, its Qt interface and fast payment locks have distinct later milestones and acceptance evidence.

## Initial executable boundary

The current executable scope is deterministic monetary accounting under the [60/20/10/10 subsidy profile](subsidy-allocation.md), an isolated [primitive laboratory](crypto-lab.md), a [transparent relation laboratory](relation-lab.md), and eight isolated hiding proof laboratories, with reference vectors and reproducible research artifacts. The [recipient capability laboratory](recipient-capability.md) adds a distinct v2 sender interface and typed local recovery while retaining legacy v1 bytes. Transparent relation checkers receive private inputs directly. The [original proof laboratory](proof-lab.md) constrains unbound integer conservation. The [canonical note proof laboratory](note-proof-lab.md) connects exact SHA3-512 payment commitments to conservation. The [membership component](membership-proof-lab.md) additionally hides both input commitments, creation versions, indices and depth 32 paths, proving common root membership and distinct input commitments in the same conservation proof. The [nullifier component](nullifier-proof-lab.md) further links retained input secrets to their private committed bindings and stable public nullifiers in the same proof. The separate [hash component](hash-proof-lab.md) constrains unframed SHA3 and SHAKE over private bytes as a foundation for later private signature verification. Ownership, recipient encryption, global spent state and eligible root policy remain outside these components. The workspace does not implement complete private payments, confidential stake, a private transaction system or an active consensus network.

The earlier note component retains its public input commitments as an isolated experiment. The membership component exposes a root, shared asset, fee, chain, output creation versions, two output commitments, context and fixed shape, without nullifier derivation. The nullifier component adds two stable public identities while retaining hidden input commitments and paths. Its root has no ledger authority without an authenticated eligibility policy. Complete payment feasibility still requires ownership and authorization, persistent spent state, encrypted delivery and composition analysis. Nullifier secret possession does not establish owner permission. No component is a production private transaction format. Private payments by default remain mandatory for the standard wallet path, without a transparent fallback.

The hash component publishes its mode, lengths and expected output only within a primitive experiment. It does not provide signature verification or whole transaction coupling. Public key hashing does not grant owner permission. The complete private relation must keep owner keys, owner bindings, `tr`, `mu` and signatures internal while checking the same transaction and hidden note. The primitive output interface does not define a ledger payment route.

The same crate now contains a [connected matrix sampler](matrix-sampling.md). One AIR binds a private seed to six complete SHAKE128 blocks, exact rejection decisions, ordered outputs and terminal completion. Its public polynomial diagnostic and bounded capacity supply no key anonymity, complete signature permission or production resource policy. The same hidden key and private matrix arithmetic still require direct connection.

The [sparse challenge sampler](challenge-sampling.md) connects the same private challenge seed and two complete SHAKE256 blocks to exact acceptance, sign selection and signed relocation. Its bounded diagnostic interface and raw false proof tests do not complete the same witness signature relation. Full private key parsing, connected arithmetic, final challenge equality and hidden note authorization remain required.

The [joint signature component](signature-challenge.md) adds canonical signature decoding against that same private seed and a held signature tail. Actual response gadget outputs populate private registers, and canonical hint events populate private Boolean state. It reuses the parent challenge AIR and existing arithmetic decoder. Its diagnostic public polynomial remains separate from full key parsing, connected signature arithmetic, challenge equality and spending permission.

The [private key source component](key-source.md) connects each of two encoded verification keys to exact private owner, tr, rho and t1 results. A single held source bank is reused only after its consumers finish, while each slot's derived outputs remain private and retained. Its opaque public context has no canonical transaction mapping. Complete same note ownership and signature authorization still require the missing direct connections.

The [arithmetic component](arithmetic-proof-lab.md) adds exact canonical multiplication modulo 8380417 with bounded carries and complements. Its public operand harness is a primitive validation boundary. Complete private NTT dataflow, signature verification and owner authorization remain unimplemented. Future wiring must keep derived matrices and signature intermediates private and connect every operation to the same actual computation.

Reusable [coefficient and hint evaluators](coefficient-constraints.md) add canonical five byte key and response windows, strict response norms, signed conversion and exact hint application. Their independent fixtures include genuine full signature coefficient stages. A separate test only hint harness checks actual proof rejection. Complete canonical parsing, sampling and private verification dataflow remain required, and the existing multiplication proof profile is unchanged.

The [NTT component](ntt-proof-lab.md) adds connected forward and inverse stages over canonical normal residues, including exact reduction and both normalization halves. Its public polynomial harness is invertible and supplies no coefficient privacy or owner permission. Future private signature composition must keep coefficients, keys, signatures, hashes and matrices internal and bind the same note and exact transaction. Complete private linkage of decoding, sampling, norm and hint constraints through signature challenge equality remains unfinished.

Its separate [compact register profile](compact-ntt.md) uses eight multiplication slots and exact canonical writes with complete bank holds. It retains the same typed diagnostic statement and exact transform, with independent dataflow attacks and actual proof rejection tests. The smaller trace layout does not establish complete private signature feasibility or change the original profile.

The [owner binding component](owner-binding-proof-lab.md) links two private exact verification key preimages to the same input note owner fields through unframed SHA3-512. It retains hidden commitments, stable nullifiers, full depth 32 membership, conservation and the existing 520 public fields. This is a preimage connection rather than a signature or owner permission. Public verification keys can be known without spending authority. The complete same key, signature and transaction relation remains unfinished.

## Milestones and evidence

| Milestone | Deliverable | Acceptance evidence |
|---|---|---|
| Accounting | Atomic units, frozen subsidy table, 60/20/10/10 allocation, miner rounding, cap, actual issuance and burns | Boundary/rejection/conservation tests and independent vectors |
| Primitive feasibility laboratory | Isolated operations for signing, verification, encapsulation, decapsulation and authenticated encryption | Exact backend versions and parameters, real primitive operations, altered input rejection, reproducible size and cost measurements |
| Transparent relation research | Local note, membership, authorization, conservation, encryption and stake eligibility checks | Plaintext witness boundary, independent encoding vectors and adversarial fixtures, no substitution for a hiding proof |
| Recipient capability laboratory | Public sender capability, KEM key binding, v2 opening without the actual nullifier secret, and strict typed recovery | Preserved v1 bytes, separate receiver authority, canonical and context rejection cases, exact recovery and later authorized local consumption |
| Isolated hiding proof component | Fixed binary AIR for four private u64 amounts, bounded conservation, public fee and opaque context | Actual proof verification, invalid raw proof rejection, independent vectors, exact profile checks and bounded canonical transport |
| Canonical note proof component | Exact SHA3-512 for four canonical payment openings linked to the same private amount conservation constraints | Independent full sponge states, amount binding, malformed encoding and raw proof rejection, fixed profile and explicit public input commitment leakage |
| Hidden membership proof component | Two private depth 32 paths, hidden input commitments and creation versions, common root membership, distinct hidden commitments and exact conservation | Independent canonical messages and complete sponge states, direction and digest linkage, invalid proof rejection, fixed profile and explicit root and privacy boundaries |
| Stable nullifier proof component | Retained private input secrets linked to their committed bindings and public stable nullifiers in the same hidden membership and conservation proof | Independent binding and nullifier preimages, split byte linkage, stable identities across valid root and context changes, invalid proof rejection and explicit owner and state boundaries |
| SHA3 and SHAKE proof foundation | Exact bounded unframed hashing and XOF squeezing over private bytes, with public mode, lengths and output | Independent rate, padding and full state vectors, selected authorization hash inputs and invalid proof rejection, without a signature or owner authorization claim |
| Exact modular multiplication foundation | Canonical multiplication modulo 8380417 through bounded integer limbs, with an isolated public operand and result harness | Independent residual bounds, false field aliases, canonical and carry rejection, bytewise public binding and actual proof verification, without NTT or signature authorization |
| Normal residue NTT foundation | Connected fixed forward and inverse stages, exact butterfly arithmetic and inverse normalization in a public polynomial harness | Independent direct negacyclic DFT and inverse DFT, stage and auxiliary records, bytewise binding and altered computation rejection, without private signature or owner authorization |
| Private owner key binding | Exact private verification key hashes linked to the same canonical inputs, hidden membership, stable nullifiers and conservation | Complete unframed key sponge states, preserved identities and hostile owner crosswires, without signature verification or spending permission |
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

The primitive laboratory is a narrower prerequisite to relation feasibility. A successful signature, KEM round trip, or authenticated encryption test establishes only the tested primitive behavior. Conformance claims require applicable reference vectors and recorded coverage. The isolated proof components establish separate evidence for unbound conservation, canonical note value linkage, hidden membership with private input distinctness, stable nullifier derivation from committed authority, exact SHA3 or SHAKE computation, canonical modular multiplication and normal residue NTT execution. These foundations do not complete private signature decoding, sampling, norm or hint checks, challenge equality or owner authorization. None proves complete private payments, confidential stake eligibility, recipient anonymity, complete protocol proof soundness, or a composed post quantum security argument.

Both complete private payment feasibility and confidential stake feasibility must pass before ledger kernel integration can satisfy its milestone. The two feasibility tracks may progress independently. Neither can be replaced by monetary tests, a primitive laboratory result or an isolated proof component. Their exact constructions, assumptions, malformed input behavior, and measured resource requirements must be recorded before dependent interfaces are frozen.

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

The [backend feasibility record](proof-feasibility.md) retains exact source versions, source inspection and isolated component adoption, with unresolved complete relation hiding, primitive coverage, knowledge soundness and quantum model requirements. All eight proof laboratories pin `p3-* 0.8.0` for their inspected statistical hiding configurations. The note, membership, nullifier, hash and owner binding components constrain Keccak permutations through the exact `p3-keccak-air` release. This does not select a consensus backend or establish a fixed quantum security level. Legacy v1 senders know output nullifier secrets and can recognize future consumption. V2 capability construction keeps that secret out of the sender interface and provides strict typed local recovery. This removes deliberate secret disclosure in that interface without proving unlinkability, nullifier pseudorandomness, recipient identity, confidential stake, or composed quantum privacy.

Preserving v1 bytes and vectors is laboratory compatibility evidence. A production privacy default must exclude sender known v1 notes or specify an explicit migration. Changing the current protocol version cannot reinterpret an existing note's encoding or reset its nullifier.

Authenticated capability routing, public capability reuse, note discovery, secret backup, private proof integration, and production wallet recovery remain separate gates. Complete capability substitution is not prevented by internal consistency. A static KEM key does not establish forward secrecy. Key rotation creates a different capability while old note recovery still requires the old committed capability and retained authority. Sharing a capability's nullifier secret with a restricted voting service can grant tracking authority across notes using that secret without granting spending authority. Neither laboratory format implements the `thm` production address encoding.

The experimental keyed nullifier hash requires analysis with its known binding image, sender chosen commitments and reused retained secrets under explicit classical and quantum query models. Its same key and commitment constraints do not supply a PRF argument or spending permission. A stable public identity must still be consumed atomically against authenticated persistent state.

Historical primitive and unbound conservation benchmarks retain their original source and machine provenance. Neither measures the canonical note, membership, nullifier, hash, arithmetic, NTT or owner binding proof component. Proof resource reports must separately record the actual profile, workload, raw observations, source revision and measurement limits. Sparse tree capacity and repeated synthetic commitments do not establish an effective anonymity set or an observer experiment.

## Proof component checks

The release suites include invalid raw proofs constructed without the normal witness precheck. Independent reference and profile checks cover separate boundaries from cryptographic proof verification. The [original proof record](proof-lab.md), [canonical note record](note-proof-lab.md), [membership record](membership-proof-lab.md), [nullifier record](nullifier-proof-lab.md), [hash record](hash-proof-lab.md), [arithmetic record](arithmetic-proof-lab.md), [NTT record](ntt-proof-lab.md) and [owner binding record](owner-binding-proof-lab.md) define their exact scope. The retained note profile is `thorum.note-proof-lab.v2-payment.sha3-512.serial.p3-0.8.0.v1`, with 1024 original rows and 4262 columns. The separate membership profile is `thorum.membership-proof-lab.v2-payment.depth32.sha3-512.serial.p3-0.8.0.v1`, with 8192 original rows, 4595 columns and 392 public fields. The nullifier profile is `thorum.nullifier-proof-lab.v2-payment.depth32.sha3-512.serial.p3-0.8.0.v1`, with 8192 original rows, 4801 columns and 520 public fields. The hash profile is `thorum.hash-proof-lab.keccak.sha3-shake.serial.p3-0.8.0.v1`, with 1024 original rows, 5359 columns and 913 public fields. These four profiles use 64 FRI queries and log blowup 3. The arithmetic profile is `thorum.arithmetic-proof-lab.modq8380417.mul.radix4096.serial.p3-0.8.0.v1`, with 256 rows, 211 columns, 76 public fields, symbolic degree two and log blowup 2. The NTT profile is `thorum.ntt-proof-lab.modq8380417.radix4096.serial.p3-0.8.0.v1`, with 256 rows, 39051 columns, 2113 public fields, symbolic degree two and log blowup 2. The owner binding profile is `thorum.owner-binding-proof-lab.v2-payment.depth32.sha3-512.serial.p3-0.8.0.v1`, with 8192 rows, 5003 columns, 520 public fields, symbolic degree four and log blowup 3. Proving tests run serially because of resource requirements.

The workspace test profile uses optimization level 2 while retaining debug assertions and overflow checks. This keeps the larger constraint corpus practical without disabling upstream debug validation. Release tests separately construct deliberately invalid proofs after bypassing the local precheck. This execution policy is not benchmark evidence and must not be used to reinterpret retained release measurements.

```text
cargo test -p thorum-proof-lab --release --locked --offline
cargo test -p thorum-note-proof-lab --locked --offline
cargo test -p thorum-note-proof-lab --release --locked --offline
cargo test -p thorum-membership-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-membership-proof-lab --release --locked --offline -- --test-threads=1
cargo test -p thorum-nullifier-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-nullifier-proof-lab --release --locked --offline -- --test-threads=1
cargo test -p thorum-hash-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-hash-proof-lab --release --locked --offline -- --test-threads=1
cargo test -p thorum-arithmetic-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-arithmetic-proof-lab --release --locked --offline -- --test-threads=1
cargo test -p thorum-ntt-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-ntt-proof-lab --release --locked --offline -- --test-threads=1
cargo test -p thorum-owner-binding-proof-lab --locked --offline -- --test-threads=1
cargo test -p thorum-owner-binding-proof-lab --release --locked --offline -- --test-threads=1
python research/proofs/reference_vectors.py --check
python research/proofs/profile_check.py
python research/note-proofs/reference_vectors.py --check
python research/note-proofs/profile_check.py
python research/membership-proofs/reference_vectors.py --check
python research/membership-proofs/profile_check.py
python research/nullifier-proofs/reference_vectors.py --check
python research/nullifier-proofs/profile_check.py
python research/hash-proofs/reference_vectors.py --check
python research/hash-proofs/profile_check.py
python research/arithmetic-proofs/reference_vectors.py --check
python research/arithmetic-proofs/profile_check.py
python research/ntt-proofs/reference_vectors.py --check
python research/ntt-proofs/profile_check.py
python research/owner-bindings/reference_vectors.py --check
python research/owner-bindings/profile_check.py
```

## Node and desktop integration

The [protocol safety and verification requirements](protocol-extensions.md) add the private Safe, private cryptographic migration, ordinary payment resource reservation, compact chain history research and fast payment locks. The selected testnet timing target is 60 second blocks, four block checkpoint opportunities and 10080 block maturity for mining/staking rewards. Ordinary transfer acceptance and staking principal withdrawal remain separate. The existing 120 second accounting model is a retained reference. A time consistent new schedule and independent vectors precede activation. These additions do not bypass the complete private payment and confidential stake feasibility gates.

The intended deliverable is a complete chain with node software and a desktop wallet. The private network integration milestone follows ledger, mining and finality integration and precedes final desktop wallet integration and public network trials. It does not exist yet. Component proofs precede authenticated state validation, durable persistence, rollback and network synchronization.

The [node and service boundary](node-integration.md) includes ordinary validating nodes without mining or stake authority, server operation and later exchange deposit/withdrawal integration. Integration tests require private scanning, idempotent accounting, explicit finality and recovery. Exchange listing decisions remain external to protocol development.

Private server trials must use independent node instances and cover peering, initial and ongoing synchronization, persistence and restart, inconsistent peers, partitions and reconnection, reorganizations, resource limits and work/checkpoint interaction. The node RPC and wallet trust boundary must be defined and tested. Independent nodes must agree on valid and rejected transitions and recover the same durable state after restart or a branch change. Starting one process on a server is not sufficient acceptance evidence.

The Qt desktop wallet target includes a local validation node, local witness construction and proving, private payments by default, restricted staking and voting authority, scoped viewing, encrypted backups and recovery. The `thm` address namespace, node resource controls and production codec remain specification work. Escrow, confidential assets and governance depend on the same reviewed ledger and authority boundaries. Wallet integration and public network claims remain subject to the milestones above.

## Release gates

Private PQ transaction and staking constructions must pass their feasibility and review gates before production interfaces that depend on them are frozen. The bootstrap, genesis, difficulty, finality, withdrawal and recovery rules need complete specifications. Source licenses and dependency notices must be inventoried. No release date or security audit completion is implied by a development milestone.

The temporary developer allocation requires a future consensus hard fork for retirement after work completion and community handover. The future miner/stake redistribution, completion criteria, change process, and activation height remain undefined. The pool share stays at 10 percent absent a separate explicit change, and existing legitimately earned credits remain unaffected. No automatic sunset, milestone key, or retirement height is implemented. No production genesis has been released.
