# Canonical preseal job binding

This document selects an exact candidate encoding for the public bytes committed by an auxiliary mining job. It completes the previously unselected outer job framing and commitment in the [auxiliary binding contract](auxiliary-work-binding.md). The separate [bounded byte diagnostic](../research/preseal-bytes/README.md) implements the outer format for unverified public synthetic data. It implements no private proof, authenticated context, block acceptance or live parent profile. Inner effect and proof classes, resource profiles, state and consensus constructions remain required before a production candidate can be admitted.

The decision is to bind the **actual ordered public effect, authorization and recovery bytes**, without substituting caller-provided aggregate roots. The job commitment follows actual proof construction and precedes parent work. Local process generations and the eventual work seal are excluded from the job. A job hash is byte identity, not permission to spend or commit state.

## Existing source and scope

The current [payment statement](../crates/thorum-relation-lab/src/payment.rs) canonically frames its chain, protocol, validation tag, anchor, ordered nullifiers, output commitments, encrypted envelopes and fee. Its [authorization mapping](../research/signature-complete-native/src/authorization.rs) derives the actual 196 byte input for that payment statement. Neither contains a block predecessor, child target, ordered block authorization body or reward policy. Neither accepts a replacement digest to sign an arbitrary job.

The existing [relation hash helper](../crates/thorum-relation-lab/src/lib.rs) uses SHA3-512 with unsigned big endian 32 bit length framing. The [crypto context](../crates/thorum-crypto-lab/src/lib.rs) independently uses framed chain, version and tag fields. Its encoding is 80 bytes but its caller owns authentication. These mechanisms inform the candidate below. Their old domains, signature messages, creation versions and stable nullifier derivation remain unchanged.

The candidate retains SHA3-512 for byte commitments. This is not a replacement authorization primitive, a smaller proof representation or an achieved security claim. In particular, hashing public proof bytes does not validate them. The existing full private signature and transport resource refusals remain unchanged.

## Canonical framing

Let `F(x) = u32be(len(x)) || x`, with no implicit terminator. Every length must be representable as an unsigned 32 bit integer. Integer field contents have the fixed widths below. A decoder must require the exact width rather than accept an alternate integer encoding. SHA3-512 is denoted by `H` and returns 64 bytes.

The job starts with the eight literal bytes `KOVAJOB\0`, hex `4b4f56414a4f4200`. The final zero byte belongs to the magic. It is not an extra terminator on a later field or hash domain.

The following fields appear once, in exactly this order. Every field after the magic is framed with `F`.

| Field | Exact field contents |
|---|---|
| Encoding version | Unsigned 16 bit big endian, value `1` |
| Chain identity | 32 bytes from the expected network context |
| Rule descriptor identity | 64 bytes |
| Consensus descriptor identity | 64 bytes |
| Cryptographic registry identity | 64 bytes |
| Resource profile identity | 64 bytes |
| Predecessor block identity | 64 bytes |
| Child height | Unsigned 64 bit big endian |
| Candidate timestamp | Unsigned 64 bit big endian, seconds |
| Active epoch | Unsigned 64 bit big endian |
| Prior finality identity | 64 bytes |
| Child work target | Exactly 32 bytes as an unsigned little endian integer |
| Parent binding profile identity | 64 bytes |
| Treasury policy | Complete canonical expected policy bytes, length `p` |
| Record count | Unsigned 32 bit big endian, value `n` |

The target must be nonzero and equal the expected value derived under the active child difficulty rule. The fixed 32 byte representation has no CompactSize or compact-target aliases. This does not select a difficulty adjustment algorithm, timestamp tolerance, eligible epoch or finality rule. Those remain properties of the authenticated expected context.

Descriptor identities are not peer-selected verifier configurations. The validator must resolve them to its actual supported canonical descriptors and match the current authenticated rules. The cryptographic registry must bind each effect schema, expected public statement construction, actual relation and verifier implementation, security parameters and resource class. An absent or unestablished mapping refuses. A matching label cannot convert the current experimental comparator into chain security.

Treasury policy bytes must equal the canonical policy obtained from authenticated state. Hashing arbitrary supplied policy text does not authenticate a destination or authorize governance. Pool, temporary development and reward routing retain their separate policies. A hash binding also supplies no external parent-chain receipt.

## Ordered records

Exactly `n` records follow the header. There are no optional sections, ignored records or trailing bytes. Each record has exactly five framed fields:

| Field | Exact field contents |
|---|---|
| Kind | Unsigned 16 bit big endian |
| Class descriptor identity | 64 bytes |
| Effect | Complete canonical public effect bytes `E_i` |
| Authorization | Complete public authorization envelope bytes `A_i` |
| Recovery data | Complete canonical public recovery payload bytes `D_i` |

The initial reserved kinds are `1` for private payment, `2` for reward creation, `3` for stake lifecycle and `4` for checkpoint control. These numbers define the outer binding vocabulary. They activate no class. Each kind needs its actual supported class descriptor, semantic encoding and verification path. Unknown kinds, unsupported classes and unavailable resource profiles refuse before proof work. Contracts, Safe operations, governance execution, migration and later Aegis require their agreed separate constructions and activations.

The effect is the exact input to expected-statement construction for its class. The authorization is the complete public proof or certificate envelope, including its canonical version and profile framing. It contains no hidden owner keys, raw private authorization signatures or constrained intermediates. Recovery data contain the actual required public encrypted delivery or other availability payload, not a success bit, location promise or digest substituted for missing bytes.

Neither hashing nor a class label permits sending private witnesses to the job encoder. Input commitments, creation versions, membership indices and paths, retained nullifier secrets, confidential amounts and assets, keys and signature intermediates remain outside these public fields. The visible fields of an earlier transparent laboratory statement do not select production visibility.

The class must derive or check every effect-to-recovery binding from the same actual data. If a retained effect encoding already embeds complete delivery bytes, it must require byte-exact agreement with `D_i`. This candidate does not silently remove that duplication. A future encoding optimization requires an explicit version and resource analysis. A class with no recovery payload must define canonical empty `D_i`; an arbitrary sender cannot use empty bytes to bypass delivery.

Record order is consensus data. Reordering records, separating effects from their authorizations or moving recovery data to another position changes the job. The ledger still checks duplicate nullifiers, restrictions and current state in that exact order. Hash equality alone establishes none of those conditions.

Issuance is a distinct record class. Its effect must account for actual authorized rights, destinations and recovery data. The current [accounting core](../crates/thorum-core/src/accounting.rs) accepts earned staking as a caller input and does not authenticate a duty, height order or reward destination. Neither a kind value nor a job commitment supplies that evidence. Unearned stake remains unissued, principal registration conserves existing value, and reward origin, 10080 block maturity and initial checkpoint finality retain their requirements.

## Effect, authorization and job identities

The exact ASCII domains below contain no final zero byte:

```text
kova.effect-id.v1
kova.authorization-id.v1
kova.preseal-job.commitment.v1
```

For a record in the exact job context, define

$$I_{E,i}=H(F(\texttt{kova.effect-id.v1})\parallel F(\text{chain})
 \parallel F(\text{rules})\parallel F(\text{kind}_i)\parallel F(\text{class}_i)
 \parallel F(E_i)\parallel F(D_i)),$$

$$I_{A,i}=H(F(\texttt{kova.authorization-id.v1})\parallel F(I_{E,i})
 \parallel F(A_i)).$$

These derived identities are not additional serialized record fields. A decoder cannot replace `E_i`, `A_i` or `D_i` with either identity. The validator computes them from the actual canonical bytes when needed for exact cache and replay accounting.

For the complete canonical job bytes `J`, define

$$I_J=H(F(\texttt{kova.preseal-job.commitment.v1})\parallel F(J)).$$

`I_J` is the 64 byte value proposed for the parent carrier. It is not accepted as an expected value from that carrier. The receiver recomputes it from its own actual child data. The commitment includes the treasury policy, every context field, record count, kind, class, effect, public authorization and recovery byte. No aggregate root or child validity callback stands in for that data.

A different valid public proof for the same effect changes `I_A` and `I_J` without changing `I_E`. Changing rules or delivery bytes changes the effect identity under this candidate. **No effect or job identity replaces a stable note nullifier.** A new current rule, proof, anchor, work header or effect identifier cannot rename a note's original consumption identity.

Neither identity is a self-contained verification-cache key. The actual expected statement, verifier implementation and complete profile, state context and canonical proof bytes must still match the [atomic acceptance contract](private-transition-state.md). A complete byte commitment cannot become a serialized proof-success token.

## Acyclic construction and ownership

The producer and receiver must follow the same source lifetime:

1. Capture one expected predecessor, rules, supported descriptors, child target, finality and treasury context. The local owner also records its current publication generation and lineage lease.
2. Form canonical effects and recovery data. Derive each expected private statement from those actual fields and the verifier-owned context. Generate the actual authorization proof or certificate under its admitted class.
3. Freeze the exact ordered public authorization bytes with their effects and recovery bytes. No class may require its proof to refer to `I_A` or `I_J`, since those contain the bytes of that proof. Such a class is cyclic and unsupported.
4. Encode immutable `J` and compute `I_J`. Hashing may stream the canonical serializer, but it must consume actual immutable source bytes. It cannot invent fields, reread a mutable path under another owner or resume an aborted proving prefix.
5. Insert `I_J` in the actual parent carrier, derive its transaction and authorization commitments, construct the actual parent header and perform work. Parent header, nonce, solution, inclusion branches, auxiliary witness, work hash and miner-local bookkeeping are excluded from `J`.
6. The receiver independently parses and re-encodes `J`, derives its expected context and checks exact equality, recomputes `I_J` and validates the actual auxiliary binding. It separately verifies every private proof, state transition, recovery obligation and consensus control.
7. Immediately before durable ledger publication, recheck the current predecessor, rules, lineage and every state-dependent predicate. A byte-identical job from a stale attempt is still stale. Failure terminates the attempt without partial state publication or refunding consumed proof-work authority.

Local publication generation is deliberately **not serialized in `J`**. It belongs to a particular database owner's concurrency and recovery state. Including it would make independently restarted nodes hash different jobs for the same protocol candidate. Excluding it does not relax the generation and lineage checks at commit. The [bounded byte journal](../research/state-journal/README.md) cannot authenticate those ledger checks or irreversible signer history.

The child predecessor, height, epoch and finality identities are protocol context, distinct from the local generation. An all-zero identity, elapsed time or wallet label is not a genesis or activation rule. The explicit confidential stake bootstrap dependency remains blocked.

## Contents, limits and refusal

Let `e_i`, `a_i` and `d_i` be the actual effect, authorization and recovery lengths. Each record occupies exactly

$$6+68+(4+e_i)+(4+a_i)+(4+d_i)=86+e_i+a_i+d_i$$

bytes. The fixed job header, including all framing, treasury length and record count, occupies `610+p` bytes. Therefore

$$|J|=610+p+\sum_{i=0}^{n-1}(86+e_i+a_i+d_i).$$

These are source specification counts. The separate byte diagnostic checks a 927 byte fixture and a 51130 byte maximum under its laboratory limits. Those are not a serialized private proof result or production capacity. Empty lists can be represented by the grammar, but syntax alone does not authorize an empty block or omit the required issuance or consensus records.

Before allocation, a future decoder must bound the total job, record count, treasury policy and each class's effect, authorization and recovery bytes under its actual supported resource descriptor. It must check accumulated lengths with overflow-safe arithmetic, exact fixed widths, field order and complete consumption. Before hashing `F(J)`, the total `|J|` must also fit an unsigned 32 bit length. No generic limit follows merely from the representational maximum.

The existing 64 KiB laboratory statement limit is not a selected production job cap. The existing two MiB proof payload cap and fixed small proof schema do not implement this job format or admit the full relation. The source-derived full main-query JSON lower bound of 5399232 bytes already exceeds that small payload cap before other proof objects. Wrapping it in this job or streaming its hash cannot remove those bytes, retained LDE/query contents, soundness or privacy obligations.

No production resource profile is selected by this encoding. No wide prover is admitted, and no memory, disk, query, security or execution-class expansion follows. A later codec experiment may use a separately marked public synthetic class and finite limits to test framing and source ownership. Such a result must remain explicitly unverified data, with no proof-success, ledger or network acceptance interface.

## Required evidence and remaining gates

The following are integration requirements. The byte diagnostic covers outer framing, byte identities and bounded source construction. It does not execute the private proof, authenticated state or parent binding requirements:

1. Independent saved complete byte fixtures and job commitments, including empty and nonempty recovery data, exact width boundaries and multiple ordered records.
2. Wrong magic or version, alternate fixed widths, overflow, oversized count or length, truncation, trailing data and noncanonical class encodings.
3. Each expected context field changed independently, including the full child target, prior finality, predecessor and treasury policy bytes.
4. Reordered records, swapped proof or recovery associations, changed kind or class and a replacement proof with identical effect.
5. Validly encoded but cryptographically invalid authorization bytes. Canonical parsing and hashing may succeed while actual class verification must reject. That distinction must be exercised rather than replaced by a caller Boolean.
6. Unavailable recovery data or mismatch between effect delivery binding and actual `D_i`.
7. Different local generation with identical protocol bytes. Encoding must agree while a stale owner's actual commit must refuse.
8. A mutable or replaced source, duplicate consumption or changed state between proof checking and commit, retaining actual first cause and only owned cleanup.
9. A purported proof statement depending on its own public proof or job commitment, and an attempt to include the work seal in `J`.
10. Correct job bytes with incorrect parent transaction, authorization path, parent profile or child threshold, without fabricating a solved complete parent fixture.

This binding decision resolves the outer job field order, framing and hash candidate. It does not select the active class registry, inner effect/proof formats, production resource cap, sealed block identity, child difficulty algorithm, authenticated genesis, bootstrap or private payment acceptance. Those omissions remain explicit refusals. The complete private relation and confidential stake feasibility still precede ledger and network activation. Private payments remain the default, and the full roadmap and agreed later deferrals remain intact.

The [source record](../research/preseal-job/source-record.json) identifies this specification's current source and historical context. No compiler, reference model, codec, native witness, prover, verifier, signer or network service executes for this increment.
