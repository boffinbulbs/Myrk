# RPC and private data access

## Scope and implementation status

Thorum's interfaces must support independent nodes, explorers, wallets and exchange integration while preserving the private transaction relation. Public verification data and private wallet capabilities have separate interfaces and authorities.

This document specifies that boundary. A production RPC server, explorer index, wallet service and exchange adapter are not implemented. Method names, wire encodings, authentication profiles and limits require versioned definitions before implementation. No private data becomes public merely to support an API.

## Public chain view and scoped wallet view

Let S be authenticated chain state and K a deliberately granted wallet capability. The two views are

$$
V_{\mathrm{public}}=\operatorname{PublicView}(S),\qquad
V_K=\operatorname{WalletView}(S,K).
$$

The public view supplies verification and synchronization data. The scoped view supplies only the owned or deliberately disclosed data authorized by K. Spending, discovery, viewing, recovery and restricted voting remain separate capabilities. An index entry or a viewing capability grants no general spending authority.

| Interface family | Data available to the caller | Authority and validation boundary |
|---|---|---|
| Chain status | Network and rule version, synchronized tip, work and checkpoint status, resource and availability state | Public query with independently verifiable chain evidence |
| Blocks and headers | Canonical header, work witness, ordered public payload commitments and applicable certificates | Bounded data retrieval and local validation |
| Transaction and receipt | Public effecting data, accepted public proof and authorizing bytes or authenticated references, receipt and inclusion/finality evidence | Exact transaction and state version binding |
| Encrypted output ranges | Commitments, encrypted recipient payloads and public indexing data | Resumable public retrieval with local private discovery |
| State synchronization | Authenticated roots, versioned changes and supported snapshot evidence | Verified starting trust, state reconstruction and data availability |
| Transaction submission | Complete canonical private proof, public statement and bound encrypted delivery | Structural limits, proof verification and current consensus admission |
| Owned wallet data | Locally discovered notes, scoped balances, recovery and private history | Authenticated wallet boundary and the caller's explicit capability |
| Wallet authorization | Local witness construction, proof generation and permitted submission | Spending authority stays within the authorized wallet process |
| Restricted stake service | Permitted epoch duties and signing state | Delegated voting capability with its own privacy and withdrawal limits |

These are interface classes rather than implemented endpoints. Each response needs explicit type, network, version, state and completeness information. A supplied root or transaction ID has authority only through its verified consensus context.

Public authorizing bytes are the protocol's published proof and validation envelope. Private signature witnesses, ownership keys, note openings and prover traces stay within the local private relation and wallet authority boundary.

## Explorer behavior

A public explorer can display headers, work, checkpoints, public transaction identifiers, proof status, nullifiers, output commitments, disclosed fees, ciphertext sizes and supported public resource information. Its data comes from the public chain view and verified indices.

Private amounts, asset information, counterparties and contract state remain within the intended private relation except for explicitly specified public fields or user controlled disclosure. A public address search cannot be assumed to reconstruct private holdings. A user may deliberately provide a scoped viewing or payment disclosure to an authorized service, with the revealed information made explicit.

Public nullifiers, roots, batching, timing, fees and retrieval patterns retain metadata analysis. An explorer label must distinguish independently verified evidence, indexed data, pending submission, inclusion, checkpoint finality and unavailable data. A local cache is not additional consensus authority.

## Local scanning and membership witnesses

Wallets retrieve bounded encrypted data ranges, scan locally and reconstruct owned notes under authenticated state. Full local validation and scanning are the initial target. Recovery includes encrypted payloads, retained capabilities, commitments, note identity and the material required to rebuild membership paths.

The standard path must keep a wallet's selected input commitment, leaf index and authentication path within its private witness. A direct query for that exact commitment's path can identify the intended input to the queried server. Any later reduced state or light client interface needs a separately evaluated query privacy construction, authenticated responses, resource limits and observer tests. It cannot silently replace local scanning with disclosed input queries.

An ordinary node never needs a wallet spending key, note opening or plaintext private balance to verify a transaction. Complete private proofs establish the required relation. Public ciphertext access does not imply access to decryption material.

## Exchange and service integration

An exchange scans outputs addressed to its own capabilities and maintains its own authenticated private account records. Its owned note and credit identities must remain idempotent across restarts, duplicate scans, branch changes and wallet restoration. Credit assignment and the exchange's internal customer balance are service state, separate from public consensus data.

Private withdrawals use the normal local wallet authorization and proving path. Viewing or deposit discovery does not authorize withdrawals. Fee changes, retries and concurrent withdrawals must preserve one consumption per note and exact customer accounting. Acceptance tests use synthetic assets and accounts.

The service reports pending, included, finalized, mature and available states according to the active chain rules. An immature reward remains restricted. Ordinary transfers do not start another seven day reward delay. A business may choose a stricter credit policy while retaining the underlying chain state distinctions.

The later Aegis protocol adds separately activated certified state and mined recording status. Its receipt is spendable only under that active version's completed consensus and private recovery rules. The initial chain retains checkpoint finality. API compatibility cannot activate Aegis or an unfinished application.

Exchange listing, custody and trading systems remain outside consensus. A scoped service integration does not require a global viewing key or a transparent payment pool.

## Authentication and resource boundaries

1. Public data calls use bounded pagination, canonical types, response size limits, time budgets and resumable synchronization. Bulk encrypted data access has deterministic ordering and explicit completeness.
2. Wallet and signing operations require a local or explicitly authorized authenticated channel with separate discovery, viewing, recovery, voting and spending permissions. Bind requests to network, service identity and intended scope.
3. Submission deduplication and verification caches bind all authorizing bytes, expected public statement, profile, rule version and relevant state. Matching an effecting identifier alone cannot reuse a different proof's acceptance.
4. Logs, metrics and errors expose the minimum public operational data. Private witnesses, keys, recovered note contents and unrestricted wallet history stay inside the wallet boundary. Recovery failures must not become a remote decryption oracle.
5. Restarts atomically recover indices, scan cursors, credit records, pending withdrawals, transaction receipts and relevant chain versions. Partial or stale data produces an explicit incomplete state.
6. Transport authentication and encryption have their own threat model and post quantum evaluation. They complement recipient encryption and private proofs rather than supplying their ledger properties.

## Acceptance evidence

| Boundary | Required tests |
|---|---|
| Public data | Identical authenticated state on independent nodes, bounded pagination, missing pages and invalid evidence |
| Wallet privacy | Observer traces for scans, path queries, logs, errors, restored devices and concurrent service clients |
| Capability scope | Viewing versus spending, delegate rotation, revoked access, replay and service identity substitution |
| Submission | Duplicate effects with changed proof bytes, stale state, malformed encodings, unsupported versions and proof floods |
| Recovery | Missing ciphertext, corrupted archive, interrupted scan, stale snapshot and membership witness reconstruction |
| Exchange accounting | Repeated deposits, note reassignment, withdrawal retries, concurrent spends, restoration and branch reconciliation |
| Later Aegis | Supported active version, complete certificate and payload, committed versus recorded cursor, policy restrictions and restart |

The [node architecture](node-integration.md), [wallet requirements](wallet.md) and [private transaction specification](private-transactions.md) define the adjacent authorities. Endpoint implementation follows complete private payment, confidential stake, kernel and network gates.
