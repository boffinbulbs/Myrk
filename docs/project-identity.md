# Project identity and protocol namespaces

Kova is the project name. The canonical repository is https://github.com/boffinbulbs/Kova and the public research site is https://kova.cash/.

The project name, wallet address prefix, network identifier and cryptographic domains are separate values. Changing presentation does not change the bytes authenticated by a signature, commitment, nullifier or proof transcript.

## Address namespace

The intended main network human readable prefix is `kova`. It remains a development target until the complete recipient descriptor and encoding are specified. A ticker is not selected by this prefix. No production address codec is implemented.

An address format must bind the network, encoding version, recipient type and canonical recipient payload under its checksum. Nodes and wallets must reject a network mismatch, unsupported mandatory type, ambiguous encoding or invalid length before transaction construction. Test and development networks require distinct namespaces.

The recipient payload must support the selected private discovery and encryption mechanism. A short identifier cannot replace authenticated recipient key establishment. Spending keys, nullifier secrets, viewing secrets and recovery authority never belong in a public address. The checksum detects encoding errors and does not authenticate the intended person or service.

Protected receiving is a distinct policy. Any Safe recipient descriptor must bind the required policy and protected destination to the resulting note. The address prefix alone grants no recovery, withdrawal or contract authority.

## Retained research interfaces

Existing laboratory package names, transcript tags, signed fixtures and measured source records retain their exact historical identifiers. The repository rename preserves their bytes, dependencies and tested relations. These retained interfaces are research snapshots rather than a released Kova network encoding.

Renaming a Rust package or a source file is a build interface change. Replacing a hash domain, signed context or proof profile is a cryptographic version change. The latter requires fresh independent vectors, exact rejection cases and complete proof verification under the new version. Editing a recorded measurement to conceal a source change is not a valid migration.

The architectural figures and current project documentation use Kova. Original source notices and reproducible measurement records retain their attribution and historical scope.

## Successor protocol requirements

1. Assign explicit network and rule versions before selecting live address and proof formats.
2. Define canonical Kova authorization, commitment, nullifier, encryption and transcript domains together. Domain changes must bind the same private witness and public transaction context.
3. Require rejection of cross network, cross version and substituted recipient contexts. Unsupported profiles fail before proving or state admission.
4. Preserve deterministic consumption within each accepted version. A cosmetic rename must not create a second spendable identity for an existing note.
5. Bind any future private migration to ownership, eligibility, value conservation and global consumption across both versions. Its design must precede failure of the older cryptography.

The next cryptographic integration gate remains a practical complete hiding proof and its same witness ledger connections. The identity change supplies no new privacy, finality or quantum security result.
