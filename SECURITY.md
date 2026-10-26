# Security status

Thorum is at the reference implementation and protocol research stage. The repository does not contain a production network or an independently audited private transaction or checkpoint construction.

The monetary module checks amount arithmetic and supply transitions. It does not prove transaction ownership, private value conservation, eligible stake, valid block order, canonical parent acceptance, or recovery data availability. These are separate kernel and protocol requirements.

The relation laboratory checks ownership, conservation and stake eligibility locally with plaintext witnesses and externally supplied state. It produces no privacy proof, consensus certificate or persistent state change. Legacy v1 senders know output nullifier secrets. V2 recipient capabilities exclude that secret from sender construction and note delivery, without establishing a formal unlinkability result. Stake statements still expose claims. Plaintext private openings and encryption witnesses must not be transmitted to validators or remote services. These experiments do not complete the private payment or confidential stake feasibility gates.

Recipient capability consistency does not authenticate the intended person or service. Substitution of a complete valid capability remains an application routing threat. Typed recovery requires an authenticated expected commitment and the recipient's separate nullifier authority. Exported nullifier backups are secret material without storage encryption in this API. A voting delegate given shared nullifier authority can track other disclosed openings under that capability, even without spending keys. Static recipient encryption keys do not provide forward secrecy.

## Security sensitive changes

Review must cover malformed inputs, arithmetic boundaries, state rollback, duplicate application, encoding canonicality, replay across networks, and resource exhaustion. Cryptographic changes must identify the exact construction and security model.

Record verified results separately from intended properties. Do not describe primitive selection, successful unit tests, or analytical calculations as a cryptographic audit.

## Reporting

A private reporting endpoint has not been configured. Repository operators must establish and publish a monitored private reporting channel before accepting sensitive disclosures or operating a public test network. Exploit details should not be placed in public issues before a coordinated reporting route exists.

There are no supported production versions or release security guarantees at this stage.
