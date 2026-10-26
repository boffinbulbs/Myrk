# Security status

Thorum is at the reference implementation and protocol research stage. The repository does not contain a production network or an independently audited private transaction or checkpoint construction.

The monetary module checks amount arithmetic and supply transitions. It does not prove transaction ownership, private value conservation, eligible stake, valid block order, canonical parent acceptance, or recovery data availability. These are separate kernel and protocol requirements.

The relation laboratory checks ownership, conservation and stake eligibility locally with plaintext witnesses and externally supplied state. It produces no privacy proof, consensus certificate or persistent state change. Its sender knows output nullifier secrets, and its stake statements expose claims. Its private openings and encryption witnesses must not be transmitted to validators or remote services. These experiments do not complete the private payment or confidential stake feasibility gates.

## Security sensitive changes

Review must cover malformed inputs, arithmetic boundaries, state rollback, duplicate application, encoding canonicality, replay across networks, and resource exhaustion. Cryptographic changes must identify the exact construction and security model.

Record verified results separately from intended properties. Do not describe primitive selection, successful unit tests, or analytical calculations as a cryptographic audit.

## Reporting

A private reporting endpoint has not been configured. Repository operators must establish and publish a monitored private reporting channel before accepting sensitive disclosures or operating a public test network. Exploit details should not be placed in public issues before a coordinated reporting route exists.

There are no supported production versions or release security guarantees at this stage.
