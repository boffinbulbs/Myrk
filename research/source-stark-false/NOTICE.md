# Source provenance

This test package calls the frozen kova-source-stark implementation without modifying it. It includes only ../source-stark/tests/common.rs, retaining the actual observed RNG, hiding MMCS, hash and challenger construction. It does not include or regenerate the prior positive proof tests. The original backend, prover, verifier and dual upstream license notices remain in their owning packages.

The new test and record checks use the repository MIT license in LICENSE. The independent reference imports the frozen Merkle node and bounded file reader functions from ../source-stark/reference.py without running that script's main routine. It reconstructs nodes and roots from actual salted leaf digests, not their preimages. The old positive artifact is verified once as an existing fixture, without generating a new positive proof.

The trace, deterministic seeds, single changed value and generated artifacts are public synthetic research data. Provenance records distinguish unchanged source and verifier identities from the new test. A single retained verifier rejection is a bounded adversarial result, not a general security theorem or a private payment implementation.
