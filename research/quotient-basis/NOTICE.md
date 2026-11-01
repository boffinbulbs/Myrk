# Source derivation

The reference program and basis argument are original Kova research under the repository MIT license. The [retained Rust sources](../fallible-source/README.md) and pinned Plonky3 0.8.0 domain and verifier implementations supply the concrete construction being analyzed. Their original authorship, notices and licenses remain applicable. No production implementation or earlier reference program is imported or changed.

The comparison paper is Shahla Atapoor, Cyprien Delpech de Saint Guilhem and Al Kindi, *STARK-Based Signatures from the RPO Permutation*, IACR Communications in Cryptology 3(2), 2026, DOI 10.62056/absgbn-3y. The published PDF is licensed CC BY 4.0. It is cited for its protocol and theorem statements. The paper is not redistributed here. The source identities and reviewed edition are recorded in provenance.json.

The Windows guard is copied unchanged from this repository's existing bounded research guard. It retains its original process, job, memory availability and deadline checks. Python uses standard library integer arithmetic and no external package. The root THIRD_PARTY_NOTICES.md retains the broader source and dependency attribution.
