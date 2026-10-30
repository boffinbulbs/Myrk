# Source provenance

The backend modules are compiled from ../storage-pcs/backend/src without changing their bytes. They retain their original authorship and dual MIT and Apache 2.0 notices. LICENSE-MIT and LICENSE-APACHE reproduce those upstream licenses. The new composite owner, bridge methods and construction controls use the repository MIT license in LICENSE.

The original source state module is compiled unchanged from ../source-commitment/src/source.rs in this package. This gives its crate relative storage and error types the same nominal identity as the new composite adapter. It does not expose private fields of a foreign compiled crate. Its dense convenience variants remain unused.

Main preparation and extension call the unchanged ../source-extension and ../source-preparation packages. The borrowed resource anchor comes from ../proof-preflight and supplies no masks or commitment salts. Auxiliary extension and masked quotient construction call the retained DenseStore kernels. The original hiding mapper generates the normalized coupled masks and the auxiliary sampler supplies its existing random input.

The construction observer is adapted from ../source-commitment/tests/roots.rs. Its test hash and quartic trace are imported unchanged from the retained storage experiment. The ordinary reference uses the root pinned p3-fri 0.8.0 package. Cargo.lock and provenance.json identify the retained sources and dependency closure. No verifier, transcript or proof format is changed.
