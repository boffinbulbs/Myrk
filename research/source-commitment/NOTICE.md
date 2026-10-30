# Source provenance

The backend modules are included directly from ../storage-pcs/backend/src without changing their bytes. They retain their original authorship and dual MIT and Apache 2.0 notices. LICENSE-MIT and LICENSE-APACHE reproduce the retained upstream licenses. The new source owner, appended convenience entries and experiment controls use the repository MIT license in LICENSE.

Source preparation and streaming construction are called from ../source-extension without copying or altering those kernels. The borrowed resource profile anchor comes from ../proof-preflight. It supplies no commitment masks or salts. Original source and notices remain at those directories.

The test hash and quartic AIR are imported from the retained storage experiment. The ordinary control uses the root-pinned p3-fri 0.8.0 registry package without parallel features. Its source identity and the remaining dependency closure are recorded in Cargo.lock, fixtures/features.json and provenance.json. No acceptance verifier or proof format is replaced by a host callback.
