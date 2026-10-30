# Source provenance

The owned prover body derives from p3-uni-stark 0.8.0 src/prover.rs. The original authorship and dual MIT and Apache 2.0 license notices are retained in LICENSE-MIT and LICENSE-APACHE. The original quotient evaluator, transcript, layouts, proof type and verifier remain registry implementations. New context and storage adaptation code uses the repository MIT license in LICENSE.

The composite module derives from ../source-composition/src/composite.rs with a separate opening and proof construction lifecycle. Its previous source and measurements remain unchanged. The hiding module retains the three original composite commitment entries and exposes their numeric profile check within this crate before raw input. Complete source differences and original identities are recorded in provenance.json and adaptation.patch.

Backend modules and the original main source state are compiled by path from the retained laboratory sources without changing their bytes. Main construction uses the existing source preparation and extension packages. Quotient and auxiliary construction use the actual retained coupled mapper, sampler and DenseStore kernels. Bounded dense intermediate matrices remain explicit.

The observer derives from the earlier source opening experiment and delegates actual hashing, commitment and opening operations. It captures the actual salted leaf digests while a commitment runs. Its independent reference reconstructs Merkle nodes from those digests. It does not reconstruct leaf preimages or certify a new hiding or quantum security theorem. The retained hash and fixed quartic AIR sources remain unchanged. Deterministic seeds and trace fixtures are public synthetic research inputs.
