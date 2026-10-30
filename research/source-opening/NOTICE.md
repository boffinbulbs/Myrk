# Source provenance

The observation helpers are adapted from ../source-commitment/tests/roots.rs into a separate opening harness. The original root tests remain unchanged and are not imported or executed. New role and phase observations support actual FRI operations without modifying their inputs or supplying acceptance decisions.

Source commitments, preparation and checked streaming come from the retained repository dependencies. Original backend and verifier modules retain their licenses and authorship at ../source-commitment and ../storage-pcs/backend. The ordinary control is root-pinned p3-fri 0.8.0. Test hash and AIR helpers are included directly from the retained storage experiment. Their exact identities are recorded in provenance.json.

The new harness and independent reference use the repository MIT license. All captured leaves, salts, points, claims and proofs derive from explicit public synthetic fixtures. They contain no wallet or real fund data.
