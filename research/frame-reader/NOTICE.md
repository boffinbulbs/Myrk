# Source derivation

The reader imports the exact codec and lexical preflight from `research/proof-transport` at revision `6dbdf844ceb0e11bee167a558e0473152d1cf572`. That laboratory retains the original proof and MMCS associated types, field encodings and canonical serializer. Its old diagnostic is not an execution target here. Original source, dependency and license notices remain with those packages. Local additions retain the repository MIT license.

The synthetic proof fixture is borrowed from the preceding decoder laboratory without generating another proof or rerunning its healthy verifier. Typed decoding constructs proof and cap objects but performs no proving, commitment or verification algorithm.

Reader behavior was reviewed against the official Rust 1.94.1 [I/O source](https://raw.githubusercontent.com/rust-lang/rust/1.94.1/library/std/src/io/mod.rs) and [vector source](https://raw.githubusercontent.com/rust-lang/rust/1.94.1/library/alloc/src/vec/mod.rs). The local target toolchain remains Rust 1.94.1. Local standard library source was unavailable. This source review is not a complete standard library or operating system audit.
