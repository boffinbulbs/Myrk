# Source attribution

The integer graph and equation transcription correspond to Plonky3 `p3-keccak-air` 0.8.0 and `p3-field` 0.8.0, under MIT or Apache 2.0. The exact constant source is retained as data in `evidence/constants.rs`. Original upstream license copies remain in `licenses/PLONKY3-MIT` and `licenses/PLONKY3-APACHE`.

The two complete 25 lane reference states are copied as data from RustCrypto `keccak` 0.2.2 `tests/xkcp.rs`. That source attributes its vectors to XKCP, the eXtended Keccak Code Package. Its exact source and attribution are retained in `evidence/xkcp.rs`, with the original RustCrypto MIT and Apache 2.0 licenses. This is not a direct capture of the original XKCP artifact. No upstream generator or test is executed by this laboratory.

New reference code is original Kova work under the repository MIT license. It supplies an integer correspondence check, not an upstream audit, Rust AIR execution, cryptographic proof or payment acceptance mechanism.
