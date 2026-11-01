# Bounded writable snapshot recovery

This diagnostic stores public synthetic bytes under one cooperative writer lease. A fixed staging pool permits a fresh writer to continue after an earlier process leaves an unpublished file. It accepts no payment, proof verdict, ledger root or consensus decision. The default library is empty. The implementation is available only through the release diagnostic feature.

## Storage and ownership

An instance permits four committed generations, numbered zero through three, and four staging names. Each frame contains the `KJS1` tag, big endian generation, parent generation, payload length, payload and a wrapping byte sum. Payloads contain at most 64 bytes and frames at most 92. Genesis uses parent `u64::MAX`. The same payload at a later generation does not revive a stale attempt.

The nine possible entries are `LOCK`, four `frame-i` names and four `pending-i` names. Their conservative logical content limit is `4 + 8 * 92 = 740` bytes. This is not physical disk allocation, directory metadata or process memory. Paths, descriptors, byte vectors, runtime buffers and child processes have separate lifetimes. There is no garbage collector or unlimited generation service.

The owner holds the actual nonblocking OS file lock until drop. An attempt tries at most four exclusive `create_new` operations. An existing staging name remains unowned and untouched. An actual different I/O error is retained. Exhaustion returns `NoFreeSlot` and fails the owner. Only the successfully created staging file belongs to the attempt. Abandoned files are neither adopted nor deleted during recovery.

After writing, `sync_all` completes and the writable descriptor closes. While holding the lease, publication checks that the destination is absent and renames the owned staging file. An observed destination returns `DestinationExists`. Successful rename updates the in-memory generation. Final readback validates the actual committed frame. An error after publication does not roll that publication back. Drop retains the first cause and removes only an unpublished owned staging file. Cleanup errors remain separate.

## Filesystem assumptions

The tested boundary is a trusted initialized directory on local NTFS with cooperative writers using this same lock. Paths, symlinks, reparse points, file types, lengths and supported names are checked where observed. These checks do not create a hostile namespace capability.

Publication is a checked cooperative rename, **not atomic no-replace**. A noncooperating writer can race the destination check. Rust 1.94.1 uses replacement semantics in its Windows rename implementation, including its access-denied fallback. The exact [retained source](https://github.com/rust-lang/rust/blob/1.94.1/library/std/src/sys/fs/windows.rs) and [MoveFileExW contract](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-movefileexw) define that boundary. This experiment supplies no protection against such a writer, portable publication theorem, directory flush protocol or power loss durability guarantee.

Reopening validates a contiguous committed prefix from genesis. A gap, corrupt frame or unknown entry refuses. Pending files are excluded from the committed sequence. The checksum detects some accidental changes and is deliberately not authentication. A control consistently rewrites a payload and checksum and is accepted. An external trusted commitment is required to detect malicious rewriting or deletion of an entire committed suffix. The finite generation counter is not a persistent authenticated chain instance identity.

## Recorded validation

Three native requests have distinct records in [validation.json](validation.json).

1. The initial hard-link implementation failed its first actual publication with Windows access denied. No primary group or child process completed.
2. The checked-rename implementation completed a source-counted prefix of sixteen primary groups. A later test fixture tried to rename its directory while the lease was open and received actual access denied. The whole test failed. No child process ran. These sixteen groups are a completed assertion prefix, not a passing harness result. Their unchanged assertions remain in `actual_journal_controls` and were not replayed.
3. The corrected `remaining_recovery_controls` test passed. It checks one actual missing-directory error before owner construction, five controlled writer terminations, eleven fresh reader processes, five fresh postrestart writers and one normally completed writer. Twenty-two sequential children run under the same aggregate job. Every interrupted case accepts a new write through a fresh process and checks its complete bytes against independent literals. Three abandoned files remain byte-identical. No earlier completed primary group was rerun.

The first sixteen groups cover literal frames, stale generation, payload and generation limits, actual OS lease contention and release, all four occupied slots, observed destination collision, truncation, checksum and format errors, consistent rewriting, a committed gap, abandonment, first cause with actual cleanup obstruction, postpublication read failure, unknown names and empty/maximum payloads. Cleanup and missing-file controls use explicit interventions in owned test paths. They are not spontaneous hardware failures. The invalid locked-directory intervention was removed rather than reported as a journal failure control.

Process cutpoints are after completed create, write, synchronization, rename and final read operations. Only owned child handles are terminated and waited. No kernel-interior interruption or power failure is tested. The successful remaining test finished in 0.43 seconds, with 1,306,624 bytes peak process private commit and 4,374,528 bytes peak aggregate job commit. Actual external limits were 512 MiB for both process and job, fresh availability of at least 2 GiB, and 120 seconds. These are small diagnostic measurements, not node or blockchain capacity estimates.

Formatting, strict diagnostic Clippy, the unchanged empty default library check and test compilation passed. Corrective compiler checks followed each changed test snapshot. There are no registry dependencies. All 1,139 frozen native inputs were verified after the successful run. No prior proof, witness walk, healthy verifier or mathematical model was replayed.

## Reproduction boundary

```text
cargo clippy --manifest-path research/state-journal/Cargo.toml --release --features diagnostics --all-targets --locked --offline --jobs 1 -- -D warnings
cargo clippy --manifest-path research/state-journal/Cargo.toml --release --no-default-features --lib --locked --offline --jobs 1 -- -D warnings
cargo test --manifest-path research/state-journal/Cargo.toml --release --features diagnostics --test admission --no-run --locked --offline --jobs 1
python -I -S research/state-journal/static_check.py
```

The two native tests are ignored by default. Fresh execution requires source and executable review, new exclusive result paths, `KOVA_JOURNAL_GATE=reviewed-external-resource-admission`, and the actual unchanged [external guard](run_guarded_windows.ps1). The worker uses `CREATE_NO_WINDOW` without job breakaway. The static checker inspects saved evidence without running a journal or child process. CI compiles diagnostics and checks evidence only.

The [historical design](../../docs/snapshot-journal.md) records the earlier uncompiled hard-link candidate and initial resource refusal. The [private transition specification](../../docs/private-transition-state.md) still requires authenticated complete state, delivery retention, atomic monetary and nullifier publication, recovery, reorganization and finality. This bounded storage experiment does not implement those requirements. Private payment proof feasibility, confidential staking and dependent consensus/network activation remain open.
