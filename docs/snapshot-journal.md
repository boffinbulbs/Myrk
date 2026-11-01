# Bounded snapshot publication and restart design

This source review develops a small storage candidate for the [atomic state specification](private-transition-state.md). It ships no journal implementation and establishes no payment, consensus or restart capability. The candidate accepts public synthetic byte payloads rather than private witnesses or proof verdicts. Its uncompiled source requires further ownership review before execution.

## Existing storage and platform boundaries

The [checked matrix](../research/storage-matrix/src/lib.rs) owns an open descriptor and validates dimensions, lengths and canonical fields. Its source explicitly leaves external modification as a threat. The [preparation store](../research/fallible-input/src/lib.rs) records exclusive file creation, first causes and owned cleanup, while excluding durable crash recovery. Neither is an immutable byte journal.

The latest [composite owner](../research/opening-domain/src/composite.rs) preserves writer claims, private data lifetime and first failure. Those mechanisms remain unchanged. A journal must not reuse its private proof opening flags as storage publication authority. The [bounded reader](../research/frame-reader/src/reader.rs) provides separate byte admission and reader ownership, not state publication or filesystem durability.

The reviewed installed standard library is Rust 1.94.1. Its Windows file operations use `LockFileEx`, `FlushFileBuffers` and `CreateHardLinkW` for the selected primitives. The [versioned Rust source](https://github.com/rust-lang/rust/blob/1.94.1/library/std/src/sys/fs/windows.rs) and [Microsoft hard link reference](https://learn.microsoft.com/en-us/windows/win32/api/winbase/nf-winbase-createhardlinkw) identify the platform boundary. An additional hard link names the same file, so another writable alias can change its contents. A hard link is not an immutable copy.

The proposed experiment assumes a trusted starting directory on the same local NTFS volume, cooperative writers using the same lock, and no hostile namespace replacement. Metadata and reparse checks can reject observed violations, but do not supply a general race resistant directory capability. Other filesystems and noncooperating mutation need separate designs.

## Candidate frame and bounded contents

For generation $g$, parent $p$, payload $x$ and length $\ell$, the proposed experimental frame is

$$F_g=\texttt{KJS1}\parallel\operatorname{BE64}(g)\parallel
\operatorname{BE64}(p)\parallel\operatorname{BE32}(\ell)\parallel x\parallel\operatorname{BE32}(s).$$

The finite candidate permits $g\in\{0,1,2,3\}$ and $0\le\ell\le64$. The genesis parent is $2^{64}-1$ and later parents equal $g-1$. The checksum $s$ is the wrapping sum of the preceding bytes. It is only an accidental corruption control. An attacker can alter a payload and recompute it. It supplies no cryptographic authentication or trusted ledger root.

Frames contain $28+\ell\le92$ bytes. The proposed namespace contains a four byte `LOCK`, four `frame-i` names and four `pending-i` names. The conservative logical content bound is

$$4+8\cdot92=740\ \text{bytes}.$$

Hard linked names can share physical data. This expression is not filesystem allocation, directory metadata, process memory or a blockchain capacity limit. Caller owned input memory, paths, runtime allocations and process buffers require separate accounting. These are deliberately small storage experiment bounds, with no change to any proof class.

## Writer and publication lifetime

| Stage | Candidate operation | Proposed visibility |
|---|---|---|
| Lease | Open the existing instance lock and acquire a nonblocking OS lock | No new snapshot |
| Admission | Validate current generation, bounded payload and reserved names | No new snapshot |
| Create | Exclusively create an owned pending file | Pending data only |
| Write | Write the complete framed payload | Pending data only |
| Synchronize | Synchronize and close its writable descriptor | Pending data only |
| Publish | Create an exclusive hard link from that file to its generation name | Candidate successor becomes discoverable |
| Cleanup | Remove only this attempt's pending name | Committed name retained |

A failed destination creation must preserve the existing file. The candidate therefore uses an exclusive link operation rather than a replacing rename. A successful publication followed by failed cleanup must not be reported as if no successor exists. Dropping a journal owner closes its lease and retains committed files. Cleanup preserves the first error and never adopts unlink authority over a preexisting sentinel.

Publication generation is separate from payload contents or block height. Returning from payload A through B to A must not make an attempt expecting the original generation current. Writer exclusion and stale generation checks do not establish that the bytes represent an authorized ledger transition.

## Restart selection and unresolved ownership

The candidate reader starts from a trusted initialized instance and validates a contiguous committed prefix beginning at generation zero. Every record must match its filename, parent, length, format and checksum. Gaps, malformed committed records and unsupported names refuse. Unpublished pending files do not become committed records merely because their numbers are larger.

This prefix rule cannot detect a malicious consistent rewrite or deletion of an entire committed suffix without an independent trusted commitment point. Snapshot authentication and rollback protection are separate requirements. Taking the highest complete record is not a substitute for consensus authenticated history.

Source review found an additional construction gap before compilation: a fixed pending name per generation survives interruption before publication and blocks the next writer for that generation. Reading the previous snapshot does not complete writable recovery. Removing that orphan automatically would violate ownership unless a separate recovery rule establishes the right to do so.

A finite pool within the existing four pending names is one possible direction. Its reservation, abandoned slot handling, exhaustion, generation binding and cleanup must be reviewed together. It must not overwrite another owner's pending file or expand the content class to hide the issue. No slot recovery policy is selected or validated by this increment.

## Planned controls and execution status

Independent literal frames specify payload A at generation zero, B at generation one and A at generation two. Their respective checksum literals are 2387, 349 and 350. These bytes are source anchors, not executed reference results.

Required controls include real lease contention and release, existing pending and publication destinations, actual truncation, malformed parent and format, checksum mismatch, consistently rewritten checksum acceptance, stale generation, failed reentry, owned cleanup and exact payload bounds. A namespace intervention that obstructs cleanup must be identified as such rather than described as a spontaneous disk failure.

The planned process experiment terminates only owned children after completed create, write, synchronize, publication and cleanup operations, then reopens through fresh processes. Those points do not cover interruption inside a kernel operation. No child interruption or restart test has executed. Process termination, filesystem failure and power failure are distinct fault models. No portable atomic publication or power loss durability theorem is established by these APIs or by a future successful test.

An initial formatting preparation was refused by its fresh memory check before target process creation. No formatter, Rust compiler, model, journal, child process or native test ran. The [preparation record](../research/snapshot-journal/preparation.json) preserves that scope. The uncompiled candidate is not included in this source publication. Recorded [source identities](../research/snapshot-journal/source-record.json) support the existing implementation and platform review, not a runtime claim.

Next construction must resolve writable recovery and complete finite ownership, namespace, buffer, descriptor and child process accounting before a new build or execution selection. The complete private proof, confidential stake, durable consensus state and network gates remain open. Journal mechanics cannot replace the same hidden witness across membership, owner authorization, stable nullifier, conservation, encrypted delivery and atomic ledger consumption.
