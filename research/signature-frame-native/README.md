# Genuine clock and packed source constraints

This experiment evaluates the retained clock and packed source equations on genuine frames produced by the complete bounded source cursor. Both functions execute in their original order. Actual global row coordinates determine first, last and transition selectors.

For a frame at row $r$ in the fixed height $H=8192$ relation,

$$
f_r=[r=0],\qquad \ell_r=[r=H-1],\qquad t_r=[r\ne H-1].
$$

The two borrowed rows have the actual width 43176. The final frame uses the original source row zero as its next row. A two row diagnostic matrix does not define the global boundary selectors.

## Executed scope

One streamed source walk supplies twelve selected adjacent frames. The retained concrete field constraint builder executes actual clock and packed equations on each baseline, seven modified frames and seven restored frames. All baseline and restored evaluations require an empty full failure list. Each negative requires its expected actual failed constraints. The current clock mutation deliberately permits coupled later failures.

| Control | Failure requirement |
|---|---|
| Current first clock value | Clock indices 0, 1, 5 and 576, with coupled failures permitted |
| High clock carry | Exactly 194 and 197 |
| Next held source word | Exactly 580 |
| Selected signature byte bit | Exactly 6158 |
| Compensated non Boolean bits | Exactly 6103 and 6104 |
| Unused Boolean port bit | Exactly 6315 |
| Locally consistent virtual tail byte | Exactly 6131 |

The last control adjusts both held tail words and the matching current port. Its padding isolation applies only to the evaluated borrowed frame. It does not describe a globally consistent modified trace. Expected index annotations derive from retained source order and the existing literal tail port list. They neither drive nor filter the actual equations.

## Evidence and boundaries

The [validation record](validation.json) retains 26 combined evaluations, 19 positive and seven negative outcomes, seven successful restorations and actual resource measurements. The complete streamed source is dependency work for these newly executed constraints. Closed reference, route and padding corpora are not replayed.

The native builder collects every failure for one finite frame. The conservative source bound is 6502 failures, with allocator overhead additional. Saved output records at most eight leading indices and the complete failure count. The builder and full failure list drop before the next evaluation. This bound is not a newly measured clean assertion count.

These two callees do not execute the complete signature AIR or its final challenge equality. No hiding proof, payment acceptance or network result is established. The default complete constructor remains disabled and the retained proof resource refusal remains. Input commitments and ownership material remain private witness data within the construction. Cryptographic confidentiality still requires the complete hiding proof and ledger composition.

## Reproduction

Rust 1.94.1 and exact locked dependencies define the compiled source. Static checks validate saved identities and observations without constructing rows or evaluating constraints.

```text
python -I -S research/signature-frame-native/static_check.py
cargo clippy --manifest-path research/signature-frame-native/Cargo.toml --locked --offline --no-default-features --lib -- -D warnings
cargo clippy --manifest-path research/signature-frame-native/Cargo.toml --locked --offline --no-default-features --features frame-controls --lib --test frame -- -D warnings
cargo test --manifest-path research/signature-frame-native/Cargo.toml --locked --offline --no-default-features --features frame-controls --release --test frame --no-run --jobs 1
```

The Windows guard installs and reads back process and aggregate limits before launching one explicit test. Native repetition requires separate source and resource review. Component measurements do not establish full proof feasibility. Provenance, the root adaptation patch and the MIT license retain the implementation lineage.
