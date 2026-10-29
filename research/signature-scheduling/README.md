# Factorized private verifier scheduling

The factorized schedule with bound activity removes 7991 columns from the complete bounded signature relation while retaining degree four. Actual symbolic inspection measures 181221 constraints per row. Nine explicitly constrained intermediate fields avoid the higher degree of the first factorized variant. The experiment remains separate from the selected verifier and has no proof or payment acceptance API.

The [reference relation](../signature-complete-native/README.md) remains unchanged. Most component modules are compiled directly from that source. Adapted sampler and matrix modules replace expanded activity expressions with producer bound fields. The [source delta](source-delta.patch) identifies copied changes with zero context hunks. Original licenses and [source identities](provenance.json) are retained.

## Clock relation

Let $m=64$ and $n=128$. Low indicators $l_0,\ldots,l_{m-1}$ and high indicators $h_0,\ldots,h_{n-1}$ satisfy

$$
l_i,h_j\in\{0,1\},\qquad \sum_i l_i=\sum_j h_j=1.
$$

Each transition rotates the low bank. With carry $c=l_{m-1}$, the high bank follows

$$
h'_j=h_j+c(h_{j-1}-h_j),\qquad h_{-1}=0.
$$

The first row fixes $l_0=h_0=1$. The last row fixes $l_{m-1}=h_{n-1}=1$. The zero predecessor prevents the high bank from wrapping into a second complete schedule. Exact row and interval selectors are

$$
s_r=l_{r\bmod m}h_{\lfloor r/m\rfloor},\qquad
s_{[a,b)}=\sum_{r=a}^{b-1}s_r.
$$

These selectors feed the retained source, hash, sampling, transform and hint equations. Key, signature and note bytes retain their original hold rules. Replacing a linear indicator with a product affects the degree of equations that use it, even when the controller alone has low degree.

![Two constrained indicator banks select the fixed private verifier source routes](schedule.svg)

## Activity binding

The first factorized relation has two degree six constraints in the challenge sampler and eight degree five constraints in the matrix sampler. Each uses an activity expression with a phase selector $\phi$ and a completed count indicator $d$. The current relation introduces one challenge activity field and eight matrix activity fields. Each satisfies

$$
a(a-1)=0,\qquad a=\phi(1-d).
$$

The count indicator is the same private state consumed by the sampler. It retains its original Boolean, initialization and transition constraints. The activity equality is asserted inside the same AIR before the source consumer uses $a$. A caller cannot choose activity independently or disable a required source read.

Here $\phi$ has degree two, so its activity binding has degree three. If a source expression $X$ has degree three, the consumer $a(X-x)=0$ has degree four. Expanding $\phi(1-d)(X-x)$ directly has degree six. The source statement is preserved through an explicit intermediate relation rather than a host validity check.

## Measured symbolic scope

The [validation record](validation.json) reports seven ordinary tests and one separately guarded symbolic test. The tests check all selectors and intervals for a 32 row integer reference, 8192 native selector positions, source dimensions, carry and boundary failures, fractional or multiple indicators and repeated schedule refusal. Restoration provides positive controls for eight local clock mutations. Activity tests cover all eight Boolean phase/completion combinations, cache corruption and a deliberately detached negative control that would hide a false source read without the producer equality.

The complete equation set contains 181221 constraints per row and has degree four at width 47058. The symbolic process used a verified 512 MiB process and aggregate limit, a 120 second deadline and at least 2 GiB free memory admission. Its peak process commit was 308523008 bytes and peak aggregate commit 309809152 bytes on Windows with Rust 1.94.1. It built expression trees, not a native field trace.

No native signature tuple, complete native trace or hiding proof was executed for this variant. Source reuse and symbolic inspection do not substitute for those validation gates. The exported research constructor is unmeasured in this variant and is not used by the ordinary or symbolic tests.

## Conditional complete cost

The [cost calculation](costs.json) retains blowup eight, extension degree four, four random columns, sixteen salt columns and 64 queries only for comparison. It does not select a chain proof profile. For degree $d$ in the retained two adic hiding construction,

$$
q=2\,2^{\lceil\log_2 d\rceil},\qquad
H_Q=qN,\qquad \text{constraint row positions}=H_Q C,
$$

where $C$ is the actual number of constraints per row. Each quotient chunk needs its own commitment field file in the current storage experiment.

| Quantity | Original | Factorized v1 | Bound activity v2 |
| :--- | ---: | ---: | ---: |
| Witness columns | 55049 | 47049 | 47058 |
| Constraints per row | 205201 | 181203 | 181221 |
| Maximum symbolic degree | 4 | 6 | 4 |
| Quotient chunks | 8 | 16 | 8 |
| Quotient domain rows | 65536 | 131072 | 65536 |
| Constraint row positions | 13448052736 | 23750639616 | 11876499456 |
| Raw field contents in bytes | 1803845632 | 1541701632 | 1541996544 |
| Prepared and commitment field files in bytes | 32509329408 | 27824291840 | 27796045824 |
| Field files | 11 | 19 | 11 |

Version two retains the original quotient size and eleven field files while reducing conditional field contents and constraint positions. All native shapes still exceed current height, width and aggregate field byte limits. No allowance was expanded and no native proving speedup is claimed. Field positions are an arithmetic count, not an instruction or runtime measurement. [Versioned records](records/README.md) preserve the first experiment and its higher degree result byte identical.

## Schedule alternatives

1. A direct thirteen bit clock makes an exact row selector a degree thirteen product. Its complete signature composition has not been measured. Raw width alone is insufficient for selection.
2. A structured controller can retain explicit indicators for expensive events. Its producer, reset and hold rules must bind every consumer before register reuse is valid.
3. The retained AIR interface supports verifier defined periodic columns and authenticated preprocessed columns. Their public values, transcript binding, queried widths and evaluation tables have costs. Moving a wide schedule into public preprocessing does not make that cost disappear.

Public schedule inputs must be fixed by the verifier. Host supplied row selectors, assumed lookups and independently accepted component joins cannot replace the complete relation. The next gate is native reference tuple and adversarial source validation for the changed schedule before any full proof integration.

## Reproduction

```text
python research/signature-scheduling/reference.py --check
python research/signature-scheduling/static_check.py
python research/signature-scheduling/compare.py --check
python -m unittest discover -s research/signature-scheduling -p test_compare.py -v
cargo fmt --manifest-path research/signature-scheduling/Cargo.toml --all -- --check
cargo test --manifest-path research/signature-scheduling/Cargo.toml --release --locked --lib -- --test-threads=1
cargo clippy --manifest-path research/signature-scheduling/Cargo.toml --release --all-targets --locked -- -D warnings
```

The ignored symbolic test requires its exact resource admission and environment marker. The marker acknowledges an installed external limit and does not install one. Ordinary tests do not run the symbolic test. No complete signature prover is included.
