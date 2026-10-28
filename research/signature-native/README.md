# Private signature sources and forward transforms

This standalone native laboratory derives private signature sources and sixteen forward transforms in one AIR. It accepts raw verification key K2592, signature sigma4627, canonical version 2 note opening N418 and a typed PaymentStatement. Public values are the existing 196 authorization bytes derived from that transaction.

The constructor preserves note owner source equality and the private rho, t1, tr, mu, decoded z, challenge and hint banks. Seven z transforms, one challenge transform and eight scaled t1 transforms read those actual banks. Their 4096 outputs remain witness columns. No public polynomial input, external inverse input, proof backend or payment API is provided.

For private witness $W=(K,\sigma,N)$ and public input $a=A(T)$, the source equations include

$$
\operatorname{owner}(N)=\operatorname{SHA3\!\!\text{-}\!512}(K),
\qquad
\mu=\operatorname{SHAKE256}(\operatorname{SHAKE256}(K,64)\parallel M'(a),64).
$$

The retained contextual framing defines $M'$. With $q=8380417$, the connected transform outputs are

$$
\widehat z_j=\operatorname{NTT}_q(z_j),\quad 0\le j<7,
\qquad \widehat c=\operatorname{NTT}_q(c),
\qquad \widehat t_i=\operatorname{NTT}_q(8192t_{1,i}),\quad 0\le i<8.
$$

Every coefficient uses its canonical residue in $[0,q)$. A negative challenge coefficient is $q-1$. Neither the note commitment nor an owner identifier is added to the public input.

The frame is 8192 rows by 44678 columns. The packaged source has measured symbolic degree 4 and 146260 constraints per row. Its native A0 test passed all 4096 independent direct Horner comparisons and limited local product and write controls. Those controls retain unchanged downstream writes. They do not isolate a consistently rebuilt suffix. The [execution record](execution_record.json) retains the packaged build, lint, selected test and resource results.

The main field payload is 1464008704 bytes before JSON, checker, allocator and stack costs. All three tests are ignored and require explicit external resource admission. The environment markers assert setup. They do not install limits. Use a process and aggregate memory cap, fresh available memory, a finite deadline and one selected test per process.

From the repository root:

    cargo test --manifest-path research/signature-native/Cargo.toml --release --lib --no-run --locked --jobs 1
    cargo fmt --manifest-path research/signature-native/Cargo.toml -- --check
    cargo clippy --manifest-path research/signature-native/Cargo.toml --release --all-targets --locked -- -D warnings
    cargo test --manifest-path research/signature-native/Cargo.toml --release --lib --locked -- --ignored --list

The static, symbolic and native selectors are tests::shape_schedule_and_private_routes, tests::actual_symbolic_shape_and_degree and tests::sixteen_direct_source_transforms_and_locally_exact_crosswires. Their respective markers are THORUM_PRIVATE_NTT_STATIC_GATE, THORUM_PRIVATE_NTT_SYMBOLIC_GATE and THORUM_PRIVATE_NTT_NATIVE_GATE, with value reviewed-external-resource-admission. A selected run uses --ignored --exact, --nocapture and --test-threads=1. Successful selection has one pass and two filtered tests.

Fixtures are the existing [signature ownership corpus](../signature-ownership/README.md). No new signatures or large fixture copies are needed. The public data mapper is local and unchanged. Source hashes, retained arithmetic references and license provenance are recorded in source_record.json.

The source, fixture and execution identities can be checked with `python research/signature-native/static_check.py`. CI compiles the ignored tests and checks formatting, strict lints and retained records. Wide native execution remains a separately bounded serial action.

The 56 matrix streams, eight inverse transforms and reconstructed rows, UseHint and ordered private w1, final challenge hash and full equality remain unfinished. Complete hidden-note membership, nullifier, conservation, delivery and payment authorization remain separate gates. These native results establish neither full signature validity nor signing authority. No backend proof has been constructed for this AIR.
