# Transaction signature and note ownership references

This corpus defines complete independent integer references for six ML DSA 87 signatures over two typed synthetic transactions. The reference covers transaction framing, all eight reconstructed signature rows, the final challenge comparison and the canonical note owner field. These computations provide expected values for subsequent private constraint implementation. They do not establish native AIR acceptance, a backend proof, input membership, nullifier coupling or payment authority.

The raw fixture contains six deterministic signatures from fixed public synthetic seeds. Native verification checks the contextual API and the retained authorization wrapper. Independent integer computation reconstructs the complete signature and canonical owner relation. The source record and execution record identify the tested scope and fixed outputs.

## Exact public transaction input

Let $F(x)=\operatorname{u32be}(|x|)\parallel x$, and let

$$
H_d(x_1,\ldots,x_n)=\operatorname{SHA3\!\!\text{-}\!512}
\left(F(d)\parallel F(x_1)\parallel\cdots\parallel F(x_n)\right).
$$

The two transactions have the same chain identifier `00` through `1f`, protocol version 7, validation tag, anchor, two nullifiers, two commitments and two synthetic envelopes. T0 has a fee of 5 atomic units. T1 changes only that fee to 6 atomic units. The envelopes exercise the canonical codec and are not encrypted delivery evidence.

For the canonical transaction bytes $T$, the authorization mapping is

$$
\begin{aligned}
m&=H_{\texttt{payment-authorization.v1}}(T),\\
v&=H_{\texttt{payment-auth-context.v1}}(m)[0:32],\\
X&=F(\mathrm{chain})\parallel F(\operatorname{u32be}(7))\parallel F(v),\\
A(T)&=F(\texttt{thorum.crypto-lab.authorization.v1})
\parallel F(\operatorname{u16be}(1))\parallel F(X)\parallel F(m).
\end{aligned}
$$

The first two hash domains include the prefix `thorum.relation-lab.`. The Context encoding $X$ is 80 bytes, $m$ is 64 bytes and $A(T)$ is 196 bytes. The complete domain strings and field ordering are executable definitions in `reference_vectors.py`. The native mapper in `authorization.rs` derives the same values directly from `PaymentStatement`.

The contextual signing API receives $A(T)$, not an already prefixed pure message. With the fixed 41 byte ASCII context $C=\texttt{Thorum crypto laboratory authorization v1}$, pure ML DSA uses

$$
M'=\texttt{00}\parallel\texttt{29}\parallel C\parallel A(T),
\quad |M'|=239,
\qquad
tr=\operatorname{SHAKE256}(K,64),
\quad
\mu=\operatorname{SHAKE256}(tr\parallel M',64).
$$

Here $K$ is the complete 2592 byte verification key. The $\mu$ preimage has 303 bytes. A valid signature over T1 must not authorize T0.

## Finite signature corpus

Key A uses the retained NIST sample seed. Key B changes byte zero by XOR 1. Both key encodings are checked against the existing signature reference. The seeds are public synthetic data and cannot protect funds.

| Signature | Key | Transaction | Signed context |
| --- | --- | --- | --- |
| A0 | A | T0 | Fixed 41 bytes |
| A1 | A | T1 | Fixed 41 bytes |
| B0 | B | T0 | Fixed 41 bytes |
| B1 | B | T1 | Fixed 41 bytes |
| A0_empty_context | A | T0 | Empty |
| A0_wrong_context41 | A | T0 | Final context byte changed from `1` to `0` |

All six signatures must verify under their own contexts. Only the first four must verify under the fixed target context. Each result is checked through the contextual native API and the retained `verify_authorization` wrapper. The context controls must return `SignatureFailed` through that wrapper.

The producer has two disjoint modes. `--verify-only RAW_JSON` reads at most 512 KiB plus one overflow byte, validates the fixed schema and provenance, rederives both keys and transactions, and verifies the existing signatures. It contains no signing operation. `--output NEW_FILE` reserves a new file before key derivation and makes exactly six deterministic signing calls. There is no outer retry, seed search, unsupported case filtering or overwrite mode. Standard internal rejection sampling remains part of the retained signing algorithm.

## Full integer verification

The arithmetic parameters are $q=8380417$, $n=256$, $k=8$, $\ell=7$, $\tau=60$ and $\omega=75$. For each reconstructed row,

$$
u_i=\operatorname{NTT}^{-1}\left(
\sum_{j=0}^{6}\widehat A_{ij}\odot\operatorname{NTT}(z_j)
-\operatorname{NTT}(c)\odot\operatorname{NTT}(2^{13}t_{1,i})
\right)\pmod q,
\qquad
w_{1,i}=\operatorname{UseHint}(h_i,u_i).
$$

The matrix coefficients are sampled directly in the NTT basis. Every value uses canonical residues at the reference interfaces. Each signature records seven transforms of z, one of the challenge, eight of shifted t1 and eight inverse transforms. Those 24 transforms are compared against separate direct odd root computations. Every UseHint result is also compared against a separate decomposition oracle.

All eight packed rows contribute 1024 bytes to the final challenge hash. Equality compares every one of its 64 output bytes with the received seed. The reference retains all 56 matrix polynomials once per key, every column product and accumulator, all transform stages, all 2048 hint steps and all packed bytes. It imports the pinned mathematical modules in `../signatures`, `../ntt-proofs` and `../coefficient-constraints`. It does not import a Rust trace builder or a large streamed fixture corpus.

The standard rejection samplers are unbounded. The prospective finite constraint class uses six SHAKE128 blocks, 1008 bytes and 336 matrix candidate events, plus 272 challenge bytes. A valid standard sample beyond either capacity is classified `UnsupportedCapacity`. It remains in the reference data. Capacity classification is distinct from signature validity.

## Canonical note owner relation

The synthetic notes use the exact 418 byte v2 Payment opening codec. Their chain identifier matches the transaction chain, their creation version is 1, their native asset identifier is zero and their amount is 50 atomic units. Creation version and transaction protocol version are distinct fields. The owner field is

$$
\operatorname{owner}(N)=\operatorname{SHA3\!\!\text{-}\!512}(K).
$$

It occupies opening bytes 141 through 204. The v2 commitment hashes the full framed opening under `thorum.relation-lab.note-commitment.v2`. Public synthetic nullifier and recipient key bindings, serial values, blinding values and the Payment policy follow the exact recipe in `reference_vectors.py`.

Ten conditional tuples cover the six signatures, an alternate note with the same owner, a wrong owner note, a wrong verification key and an A1 signature checked against T0. Replacing a complete private witness by another valid owner witness is allowed. The conditional reference accepts only when the fixed context signature is valid, the actual note owner matches the actual key, and the finite capacities suffice. A note commitment alone does not establish an unspent note or bind a nullifier.

## Reproduction

Run from the repository root with Python assertions enabled and Rust 1.94.1. `static_check.py` checks source hashes, Python syntax, local paths and retained registry tuple membership without mathematical imports or Cargo. The producer is a standalone workspace with three path dependencies into this repository. Its lock pins 52 registry packages already present in the retained dependency inventory.

```text
python research/signature-ownership/static_check.py
cargo run --release --locked --manifest-path research/signature-ownership/producer/Cargo.toml -- --verify-only research/signature-ownership/raw-fixture.json
python research/signature-ownership/reference_vectors.py --input research/signature-ownership/raw-fixture.json --output research/signature-ownership/reference-fixture.json --check
```

The generator uses only Python standard library code and retained repository modules. It reads the raw file within 512 KiB, rejects duplicate keys and limits reference output to 32 MiB. `--check` recomputes the committed arithmetic without writing or signing. To create a separate reference file, omit `--check` and select a new output path. Existing files are never replaced. Optimized Python execution is refused before checks and mathematical imports.

A separate deterministic raw reproduction, when needed, uses `--output NEW_FILE`. It creates six new signature API calls and must use a fresh destination. Verification and reference reproduction require no additional signing.

The source inventory distinguishes local files from retained repository sources. `source_record.json` records source preparation and execution status. Native private constraints, backend verification of complete authorization, hidden note membership and a complete private payment remain separate implementation requirements.

## Source attribution

Original code and derivative synthetic data use the Thorum MIT license in `LICENSE`. The local public authorization mapper is retained byte for byte. Existing mathematical modules retain their original repository provenance.

The native primitive is RustCrypto `ml-dsa` 0.1.1 from revision `f75d5b829948988f18d9463f286805fb9410bcdd`, with archive SHA256 `add6b9d92e496f16f4526d68ff29da1483aba4b119baeab8bed3b9e3544a6f3d`. Its original MIT and Apache 2.0 notices are in `licenses`. The existing dependency inventory supplies the transitive source and license records.

The public seed comes from NIST ACVP sample data at revision `975de31eb83d87039ec88934fdc47d8c312b892d`. The selected data SHA256 is `fe61306ae7bafad8b36d2ef8cac9cf12ce3706afe12171b8e7b27d97edba7de4`. `UPSTREAM-NOTICE.txt` preserves the full required NIST notice. The new signatures and note tuples are derivative synthetic research data. The original selected sample values are unchanged.
