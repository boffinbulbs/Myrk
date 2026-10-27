# Transparent signature verification reference

This directory retains an independent mathematical verifier for pure contextual ML-DSA-87 signatures. Python integer arithmetic, explicit normal residue transforms and standard library SHAKE reproduce complete verification, including exact key and signature decoding, strict norm rejection, matrix and challenge sampling, reconstruction, hint application and final challenge equality. The generator imports the local Python verifier by its file path. It imports neither the native implementation nor a proof backend.

All fixture bytes and all intermediate values are public. This is a transparent reference artifact, not a private signature AIR, a proof component or a production transaction validator. It does not increase the eight isolated proof laboratories described in the implementation record. Native signature verification over these public bytes does not establish private spending permission or the complete private payment relation.

## Sources and scope

The normative baseline is [NIST FIPS 204](https://csrc.nist.gov/pubs/fips/204/final), published August 13, 2024, with SHAKE as specified in [NIST FIPS 202](https://csrc.nist.gov/pubs/fips/202/final). The FIPS 204 publication record identifies [potential updates](https://csrc.nist.gov/files/pubs/fips/204/final/docs/fips-204-potential-updates.xlsx), whose retained SHA256 is `5bc93ce63bc647e6d1d456cb2d3a171426c15aca4a7a0e0edd40d08b7a34c793`. The workbook records July 31, 2026 as its update date. These are potential updates rather than a replacement standard. The review covers the order `mu || w1`, the distinction between the message and its context encoding, odd root evaluation order, the four bit upper bound for `w1` and representation details. The reference uses normal residues and does not use Montgomery arithmetic.

The native comparison is pinned to `ml-dsa` version `0.1.1`, source commit `f75d5b829948988f18d9463f286805fb9410bcdd`, and `module-lattice` version `0.2.3`. Exact source and archive digests, retained input digests and source links appear in [source_record.json](source_record.json). Version updates require separate review and new evidence.

The National Institute of Standards and Technology is the source of the two retained official verification answers and of the public key generation seed used for the synthetic fixture. Original group and case identifiers, source digests, attribution and the complete required notice are retained in [the official vector record](../crypto/vectors/README.md) and [UPSTREAM-NOTICE.txt](../crypto/vectors/UPSTREAM-NOTICE.txt). This corpus selects the two answers without altering their cryptographic values. Additional synthetic signatures, malformed cases and diagnostic intermediate values were created on October 27, 2026. The retained vector file must match SHA256 `fe61306ae7bafad8b36d2ef8cac9cf12ce3706afe12171b8e7b27d97edba7de4` before the generator uses it.

This selected corpus is not the complete ACVP suite, an ACVP validation session, certification, a security audit, a constant time implementation claim or evidence of a composed post quantum private protocol.

## Encodings and strict rejection

The parameter set uses $n=256$, $q=8380417$, $k=8$, $\ell=7$, $d=13$, $\tau=60$, $\gamma_1=524288$, $\gamma_2=261888$, $\beta=120$ and $\omega=75$.

| Encoding | Exact byte range | Meaning |
|---|---|---|
| Public key | `[0,32)` | Matrix seed `rho` |
| Public key | `[32,2592)` | Eight polynomials with 256 coefficients packed in ten bits each |
| Signature | `[0,64)` | Received challenge hash |
| Signature | `[64,4544)` | Seven response polynomials with 256 coefficients packed in twenty bits each |
| Signature | `[4544,4619)` | At most 75 sparse hint indices |
| Signature | `[4619,4627)` | Eight cumulative hint segment endpoints |

The public key must have exactly 2592 bytes and the signature exactly 4627 bytes. A twenty bit response encoding $e$ decodes to $z=\gamma_1-e$. Verification requires the strict inequality

$$
\lVert z\rVert_\infty<\gamma_1-\beta=524168.
$$

Accepted signed coefficients lie in $[-524167,524167]$, corresponding to encoded integers $e\in[121,1048455]$. An altered coefficient within that interval still requires successful complete challenge verification.

Hint endpoints must be nondecreasing and at most 75. Within each polynomial's segment, active indices must be strictly increasing. Empty segments are allowed. An index may appear in different polynomial segments, and zero is a valid active index. Every unused index byte after the final endpoint must be zero. These rules ensure canonical sparse decoding rather than merely a bounded hint count.

## Complete verification calculation

Let $K$ be the encoded public key, $M$ the exact message and $D$ the pure context, with $|D|\le255$. The hashes are unframed FIPS operations:

$$
tr=\operatorname{SHAKE256}(K,64),
\quad M'=\mathtt{00}\mathbin\Vert\operatorname{u8}(|D|)\mathbin\Vert D\mathbin\Vert M,
\quad \mu=\operatorname{SHAKE256}(tr\mathbin\Vert M',64).
$$

Matrix sampling reads SHAKE128 of `rho || column || row`. Each candidate uses three little endian bytes with the top bit removed and is accepted only below $q$. Sampling continues until 256 coefficients are accepted. The retained 840 byte initial stream is an implementation starting size, not a universal rejection sampling limit. The challenge sampler uses SHAKE256 of the received challenge hash and independently records every rejected byte.

The root $\psi=1753$ satisfies $\psi^{256}=-1\pmod q$ and $\psi^{512}=1\pmod q$. Transform output position $i$ evaluates the input polynomial once at $\psi^{2\operatorname{bitrev}_8(i)+1}$. The normal residue forward and inverse schedules agree with the separately retained [NTT references](../ntt-proofs/README.md), with inverse normalization $256^{-1}=8347681\pmod q$.

After decoding $t_1$, $z$ and hints $h$, the verifier reconstructs

$$
c=\operatorname{SampleInBall}(\widetilde c),
\qquad
w'=\operatorname{NTT}^{-1}\left(\widehat A\operatorname{NTT}(z)-\operatorname{NTT}(c)\operatorname{NTT}(2^{13}t_1)\right).
$$

Each row's hint reconstructs $w_1'=\operatorname{UseHint}(h,w')$. Every coefficient is in $[0,15]$ and packs into four bits, so the eight polynomial encoding has 1024 bytes. The final equality is

$$
\widetilde c=\operatorname{SHAKE256}\left(\mu\mathbin\Vert\operatorname{Encode}(w_1'),64\right).
$$

[verification_stages.json](verification_stages.json) records both official cases and all four genuine synthetic signatures, including owner hash, `tr`, exact `mu` preimage and digest, reconstruction coefficients, encoded `w1`, received and expected challenges, norm, hint weight and sampling cursors. These intermediate values expose the entire public calculation and are never a private wallet export format.

## Exact synthetic authorization

[synthetic_authorization.json](synthetic_authorization.json) contains one signature over the existing synthetic 196 byte authorization input $A$ with the exact 41 byte context `Thorum crypto laboratory authorization v1`. It also retains genuine alternate signatures for an empty context, a changed authorization message and a different key. Each alternate verifies under its own exact tuple of key, message and context. Substitution of any alternate signature into the original tuple fails.

The corresponding [application inputs](../hash-proofs/application_inputs.json) retain a structural 2402 byte canonical transaction with one input and one output, including a structural 2036 byte envelope. For $F(x)=\operatorname{u32be}(|x|)\mathbin\Vert x$, the reference rebuilds the existing transaction, derives its authorization digest and tag, encodes the resulting 80 byte crypto context and reconstructs $A$ with the existing framed domains and suite. Each altered transaction case recomputes this entire sequence. It does not replace the message with an unrelated arbitrary digest.

For this exact fixture, the FIPS `mu` input has $64+2+41+196=303$ bytes. The mathematical verifier checks the signature on $A$. The Python generator checks the relationship between synthetic transaction bytes and $A$ outside any proof. The structural envelope is not evidence of valid recipient encryption or recovery. No AIR in this directory links the key, signature, hashes and transaction.

The signing seed comes from the retained official key generation case. The alternate owner uses that same public seed with its first byte changed. Both seeds and every derived key are known public test data. They must never be used for operational signing, funds, wallet recovery or entropy evaluation. The verifier implements no signing and consumes no seed. The separate native example generates these four public deterministic signatures.

## Retained cases

[cases.json](cases.json) retains 49 exact cases, with five expected valid results and 44 expected invalid results. These numbers describe the corpus rather than a proof security or conformance claim.

| Cases | Count | Coverage |
|---|---|---|
| Official verification answers | 2 | One valid and one invalid external pure signature |
| Exact synthetic authorization | 1 | Genuine signature over the existing `A196` and context |
| Alternate signatures | 6 | Three genuine signatures in their own contexts and three substitutions into the original tuple |
| Key and signature byte changes | 12 | Matrix seed, packed public key, challenge, response and final response byte positions |
| Wrong encoded lengths | 6 | Empty, truncated and overlong keys or signatures |
| Changed contexts | 4 | Empty, changed, 255 byte and invalid 256 byte contexts |
| Signed response boundaries | 5 | Strict norm rejection and full challenge rejection for admissible altered coefficients |
| Malformed hints | 5 | Excessive or decreasing endpoints, nonzero unused data, duplicate and descending indices |
| Rebound transaction fields | 8 | Chain, tag, root, input nullifier, output commitment, envelope, current protocol version and fee |

Each case records `name`, `public_key_hex`, `signature_hex`, `message_hex`, `context_hex`, `expected_valid`, `expected_rejection` and the violated condition. The native integration independently compares its Boolean result with every retained classification. Mathematical reference agreement, native implementation agreement and a future private proof relation are separate validation boundaries.

## Reproduction and remaining proof work

Run these commands from the repository root. Python commands use only the standard library and do not run a prover. `--check` compares all retained JSON outputs byte for byte, including the six detailed stage records and source record, without rewriting them.

```text
python research/signatures/reference_vectors.py --check
python research/signatures/verify_reference.py
cargo run -p thorum-crypto-lab --example signature_reference_fixture --locked --offline -- --check
cargo test -p thorum-crypto-lab --test signature_reference --locked --offline
```

Running the reference generator without `--check` reproduces `cases.json`, `verification_stages.json` and `source_record.json` from the retained inputs. Running the native example without `--check` reproduces `synthetic_authorization.json` with a final newline. None of these commands performs a network transaction or accepts a payment.

A future private verification relation must keep the actual verification key, signature, coefficients, matrix, sampled challenge, intermediate hashes and note owner binding internally connected. It must enforce canonical decoding, norm and hint rules, every sampling decision, exact transform and reconstruction arithmetic, final challenge equality and the same complete canonical transaction. Public intermediate checks cannot supply a hidden private relation by themselves. Eligible roots, global spent nullifiers, atomic state changes, recipient encryption, recovery and the composed security argument remain required independently. The [private owner key binding record](../../docs/owner-binding-proof-lab.md) defines the current preimage boundary.
