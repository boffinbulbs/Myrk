# Fixed signature proof boundary

This laboratory connects owned signature inputs and canonical transaction preprocessing to a fixed resource assessment interface. It constructs neither a trace nor a hiding proof. The dependency on the complete packed signature relation keeps native execution disabled.

## Owned inputs

For a public transaction T, the retained mapper derives the 196 public authorization bytes A(T). The input object owns

$$
B=(w,T,A(T)),\qquad w=(k,\sigma,n).
$$

Here k is the private verification key source, sigma is the private signature source and n is the private note opening. The existing typed Witness supplies fixed arrays of 2592, 4627 and 418 bytes. Their lengths do not establish canonical private encoding or validity. The constructor accepts only the actual Witness and an owned PaymentStatement. It derives the actual Statement from that same transaction.

BoundInputs has private fields, no cloning or serialization interface, no private getters and no transaction setter. Its public values come only from the retained canonical mapper. This preserves an input ownership boundary for subsequent integration. It does not authenticate the witness, erase secrets from memory or prove the same witness ledger joins.

Public preprocessing retains the existing canonical transaction limits and errors. A correctly sized invalid private source can be bound because private verification belongs to the future constrained proving path. Binding is never payment authorization.

## Actual resource assessment

The assessment borrows the actual retained HidingFriPcs and instantiates the actual PackedSignatureOwnerAir. Callers cannot supply another AIR, dimensions, derived operands, request or profile. The request uses the fixed source height 8192, typed BabyBear quartic extension, two main opening points, retained declaration of eight quotient chunks and shift one.

The upstream allocation free batching helper supplies the conditional request count of 86432 functions. Eight chunks and four masking codewords remain retained class declarations. They are not newly measured full proof parameters or a selected security profile.

The real planner reads

$$
W_{\mathrm{packed}}=43176>W_{\mathrm{class}}^{\max}=8
$$

and returns RawWidth before inspecting later PCS parameters, evaluating symbolic constraints, drawing entropy or touching storage. The wrapper propagates that actual refusal. An unexpected planner success stops at UnsupportedIntegration. The return type cannot contain a successful proof or construction permission.

An early width refusal does not validate the actual FRI configuration, masking lifetime, hash policy, transcript, field payload, transport bounds or security composition. A deliberately changed later query parameter reaches the same width refusal. No configuration certificate follows from that result.

## Bounded controls

Three nonproving integration groups cover two independently retained canonical transaction and A196 records, external public mutation isolation, two actual canonical limit errors and two actual fixed relation resource refusals. The private arrays in the binding controls are deliberately invalid. No signature validation result is attributed to them.

The resource fixture uses actual base and extension hiding MMCS types. Continuing mask and salt RNG calls share an observer. All five nominal storage hooks fail immediately before dense defaults can run. Store clones are observed separately. Counters are sampled after configuration and compared afterward without resetting them. A fork would consume observed parent seed material. Descendant RNG activity is not separately measured.

Six bounded observations synchronize before their result assertions. Each selected run requires fresh result paths and one test thread. The execution record in validation.json distinguishes observed counters from source reach and records the actual guard limits and outcome.

The selected Windows run passes all three groups with six observations. Both actual planner calls return RawWidth with unchanged zero observer counts. The kernel reports 2265088 bytes of peak aggregate commit under the unchanged 512 MiB process and aggregate limits. Available memory before launch was 11134541824 bytes against a 2 GiB admission requirement. No trace, symbolic evaluation or backend proof is executed by this gate.

## Integration still required

The complete packed constructor remains dense and runs several dependent passes. An owned streamed producer, canonical quotient views, shared opening lifetime and actual nominal type bridges remain unfinished. The preflight and source prover crates include retained backend code as different Rust types. Source identity does not make those types interchangeable.

Full proof work must bind the fixed constraint relation and profile in both prover and verifier, preserve masking and transcript order, and account for all simultaneously retained storage and proof buffers. Current resource and transport refusals remain unchanged.

The signature and note sources must still join the same hidden eligible input, stable nullifier, unspent state, restrictions, conservation and encrypted delivery. This input boundary does not supply those equations or establish private payments. The full system privacy and post quantum security targets remain subject to implementation and review.

## Reproduction and provenance

Use Rust 1.94.1 with the committed lockfile. Format and compile only the selected contract integration target, then run the reviewed finite admission with fresh outputs. The unchanged small Windows guard enforces 512 MiB process and aggregate commit limits, at least 2 GiB available memory and a 120 second deadline. No old native, symbolic or proof suite is selected by this package.

provenance.json records retained sources, critical registry files, actual features and execution inputs. The two public records are selected verbatim from the existing independent signature ownership reference. The test PCS fixture is adapted from proof-preflight/tests/preflight.rs and imports the retained storage hash helper with original attribution preserved. The new library is MIT licensed. Dependencies retain their own licenses.
