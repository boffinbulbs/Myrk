# Complete proof transport feasibility

This source review identifies a conditional incompatibility between the complete overlay and the retained proof representation. It constructs no proof, query array or encoded payload. The current small decoder does not accept the full relation. The [source identities](transport-sources.json) record the reviewed implementation and dependency editions.

## Actual representation

The original uni-STARK `Proof` serializes its PCS opening proof. The hiding PCS retains a tuple of random codeword claims and the inner FRI proof. The physical domain wrapper preserves that proof type. The inner [FRI proof](../storage-pcs/backend/src/proof.rs) stores `BatchMultiOpening::opened_values` as `Vec<Vec<Vec<T>>>`, indexed by query, matrix and column.

The [input opener](../storage-pcs/backend/src/prover.rs) passes every reduced query index to MMCS. In Plonky3 0.8.0, `MerkleTreeMmcs::open_batch_pruned` gathers a complete matrix row for each supplied index and prunes authentication siblings afterward. Duplicate indices retain duplicate value rows. The hiding MMCS splits every salted row into its full data prefix and salt suffix. It does not reduce the number of queried data columns. Pruned authentication paths therefore do not compress this value collection.

The [actual codec](../proof-transport/src/codec.rs) uses the original typed serializer through `serde_json::to_writer`. BabyBear's retained `MontyField31` serializer uses an unsigned integer for human readable formats. The JSON serializer writes decimal digits and commas between successive array elements. Its canonical comparison does not replace data rows with references or a compressed representation. These properties also hold when the numerical value is zero.

## Necessary byte bound

Conditionally retain the complete [overlay dimensions](README.md), four random columns and 64 queries. Let

$$W_p=42178+4=42182,\qquad q=64,\qquad N=qW_p=2699648.$$

The main query rows alone require at least one digit per base field and one comma between consecutive fields in each row. Omitting even array brackets and every other proof object gives the conservative bound

$$B_{\rm main}\ \ge\ qW_p+q(W_p-1)=q(2W_p-1)=5399232\ \text{bytes}.$$

This is a lower bound on the retained canonical JSON representation, independent of field values. It is not an actual encoded length or an entropy bound for arbitrary encodings. Salts, commitments, random and ordinary claims, FRI siblings, authentication paths, framing and public values increase the complete representation.

The [lexical preflight](../proof-transport/src/transport.rs) enforces a 2,097,152 byte payload cap. The [reader](../frame-reader/src/reader.rs) admits that same payload limit before reservation. Their limit already falls below the lower bound. Two further necessary lexical conditions also fail for this conditional representation: a main row has 42,182 entries against the 16,384 item limit, and its 2,699,648 numerical tokens alone exceed the 200,000 token limit. Byte refusal occurs first for an oversized supplied slice. These are separate source conditions rather than three observed errors from a full proof.

The saved 10,798,592 main query field bytes describe four byte field contents. They are not the JSON lower bound, measured serialized size or simultaneous process memory. A binary serializer, row deduplication or compression would require a different reviewed encoding and matching verifier boundary. None is implemented or selected here.

## Architectural decision

The complete overlay is inadmissible under the current source classes and transport architecture. Streaming source construction and bounded metadata do not resolve retained LDE contents or authenticated full-width query transport. The two MiB payload is an enforced limit in these small codec and reader implementations. `ResourcePlan`'s separate declared proof cap does not establish a generic full relation parser.

The existing decoder additionally fixes the small proof's degree, row widths, matrix counts, claim shapes and FRI profile. A full overlay serializer would not turn it into a full overlay verifier. No wide allocation, serialization attempt, prover invocation or full decoder refusal was executed for this review.

A viable successor must reduce the actual authenticated representation or constrained relation while preserving verifier compatibility and complete security obligations. Its review must account together for height, width, public values, degree, padding and holds, raw and retained source contents, salts, trees, query and claim ownership, peak memory and accepted transport. Raising a limit or weakening the query profile does not supply that construction. Replacing private authorization, omitting columns or accepting independent component proofs supplies no valid payment relation.

Until such a construction is selected, full signature proving and dependent payment acceptance remain closed. Independent work can advance the [unified private transition](../../docs/private-transactions.md), atomic state context and confidential stake specifications in the [delivery sequence](../../docs/delivery-roadmap.md). Ledger or network activation still requires the complete privacy and consensus gates. Safe, fast payment locks and Aegis retain their later boundaries.

## Evidence and remaining security obligations

This increment changes source documentation and identity records only. No model, compiler, symbolic collector, native witness, field operation, RNG, MMCS, challenger, prover, verifier or old test was executed. Source identity and local documentation checks do not validate a cryptographic theorem or produce a security score.

The [instance record](instance-security.md) retains the distinct normalized quotient, batching, joint observation and domain admission evidence. Hash and salt compilation, claim dependent challenges, FRI views, repeated and concurrent observations, knowledge and quantum applicability remain unresolved composition obligations. A future construction must keep the same hidden witness through membership, input commitment, owner authorization, stable nullifier, conservation, encrypted delivery and atomic ledger consumption. Payments remain private by default.
