# Contributing

Changes should be small enough to review against a documented invariant or interface. Describe the resulting behavior and the evidence used to validate it.

## Code and validation

- Use integer arithmetic for consensus amounts and limits.
- Reject malformed external input with explicit errors.
- Document units, state preconditions, rounding, overflow behavior, and caller responsibilities.
- Add tests for meaningful boundaries, conservation properties, invalid states, and regression cases.
- Keep reference implementations independent enough to detect shared implementation mistakes.
- Run formatting, workspace tests, and lint checks before submitting changes.

Do not introduce a placeholder proof, signature, randomness source, or checkpoint rule that appears to provide production security. Experimental components must identify their actual guarantees and evaluation scope.

## Documentation and research

Write directly about Kova's architecture, implementation, and results. Record definitions, assumptions, equations, parameter values, references, and open questions. Include source data and a reproducible generation command for each research figure.

Comments explain non-obvious reasoning and invariants. Avoid decorative symbols, conversational history, and descriptions that merely repeat a statement of code.

Commit subjects describe the actual change using a concise imperative sentence. Commit bodies include motivation, validation, and compatibility effects when those details help review.

## Dependencies and source attribution

Record the source, version, license, security assumptions, and review scope of an incorporated dependency. Preserve upstream notices. Adding a library is not evidence that its composition with the protocol has been reviewed.

Project distribution licensing remains an explicit release decision. The initial Rust core is dependency-free; later third-party integration requires an inventory.
