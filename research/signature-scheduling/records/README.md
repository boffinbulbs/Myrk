# Earlier scheduling measurements

The version one [provenance](provenance-v1.json), [validation](validation-v1.json) and [cost calculation](costs-v1.json) are retained byte identical from [87c50b570c380cd8d9f0297b9b1dbea775d1cba1](https://github.com/th0rigin/Kova/commit/87c50b570c380cd8d9f0297b9b1dbea775d1cba1).

That variant replaced the one hot clock with two indicator banks. Its complete symbolic relation measured width 47049, 181203 constraints and degree six. It lowered field contents while increasing quotient work and field file count under the conditional profile.

Version two [provenance](provenance-v2.json), [validation](validation-v2.json) and [costs](costs-v2.json) are retained byte identical from [c855cd3722834fe4bb0fa9bfefe8ca60901a6fdd](https://github.com/th0rigin/Kova/commit/c855cd3722834fe4bb0fa9bfefe8ca60901a6fdd). It adds nine explicitly bound activity fields and restores degree four. Version one and two source identities refer to their earlier commits, not to current files. Neither historical record has a native trace or backend proof.

Version three [provenance](provenance-v3.json), [validation](validation-v3.json) and [costs](costs-v3.json) are retained byte identical from [e549c6077a4904689b3b54ecb859f0192f4b2b31](https://github.com/th0rigin/Kova/commit/e549c6077a4904689b3b54ecb859f0192f4b2b31). It records the separately guarded A0 native baseline and activity mutations. The current record covers the remaining nine tuples, preserving the version two equations and the prior A0 result. Native tuple coverage is cumulative across the two records. Neither execution uses a proof backend.
