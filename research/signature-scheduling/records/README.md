# Earlier scheduling measurements

The version one [provenance](provenance-v1.json), [validation](validation-v1.json) and [cost calculation](costs-v1.json) are retained byte identical from [87c50b570c380cd8d9f0297b9b1dbea775d1cba1](https://github.com/th0rigin/Kova/commit/87c50b570c380cd8d9f0297b9b1dbea775d1cba1).

That variant replaced the one hot clock with two indicator banks. Its complete symbolic relation measured width 47049, 181203 constraints and degree six. It lowered field contents while increasing quotient work and field file count under the conditional profile.

The current variant adds nine explicitly bound activity fields. Version one source identities refer to that earlier commit, not to current files. No historical native trace or backend proof exists for either scheduling record.
