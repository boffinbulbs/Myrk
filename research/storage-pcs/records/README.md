# Versioned validation records

[validation-v1.json](validation-v1.json) is retained byte identical from revision [aa9b8061f23e804a30ba4fc43587099e2cd8bb61](https://github.com/th0rigin/Kova/commit/aa9b8061f23e804a30ba4fc43587099e2cd8bb61). Its source identities and measurements describe version 0.1.0, which constructed a full dense LDE before moving it to storage. Its SHA256 is be71bd7da97590fe759f3664e813267e34704286f660249b438b2a9e3f58a09d.

That earlier execution corrected a one MiB field file allowance after an attempt stopped before proof completion. Eight quotient chunks alone occupy one MiB. The complete ten file total is 1277952 bytes, under the two MiB allowance. No memory limit was exceeded.

The current [validation.json](../validation.json) describes version 0.2.0 with column construction for ordinary main and separate randomization commitments. Both versions retain the same finite quartic relation and proof profile. Historical source hashes do not describe later source revisions.
