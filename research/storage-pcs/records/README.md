# Versioned validation records

[validation-v1.json](validation-v1.json) is retained byte identical from revision [aa9b8061f23e804a30ba4fc43587099e2cd8bb61](https://github.com/th0rigin/Kova/commit/aa9b8061f23e804a30ba4fc43587099e2cd8bb61). Its source identities and measurements describe version 0.1.0, which constructed a full dense LDE before moving it to storage. Its SHA256 is be71bd7da97590fe759f3664e813267e34704286f660249b438b2a9e3f58a09d.

That earlier execution corrected a one MiB field file allowance after an attempt stopped before proof completion. Eight quotient chunks alone occupy one MiB. The complete ten file total is 1277952 bytes, under the two MiB allowance. No memory limit was exceeded.

[validation-v2.json](validation-v2.json) is retained byte identical from revision [85a42294119f46c55113ee43727b915d173b5d75](https://github.com/th0rigin/Kova/commit/85a42294119f46c55113ee43727b915d173b5d75). It describes version 0.2.0 with column construction for ordinary main and separate randomization commitments. Its SHA256 is 22875efeaf454fb2918d2e16bcb0dbbc5bdb3cb24dc66750917ed5188cade173.

[validation-v3.json](validation-v3.json) is retained byte identical from revision [ae5d9cf1a2a5ece9ee5136bde74cf01bd2d78e82](https://github.com/th0rigin/Kova/commit/ae5d9cf1a2a5ece9ee5136bde74cf01bd2d78e82). It describes version 0.3.0 with coupled quotient column construction. Its SHA256 is 2424a76deb507e785963abf6f5e899fb671781a246e9446521977d56e2ba9cbe.

The current [validation.json](../validation.json) describes version 0.4.0, which also prepares main randomized rows directly in storage. All versions retain the same finite quartic relation and proof profile. Historical source hashes do not describe later source revisions.
