# Dated advisory source evidence

The [27 October 2026 request](2026-10-27-request.json) lists all 92 exact registry package versions in the recorded build resolution. The [raw response](2026-10-27-response.json) preserves the OSV batch result without reformatting. The dependency inventory checks both byte hashes, query coverage and matching identifiers offline. Inventory generation never makes a network request.

The batch contains one match for `paste 1.0.15`, [RUSTSEC-2024-0436](https://rustsec.org/advisories/RUSTSEC-2024-0436.html). The source classifies it as informational unmaintained and records no patched version. The RustSec page identifies its advisory data as CC0-1.0. This dated response is separate from upstream code inspection, future advisory changes and an implementation security audit.

The retained request can be submitted to the [OSV query batch API](https://google.github.io/osv.dev/post-v1-querybatch/) for a new response. A later response needs a new dated record and source review. Historical bytes and earlier lock records must retain their original dates and meaning.
