# Attestation evidence core

This Rust crate holds the bounded SNP/HCL and vTPM quote parsers used by the
native collector and the portable Confido verifier. `verify_snapshot` checks
the quote signature, nonce/certificate/IMA binding, and quoted PCR values
before a collector returns a snapshot. It does not check AMD endorsement chains,
platform policy, reference values, or application admission. The receiving
verifier performs those checks independently.

| File | Role |
| --- | --- |
| [`src/lib.rs`](src/lib.rs) | Exposes the parser module and snapshot check. |
| [`src/formats.rs`](src/formats.rs) | Bounded SNP/HCL and quote decoding, signature and binding checks. |
| [`src/formats/tests.rs`](src/formats/tests.rs) | Signed synthetic quote and rejection tests. |
| [`tests/fixtures/binding-v1.json`](tests/fixtures/binding-v1.json) | Frozen wire-v1 binding vector. |
| [`Cargo.toml`](Cargo.toml), [`../Cargo.lock`](../Cargo.lock) | Package dependencies and shared reproducible test build. |

The wire structures and transcript construction remain in
[`protocol/`](../protocol/README.md). The two crates form one shared component;
Confido and Attestor must pin compatible releases of both crates and the
wire/binding contract.

Run `cargo test --locked --workspace` from the evidence workspace root. The
normal dependency graph must stay free of TPM, HTTP, and
application transport dependencies. The parsers retain attribution to the
pinned Microsoft azure-cvm-tooling source; see
[`THIRD_PARTY_NOTICES.md`](../THIRD_PARTY_NOTICES.md).
