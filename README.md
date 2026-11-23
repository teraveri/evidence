# Evidence

Evidence is a Rust workspace for the evidence contract shared by the [GENXT Confido](https://github.com/genxnetwork/confido) verifier and the [JAN Attestor](https://github.com/jandigitrust/attestor) collector.

The current scope is the `azure-snp-vtpm-ima/1` profile: AMD SEV-SNP reports, Azure HCL, vTPM quotes, and IMA measurements.

| Crate | Responsibility |
| --- | --- |
| [`evidence-protocol`](protocol/README.md) | Wire-v1 request and response types, profile/version envelope, and quote-binding transcript. |
| [`evidence-core`](core/README.md) | Bounded SNP/HCL/vTPM parsing and collected-snapshot consistency checks. |

`evidence-core` depends on `evidence-protocol`; consumers should pin compatible versions of both crates. A collector can check a snapshot before sending it. The verifier appraises received evidence against its own trust anchors, policy, and reference values. Device collection, HTTP transport, reference appraisal, and application admission belong to the consuming projects.

Use the pinned toolchain in [`rust-toolchain.toml`](rust-toolchain.toml). Run `cargo test --locked --workspace` from this directory. Licensing and third-party attribution are in [`LICENSE`](LICENSE) and [`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
