# Evidence wire protocol

`evidence-protocol` is the shared Rust crate for the native Attestor collector
and the portable Confido verifier.
It keeps their evidence representation and quote-binding calculation aligned.
The crate's package version is **0.2.0**; the supported evidence profile is
`azure-snp-vtpm-ima/1` with wire/binding version **1**. The verifier's JSON
policy, result, and archive schemas use version **2** independently of this
wire version.

| Item | Role |
| --- | --- |
| `AttestationRequest`, `Base64`, `Nonce` | A caller's base64-encoded 32-byte challenge and the collector's nonce handling. |
| `EvidenceEnvelope`, `AttestationResponse`, `Evidence` | Shared versioned response and evidence shapes. The collector serializes the flat `profile`/`wireVersion` envelope; the verifier checks it before appraising evidence. |
| `Quote`, `PcrBank`, `Algorithm` | TPM quote and PCR representations consumed by the collector and verifier. |
| `IMALogEntry`, `ModuleLoadOrder` | IMA entries and their ordering information used during measurement appraisal. |
| `Evidence::ima_binding`, `Nonce::extend_binding` | The wire-v1 transcript calculation shared by both sides. |

For wire v1, the TPM quote's extra data commits to
`SHA256(nonce[32] || certificate_DER || SHA256(serde_json(IMA entries)))`.
The JSON response carries the certificate as an array of PEM-encoded bytes;
the binding uses that certificate's DER bytes. IMA entry serialization,
including field names and order, is part of this transcript. The
[binding-v1 test vector](../core/tests/fixtures/binding-v1.json) and the
[evidence-core format tests](../core/src/formats/tests.rs) guard
compatibility. A changed transcript needs an explicit new wire version and
matching collector/verifier rollout.

The collector currently sets `cgpu_attestation` to `null`; Confido does not
appraise GPU evidence. `module_load_order` is checked during reference
comparison, while the quote transcript directly binds the serialized IMA
entries. The presence of a field in the wire response is not a verified claim.
The [evidence core](../core/README.md) owns bounded parsing and snapshot
consistency checks. Confido owns appraisal and its policy/result schemas. The
application owns HTTPS peer authentication and admission.

The crate performs no device access, HTTP, clock lookup, or challenge
generation. Its WASM configuration rejects randomness requests instead of
importing browser or OS entropy. When the native collector moves to Attestor,
both repositories will need the versioned wire contract and evidence core.
The two crates are versioned together in this workspace so consumers can pin
the same wire and binding contract.
