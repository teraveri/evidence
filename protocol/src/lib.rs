//! Stable evidence wire v1. No device, clock, randomness or transport access.
use ring::digest::{digest, SHA256};
use serde::{Deserialize, Serialize};
use std::fmt;
pub const PROFILE: &str = "azure-snp-vtpm-ima/1";
pub const WIRE_VERSION: u32 = 1;

/// Versioned fields at the top of every evidence response.
#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct EvidenceEnvelope {
    pub profile: String,
    #[serde(rename = "wireVersion")]
    pub wire_version: u32,
}

impl EvidenceEnvelope {
    pub fn current() -> Self {
        Self {
            profile: PROFILE.into(),
            wire_version: WIRE_VERSION,
        }
    }

    pub fn is_supported(&self) -> bool {
        self.profile == PROFILE && self.wire_version == WIRE_VERSION
    }
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct AttestationRequest {
    pub nonce: Base64,
}

#[derive(Deserialize, Serialize, Debug)]
pub struct ModuleLoadOrder {
    pub kernel: String,
    pub order: Vec<String>,
}

#[derive(Deserialize, Serialize, Debug, Clone, PartialEq, Eq)]
pub struct IMALogEntry {
    pub name: String,
    #[serde(rename = "PCR")]
    pub pcr: u32,
    pub template_hash: String,
    pub ima_template: String,
    pub filedata_alg: String,
    pub filedata_hash: String,
    pub filename_hint: String,
}

#[derive(Deserialize, Serialize)]
pub struct AttestationResponse {
    #[serde(flatten)]
    pub envelope: EvidenceEnvelope,
    pub evidence: Evidence,
    pub certificate: Vec<u8>, // can't use X509 as it non-serializable
}

impl AttestationResponse {
    pub fn new(evidence: Evidence, certificate: Vec<u8>) -> Self {
        Self {
            envelope: EvidenceEnvelope::current(),
            evidence,
            certificate,
        }
    }
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum Algorithm {
    Sha1 = 0,
    Sha256 = 1,
}

impl Algorithm {
    pub fn length(&self) -> usize {
        match self {
            Self::Sha1 => 20,
            Self::Sha256 => 32,
        }
    }

    pub fn to_str(&self) -> &'static str {
        match self {
            Self::Sha1 => "sha1",
            Self::Sha256 => "sha256",
        }
    }

    pub fn digest(&self) -> &'static ring::digest::Algorithm {
        match self {
            Self::Sha1 => &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
            Self::Sha256 => &ring::digest::SHA256,
        }
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct PcrBank {
    pub algo: Algorithm,
    pub pcr_values: Vec<Vec<u8>>,
}

impl PcrBank {
    pub fn get(&self, index: usize) -> Option<&Vec<u8>> {
        self.pcr_values.get(index)
    }
}

impl fmt::Debug for PcrBank {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PcrBank")
            .field("algo", &self.algo)
            .field(
                "pcr_values",
                &self.pcr_values.iter().map(hex::encode).collect::<Vec<_>>(),
            )
            .finish()
    }
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Quote {
    pub signature: Vec<u8>,
    pub message: Vec<u8>,
    pub pcr_banks: Vec<PcrBank>,
}

impl fmt::Debug for Quote {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Quote")
            .field("signature", &hex::encode(&self.signature))
            .field("message", &hex::encode(&self.message))
            .field("pcr_banks", &self.pcr_banks)
            .finish()
    }
}

impl Quote {
    pub fn bank_count(&self) -> usize {
        self.pcr_banks.len()
    }

    pub fn get_pcr_bank(&self, algo: Algorithm) -> Option<&PcrBank> {
        self.pcr_banks.iter().find(|bank| bank.algo == algo)
    }

    pub fn message(&self) -> Vec<u8> {
        self.message.clone()
    }
}
#[derive(Serialize, Deserialize)]
pub struct Evidence {
    pub report: Vec<u8>,
    pub quote: Quote,
    pub cgpu_attestation: serde_json::Value,
    pub module_load_order: ModuleLoadOrder,
    pub ima_measurements: Vec<IMALogEntry>,
}

impl fmt::Debug for Evidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let report_hex = hex::encode(&self.report);

        f.debug_struct("Evidence")
            .field("report", &report_hex)
            .field("quote", &self.quote)
            .finish()
    }
}

impl Evidence {
    pub fn new(
        report: Vec<u8>,
        quote: Quote,
        cgpu_attestation: serde_json::Value,
        module_load_order: ModuleLoadOrder,
        ima_measurements: Vec<IMALogEntry>,
    ) -> Self {
        Evidence {
            report,
            quote,
            cgpu_attestation,
            module_load_order,
            ima_measurements,
        }
    }

    pub fn ima_binding(measurements: &[IMALogEntry]) -> Result<Vec<u8>, serde_json::Error> {
        let serialized = serde_json::to_vec(measurements)?;
        Ok(ring::digest::digest(&ring::digest::SHA256, &serialized)
            .as_ref()
            .to_vec())
    }
}
#[derive(Deserialize, Serialize)]
pub struct Base64(String);

impl Base64 {
    pub fn from_base64(base64: String) -> Self {
        Base64(base64)
    }

    pub fn to_base64(&self) -> &String {
        &self.0
    }

    pub fn as_bytes(&self) -> Result<Vec<u8>, base64::DecodeError> {
        base64::decode(&self.0)
    }
}

#[derive(Clone)]
pub struct Nonce {
    nonce: Vec<u8>,
}

impl Nonce {
    pub fn read(base64: &Base64) -> Result<Self, &'static str> {
        match base64.as_bytes() {
            Ok(decoded) => {
                if decoded.len() != 32 {
                    Err("Nonce is not 32 bytes")
                } else {
                    Ok(Nonce { nonce: decoded })
                }
            }
            Err(_) => Err("Failed to decode nonce"),
        }
    }

    pub fn extend_bytes(&mut self, bytes: &[u8]) -> &Nonce {
        self.nonce.extend_from_slice(bytes);
        self
    }

    pub fn extend_binding(&mut self, certificate: &[u8], binding: &[u8]) -> &Nonce {
        let certificate_bytes = certificate;
        let mut data =
            Vec::with_capacity(self.nonce.len() + certificate_bytes.len() + binding.len());
        data.extend_from_slice(&self.nonce);
        data.extend_from_slice(certificate_bytes);
        data.extend_from_slice(binding);
        self.nonce = digest(&SHA256, &data).as_ref().to_vec();
        self
    }

    pub fn as_bytes(&self) -> &Vec<u8> {
        &self.nonce
    }

    pub fn as_string(&self) -> String {
        base64::encode(&self.nonce)
    }
}

impl From<Nonce> for Base64 {
    fn from(nonce: Nonce) -> Self {
        let base64_encoded = base64::encode(&nonce.nonce);
        Base64::from_base64(base64_encoded)
    }
}

// ring depends on getrandom, but verification never needs entropy. A fail-closed
// backend keeps the WASM module independent of browser/OS randomness imports.
#[cfg(target_arch = "wasm32")]
fn no_randomness(_: &mut [u8]) -> Result<(), getrandom::Error> {
    Err(getrandom::Error::UNSUPPORTED)
}
#[cfg(target_arch = "wasm32")]
getrandom::register_custom_getrandom!(no_randomness);

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::{json, Value};

    fn synthetic_response() -> AttestationResponse {
        AttestationResponse::new(
            Evidence::new(
                vec![1, 2],
                Quote {
                    signature: vec![],
                    message: vec![],
                    pcr_banks: vec![],
                },
                Value::Null,
                ModuleLoadOrder {
                    kernel: String::new(),
                    order: vec![],
                },
                vec![],
            ),
            vec![3],
        )
    }

    #[test]
    fn response_uses_flat_versioned_wire_envelope() {
        let value = serde_json::to_value(synthetic_response()).unwrap();
        assert_eq!(
            value,
            json!({
                "profile": PROFILE,
                "wireVersion": WIRE_VERSION,
                "evidence": {
                    "report": [1, 2],
                    "quote": {"signature": [], "message": [], "pcr_banks": []},
                    "cgpu_attestation": null,
                    "module_load_order": {"kernel": "", "order": []},
                    "ima_measurements": []
                },
                "certificate": [3]
            })
        );
        let header: EvidenceEnvelope = serde_json::from_value(value.clone()).unwrap();
        assert!(header.is_supported());
        let decoded: AttestationResponse = serde_json::from_value(value).unwrap();
        assert!(decoded.envelope.is_supported());
        assert_eq!(decoded.evidence.report, [1, 2]);
        assert_eq!(decoded.certificate, [3]);
    }

    #[test]
    fn response_requires_version_and_rejects_unsupported_header() {
        let mut value = serde_json::to_value(synthetic_response()).unwrap();
        value.as_object_mut().unwrap().remove("wireVersion");
        assert!(serde_json::from_value::<EvidenceEnvelope>(value.clone()).is_err());
        assert!(serde_json::from_value::<AttestationResponse>(value).is_err());

        let mut value = serde_json::to_value(synthetic_response()).unwrap();
        value["wireVersion"] = json!(WIRE_VERSION + 1);
        let header: EvidenceEnvelope = serde_json::from_value(value).unwrap();
        assert!(!header.is_supported());
    }
}
