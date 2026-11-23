fn verify(
    q: &evidence_protocol::Quote,
    key: &openssl::pkey::PKey<openssl::pkey::Public>,
    nonce: &[u8],
) -> Result<(), String> {
    let rsa = key.rsa().unwrap();
    super::quote(q, &rsa.n().to_vec(), &rsa.e().to_vec(), nonce)
}
use evidence_protocol::Evidence;
use evidence_protocol::IMALogEntry;
use evidence_protocol::Quote;
use evidence_protocol::{Base64, Nonce};
use openssl::asn1::Asn1Time;
use openssl::hash::MessageDigest;
use openssl::pkey::{PKey, Private, Public};
use openssl::rsa::Rsa;
use openssl::sign::Signer;
use openssl::x509::{X509NameBuilder, X509};

fn certificate(key: &PKey<Private>, name: &str) -> X509 {
    let mut subject = X509NameBuilder::new().unwrap();
    subject.append_entry_by_text("CN", name).unwrap();
    let subject = subject.build();
    let mut builder = X509::builder().unwrap();
    builder.set_version(2).unwrap();
    builder.set_subject_name(&subject).unwrap();
    builder.set_issuer_name(&subject).unwrap();
    builder.set_pubkey(key).unwrap();
    builder
        .set_not_before(&Asn1Time::days_from_now(0).unwrap())
        .unwrap();
    builder
        .set_not_after(&Asn1Time::days_from_now(1).unwrap())
        .unwrap();
    builder.sign(key, MessageDigest::sha256()).unwrap();
    builder.build()
}

fn measurements() -> Vec<IMALogEntry> {
    ["boot_aggregate", "module.ko"]
        .iter()
        .map(|name| IMALogEntry {
            name: name.to_string(),
            pcr: 10,
            template_hash: "01".repeat(20),
            ima_template: "ima-ng".into(),
            filedata_alg: "sha256".into(),
            filedata_hash: "02".repeat(32),
            filename_hint: name.to_string(),
        })
        .collect()
}

fn bound_nonce(challenge: &Nonce, cert: &X509, entries: &[IMALogEntry]) -> Nonce {
    let mut nonce = challenge.clone();
    nonce.extend_binding(
        &cert.to_der().unwrap(),
        &Evidence::ima_binding(entries).unwrap(),
    );
    nonce
}

// Construct and sign a TPMS_ATTEST quote with PCRs 0..=10. This exercises the
// actual quote verifier without requiring a TPM or AMD certificate service.
fn signed_quote(nonce: &Nonce, key: &PKey<Private>) -> Quote {
    signed_quote_with_selection(nonce, key, [0xff, 0x07, 0])
}

fn signed_quote_with_selection(nonce: &Nonce, key: &PKey<Private>, slots: [u8; 3]) -> Quote {
    let mut message = vec![];
    message.extend_from_slice(&0xff544347u32.to_be_bytes()); // TPM_GENERATED_VALUE
    message.extend_from_slice(&0x8018u16.to_be_bytes()); // TPM_ST_ATTEST_QUOTE
    message.extend_from_slice(&0u16.to_be_bytes()); // qualified signer
    message.extend_from_slice(&(nonce.as_bytes().len() as u16).to_be_bytes());
    message.extend_from_slice(nonce.as_bytes());
    message.extend_from_slice(&[0; 16]); // clock, reset count, restart count
    message.push(1); // safe clock
    message.extend_from_slice(&[0; 8]); // firmware version
    message.extend_from_slice(&1u32.to_be_bytes()); // one PCR selection
    message.extend_from_slice(&0x000bu16.to_be_bytes()); // TPM_ALG_SHA256
    message.push(3);
    message.extend_from_slice(&slots);
    message.extend_from_slice(&32u16.to_be_bytes());
    message.extend_from_slice(&openssl::sha::sha256(&[0; 32 * 11]));
    let mut signer = Signer::new(MessageDigest::sha256(), key).unwrap();
    signer.update(&message).unwrap();
    serde_json::from_value(serde_json::json!({
        "message": message, "signature": signer.sign_to_vec().unwrap(),
        "pcr_banks": [{"algo": "Sha256", "pcr_values": vec![vec![0u8; 32]; 11]}]
    }))
    .unwrap()
}

#[test]
fn quote_accepts_original_binding_and_rejects_changed_challenge_certificate_or_log() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let public_key: PKey<Public> =
        PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let cert = certificate(&key, "original");
    let challenge = Nonce::read(&Base64::from_base64(base64::encode([7; 32]))).unwrap();
    let entries = measurements();
    let nonce = bound_nonce(&challenge, &cert, &entries);
    assert_eq!(nonce.as_bytes().len(), 32);
    assert_ne!(nonce.as_bytes(), challenge.as_bytes());
    let quote = signed_quote(&nonce, &key);
    verify(&quote, &public_key, nonce.as_bytes()).unwrap();
    let unrelated = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let unrelated = PKey::public_key_from_der(&unrelated.public_key_to_der().unwrap()).unwrap();
    assert!(verify(&quote, &unrelated, nonce.as_bytes()).is_err());

    let different_challenge = Nonce::read(&Base64::from_base64(base64::encode([8; 32]))).unwrap();
    let different_certificate = certificate(&key, "substituted");
    for changed in [
        bound_nonce(&different_challenge, &cert, &entries),
        bound_nonce(&challenge, &different_certificate, &entries),
    ] {
        assert!(verify(&quote, &public_key, changed.as_bytes()).is_err());
    }

    let mut changed_logs = vec![];
    let mut altered = entries.clone();
    altered[1].filedata_hash = "03".repeat(32);
    changed_logs.push(altered);
    let mut reordered = entries.clone();
    reordered.reverse();
    changed_logs.push(reordered);
    changed_logs.push(entries[..1].to_vec());
    let mut duplicated = entries.clone();
    duplicated.push(entries[1].clone());
    changed_logs.push(duplicated);
    for changed in changed_logs {
        let changed_nonce = bound_nonce(&challenge, &cert, &changed);
        assert!(verify(&quote, &public_key, changed_nonce.as_bytes()).is_err());
    }

    let mut changed_pcrs = serde_json::to_value(&quote).unwrap();
    changed_pcrs["pcr_banks"][0]["pcr_values"][10][0] = serde_json::json!(1);
    let changed_quote: Quote = serde_json::from_value(changed_pcrs).unwrap();
    assert!(verify(&changed_quote, &public_key, nonce.as_bytes()).is_err());
}

#[test]
fn rejects_invalid_nonce_encoding_and_lengths() {
    for encoded in [
        "invalid!".to_string(),
        base64::encode([0; 31]),
        base64::encode([0; 33]),
    ] {
        assert!(Nonce::read(&Base64::from_base64(encoded)).is_err());
    }
}

#[test]
fn rejects_unsigned_bank_labels_lengths_and_shifted_pcr_selection() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let public_key = PKey::public_key_from_der(&key.public_key_to_der().unwrap()).unwrap();
    let nonce = Nonce::read(&Base64::from_base64(base64::encode([9; 32]))).unwrap();
    let quote = signed_quote(&nonce, &key);

    let mut relabeled = serde_json::to_value(&quote).unwrap();
    relabeled["pcr_banks"][0]["algo"] = serde_json::json!("Sha1");
    let relabeled: Quote = serde_json::from_value(relabeled).unwrap();
    assert!(verify(&relabeled, &public_key, nonce.as_bytes()).is_err());

    let mut regrouped = serde_json::to_value(&quote).unwrap();
    regrouped["pcr_banks"][0]["pcr_values"][0] = serde_json::json!(vec![0; 31]);
    regrouped["pcr_banks"][0]["pcr_values"][1] = serde_json::json!(vec![0; 33]);
    let regrouped: Quote = serde_json::from_value(regrouped).unwrap();
    assert!(verify(&regrouped, &public_key, nonce.as_bytes()).is_err());

    let mut extra = serde_json::to_value(&quote).unwrap();
    extra["pcr_banks"]
        .as_array_mut()
        .unwrap()
        .push(serde_json::json!({"algo":"Sha1","pcr_values":[]}));
    let extra: Quote = serde_json::from_value(extra).unwrap();
    assert!(verify(&extra, &public_key, nonce.as_bytes()).is_err());

    let shifted = signed_quote_with_selection(&nonce, &key, [0xfe, 0x0f, 0]);
    assert!(verify(&shifted, &public_key, nonce.as_bytes()).is_err());
}

#[test]
fn malformed_hcl_never_panics() {
    for n in [0, 1, 31, 32, 1184, 1235, 1236, 65537] {
        assert!(super::hcl(&vec![0; n]).is_err());
    }
    let mut b = vec![0; 1236];
    b[1224..1228].copy_from_slice(&2u32.to_le_bytes());
    b[1228..1232].copy_from_slice(&1u32.to_le_bytes());
    b[1232..1236].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(super::hcl(&b).is_err());
}

#[test]
fn snp_versions_preserve_fields_and_reject_unknown_layouts() {
    let mut b = vec![0; 1236];
    b[1224..1228].copy_from_slice(&2u32.to_le_bytes());
    b[1228..1232].copy_from_slice(&1u32.to_le_bytes());
    b[32 + 52..32 + 56].copy_from_slice(&1u32.to_le_bytes());
    for version in [2u32, 3, 5] {
        b[32..36].copy_from_slice(&version.to_le_bytes());
        b[32 + 384..32 + 392].copy_from_slice(&[4, 0, 0, 0, 0, 0, 24, 219]);
        b[32 + 480..32 + 488].copy_from_slice(&[4, 0, 0, 0, 0, 0, 24, 219]);
        b[32 + 144..32 + 192].fill(0x11);
        b[32 + 416..32 + 480].fill(0x22);
        b[32 + 80..32 + 144].fill(0x33);
        b[32 + 392] = 0x19;
        b[32 + 393] = 0x01;
        let snp = super::snp(&b).unwrap();
        assert_eq!(snp.tcb, [4, 0, 24, 219]);
        assert_eq!(snp.committed, snp.tcb);
        assert_eq!(snp.measurement, &[0x11; 48]);
        assert_eq!(snp.chip, &[0x22; 64]);
        assert_eq!(snp.report_data, &[0x33; 64]);
        assert_eq!(
            snp.product_hint().unwrap(),
            if version == 2 { None } else { Some("Milan") }
        );
    }
    for version in [0u32, 1, 4, 6, u32::MAX] {
        b[32..36].copy_from_slice(&version.to_le_bytes());
        assert_eq!(
            super::snp(&b).unwrap_err(),
            format!("Unsupported SNP report version {version}")
        );
    }
}

#[test]
fn processor_product_selection_is_bounded() {
    let mut b = vec![0; 1236];
    b[1224..1228].copy_from_slice(&2u32.to_le_bytes());
    b[1228..1232].copy_from_slice(&1u32.to_le_bytes());
    b[32 + 52..32 + 56].copy_from_slice(&1u32.to_le_bytes());
    for version in [3u32, 5] {
        b[32..36].copy_from_slice(&version.to_le_bytes());
        for (family, model, expected) in [(0x19, 0x01, Some("Milan")), (0x19, 0x11, Some("Genoa"))]
        {
            b[32 + 392] = family;
            b[32 + 393] = model;
            assert_eq!(super::snp(&b).unwrap().product_hint().unwrap(), expected);
        }
        for (family, model) in [(0x19, 0x20), (0x19, 0xa0), (0x1a, 0x01), (0, 0)] {
            b[32 + 392] = family;
            b[32 + 393] = model;
            assert!(super::snp(&b).unwrap().product_hint().is_err());
        }
    }
    // No CPUID in v2: chain validation must establish the enrolled product.
    b[32..36].copy_from_slice(&2u32.to_le_bytes());
    assert_eq!(super::snp(&b).unwrap().product_hint().unwrap(), None);
}
#[test]
fn binding_v1_serialization_matches_existing_vector() {
    let v: serde_json::Value =
        serde_json::from_str(include_str!("../../tests/fixtures/binding-v1.json")).unwrap();
    let entries: Vec<IMALogEntry> = serde_json::from_value(v["ima_measurements"].clone()).unwrap();
    assert_eq!(
        serde_json::to_string(&entries).unwrap(),
        v["serialized_ima_utf8"].as_str().unwrap()
    );
    let cert = base64::decode(v["certificate_der_base64"].as_str().unwrap()).unwrap();
    let binding = Evidence::ima_binding(&entries).unwrap();
    let mut nonce = Nonce::read(&Base64::from_base64(
        v["nonce_base64"].as_str().unwrap().into(),
    ))
    .unwrap();
    nonce.extend_binding(&cert, &binding);
    assert_eq!(
        hex::encode(nonce.as_bytes()),
        v["quote_extra_data_sha256"].as_str().unwrap()
    );
}

#[test]
fn quote_stage_dependencies_keep_signature_binding_and_pcr_separate() {
    let key = PKey::from_rsa(Rsa::generate(2048).unwrap()).unwrap();
    let rsa = key.rsa().unwrap();
    let nonce = Nonce::read(&Base64::from_base64(base64::encode([9; 32]))).unwrap();
    let q = signed_quote(&nonce, &key);
    let signed = super::quote_signature(&q, &rsa.n().to_vec(), &rsa.e().to_vec()).unwrap();
    super::verify_quote_binding(&signed, nonce.as_bytes()).unwrap();
    super::quoted_pcrs(&signed, &q).unwrap();
    assert!(super::verify_quote_binding(&signed, &[0; 32]).is_err());
    let mut changed: Quote = serde_json::from_value(serde_json::to_value(&q).unwrap()).unwrap();
    changed.pcr_banks[0].pcr_values[10][0] ^= 1;
    let signed = super::quote_signature(&changed, &rsa.n().to_vec(), &rsa.e().to_vec()).unwrap();
    super::verify_quote_binding(&signed, nonce.as_bytes()).unwrap();
    assert!(super::quoted_pcrs(&signed, &changed).is_err());
    changed.signature[0] ^= 1;
    assert!(super::quote_signature(&changed, &rsa.n().to_vec(), &rsa.e().to_vec()).is_err());
}
