//! Bounded decoders for the existing Azure SNP/HCL and TPM quote profile.
//! Layouts adapted from the pinned Microsoft azure-cvm-tooling (MIT), see notices.
use evidence_protocol::{Algorithm, Evidence, Quote};
use ring::{digest, signature};
use serde::Deserialize;

pub type Result<T> = std::result::Result<T, String>;
pub fn bytes(b: &[u8], at: usize, n: usize) -> Result<&[u8]> {
    b.get(at..at.checked_add(n).ok_or("Length overflow")?)
        .ok_or_else(|| "Truncated binary structure".into())
}
fn le32(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        bytes(b, at, 4)?.try_into().map_err(|_| "u32")?,
    ))
}
#[derive(Debug)]
pub struct Snp<'a> {
    pub raw: &'a [u8],
    pub version: u32,
    pub vmpl: u32,
    pub policy: u64,
    pub tcb: [u8; 4],
    pub committed: [u8; 4],
    pub measurement: &'a [u8],
    pub chip: &'a [u8],
    pub report_data: &'a [u8],
}
impl Snp<'_> {
    pub fn product_hint(&self) -> Result<Option<&'static str>> {
        // v2 has no CPUID. Its product must be established by the enrolled
        // policy and the authenticated VCEK product extension instead.
        if self.version == 2 {
            return Ok(None);
        }
        let product = match (self.raw[392], self.raw[393]) {
            (0x19, 0x00..=0x0f) => "Milan",
            (0x19, 0x10..=0x1f) => "Genoa",
            (family, model) => {
                return Err(format!(
                    "Unsupported SNP processor family {family:#04x}, model {model:#04x}"
                ))
            }
        };
        Ok(Some(product))
    }
}
pub struct Hcl<'a> {
    pub snp: Snp<'a>,
    pub var_hash: Vec<u8>,
    pub n: Vec<u8>,
    pub e: Vec<u8>,
    pub spki: Vec<u8>,
}
#[derive(Deserialize)]
struct Keys {
    keys: Vec<Key>,
}
#[derive(Deserialize)]
struct Key {
    kid: Option<String>,
    kty: String,
    n: Option<String>,
    e: Option<String>,
}

// DER encoding here only encodes RSA public values; crypto is delegated to ring.
fn der(tag: u8, data: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    if data.len() < 128 {
        out.push(data.len() as u8)
    } else {
        let n = (data.len() as u32).to_be_bytes();
        let p = n.iter().position(|&v| v != 0).unwrap_or(3);
        out.push(0x80 | (4 - p) as u8);
        out.extend_from_slice(&n[p..]);
    }
    out.extend_from_slice(data);
    out
}
fn integer(n: &[u8]) -> Vec<u8> {
    let mut b = n.to_vec();
    if b.first().is_some_and(|v| v & 128 != 0) {
        b.insert(0, 0)
    }
    der(2, &b)
}
pub fn rsa_spki(n: &[u8], e: &[u8]) -> Vec<u8> {
    let rsa = der(0x30, &[integer(n), integer(e)].concat());
    let bits = der(3, &[vec![0], rsa].concat());
    der(
        0x30,
        &[
            vec![
                0x30, 0x0d, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01, 0x05,
                0x00,
            ],
            bits,
        ]
        .concat(),
    )
}
pub fn snp(b: &[u8]) -> Result<Snp<'_>> {
    if !(1236..=65536).contains(&b.len()) {
        return Err("Invalid HCL report size".into());
    }
    if le32(b, 1224)? != 2 || le32(b, 1228)? != 1 {
        return Err("Unsupported HCL report/hash type".into());
    }
    bytes(b, 1236, le32(b, 1232)? as usize)?;
    let s = bytes(b, 32, 1184)?;
    let tcb = |at| -> Result<[u8; 4]> {
        let v = bytes(s, at, 8)?;
        Ok([v[0], v[1], v[6], v[7]])
    };
    if le32(s, 52)? != 1 {
        return Err("Unsupported SNP signature algorithm".into());
    }
    let snp = Snp {
        raw: s,
        version: le32(s, 0)?,
        vmpl: le32(s, 48)?,
        policy: u64::from_le_bytes(bytes(s, 8, 8)?.try_into().map_err(|_| "policy")?),
        tcb: tcb(384)?,
        committed: tcb(480)?,
        measurement: bytes(s, 144, 48)?,
        chip: bytes(s, 416, 64)?,
        report_data: bytes(s, 80, 64)?,
    };
    // AMD ABI 1.58, table 23: v5 retains these SNP field offsets and the
    // 0x000..0x29f signed region. Its mitigation vectors are authenticated
    // by the signature but are not appraised by this bounded profile.
    if ![2, 3, 5].contains(&snp.version) {
        return Err(format!("Unsupported SNP report version {}", snp.version));
    }
    Ok(snp)
}

pub fn hcl(b: &[u8]) -> Result<Hcl<'_>> {
    let snp = snp(b)?;
    let var = bytes(b, 1236, le32(b, 1232)? as usize)?;
    let keys: Keys = serde_json::from_slice(var).map_err(|e| e.to_string())?;
    if keys.keys.len() > 16 {
        return Err("Too many HCL keys".into());
    }
    let keys: Vec<_> = keys
        .keys
        .into_iter()
        .filter(|k| k.kid.as_deref() == Some("HCLAkPub"))
        .collect();
    if keys.len() != 1 || keys[0].kty != "RSA" {
        return Err("Missing, duplicate or unsupported HCL AK".into());
    }
    let decode = |v: &Option<String>| -> Result<Vec<u8>> {
        base64::decode_config(
            v.as_ref().ok_or("Missing RSA component")?,
            base64::URL_SAFE_NO_PAD,
        )
        .map_err(|e| e.to_string())
    };
    let n = decode(&keys[0].n)?;
    let e = decode(&keys[0].e)?;
    if !(256..=1024).contains(&n.len())
        || n[0] & 0x80 == 0
        || e.is_empty()
        || e.len() > 4
        || e[0] == 0
    {
        return Err("Invalid RSA AK size/encoding".into());
    }
    let spki = rsa_spki(&n, &e);
    Ok(Hcl {
        snp,
        var_hash: digest::digest(&digest::SHA256, var).as_ref().to_vec(),
        n,
        e,
        spki,
    })
}
struct Cursor<'a> {
    b: &'a [u8],
    p: usize,
}
impl<'a> Cursor<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let v = bytes(self.b, self.p, n)?;
        self.p += n;
        Ok(v)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(
            self.take(2)?.try_into().map_err(|_| "u16")?,
        ))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(
            self.take(4)?.try_into().map_err(|_| "u32")?,
        ))
    }
    fn sized(&mut self) -> Result<&'a [u8]> {
        let n = self.u16()? as usize;
        self.take(n)
    }
}
pub struct SignedQuote<'a> {
    challenge: &'a [u8],
    pcr_data: &'a [u8],
}
pub fn quote_signature<'a>(q: &'a Quote, n: &[u8], e: &[u8]) -> Result<SignedQuote<'a>> {
    if q.message.len() > 4096
        || q.signature.len() > 1024
        || q.pcr_banks.is_empty()
        || q.pcr_banks.len() > 2
    {
        return Err("Invalid quote size/banks".into());
    }
    signature::RsaPublicKeyComponents { n, e }
        .verify(
            &signature::RSA_PKCS1_2048_8192_SHA256,
            &q.message,
            &q.signature,
        )
        .map_err(|_| "Quote signature mismatch")?;
    let mut c = Cursor {
        b: &q.message,
        p: 0,
    };
    if c.u32()? != 0xff544347 || c.u16()? != 0x8018 {
        return Err("Invalid TPM quote magic/type".into());
    }
    if c.sized()?.len() > 68 {
        return Err("Invalid qualified signer".into());
    }
    let challenge = c.sized()?;
    c.take(16)?;
    if c.u8()? > 1 {
        return Err("Invalid TPM clock flag".into());
    }
    c.take(8)?;
    Ok(SignedQuote {
        challenge,
        pcr_data: &q.message[c.p..],
    })
}
pub fn quoted_pcrs(signed: &SignedQuote<'_>, q: &Quote) -> Result<()> {
    let mut c = Cursor {
        b: signed.pcr_data,
        p: 0,
    };
    let count = c.u32()? as usize;
    if count != q.pcr_banks.len() {
        return Err("Unsigned/missing PCR banks".into());
    }
    let mut seen = vec![];
    let mut d = digest::Context::new(&digest::SHA256);
    for _ in 0..count {
        let algo = match c.u16()? {
            4 => Algorithm::Sha1,
            11 => Algorithm::Sha256,
            _ => return Err("Unsupported PCR bank".into()),
        };
        if seen.contains(&algo) {
            return Err("Duplicate PCR bank".into());
        }
        seen.push(algo);
        let len = c.u8()? as usize;
        if len != 3 {
            return Err("Unsupported PCR selection size".into());
        }
        let bits = c.take(len)?;
        let slots: Vec<_> = (0..24)
            .filter(|i| bits[i / 8] & (1 << (i % 8)) != 0)
            .collect();
        let bank = q.get_pcr_bank(algo).ok_or("Signed PCR bank missing")?;
        if slots.len() < 11 || slots.len() != bank.pcr_values.len() {
            return Err("Invalid signed PCR count".into());
        }
        for (i, (&slot, value)) in slots.iter().zip(&bank.pcr_values).enumerate() {
            if slot != i || value.len() != algo.length() {
                return Err("Invalid signed PCR position/length".into());
            }
            d.update(value);
        }
    }
    if c.sized()? != d.finish().as_ref() || c.p != signed.pcr_data.len() {
        return Err("PCR digest mismatch or trailing quote bytes".into());
    }
    Ok(())
}
pub fn snapshot_binding(
    signed: &SignedQuote<'_>,
    evidence: &Evidence,
    nonce: &[u8],
    certificate_der: &[u8],
) -> Result<()> {
    if nonce.len() != 32 {
        return Err("Expected 32-byte nonce".into());
    }
    let binding = Evidence::ima_binding(&evidence.ima_measurements).map_err(|e| e.to_string())?;
    let transcript = digest::digest(
        &digest::SHA256,
        &[nonce, certificate_der, &binding].concat(),
    );
    verify_quote_binding(signed, transcript.as_ref())
}
fn verify_quote_binding(signed: &SignedQuote<'_>, expected: &[u8]) -> Result<()> {
    if signed.challenge != expected {
        return Err("Quote challenge/certificate/log binding mismatch".into());
    }
    Ok(())
}
#[cfg(test)]
pub(crate) fn quote(q: &Quote, n: &[u8], e: &[u8], expected: &[u8]) -> Result<()> {
    let signed = quote_signature(q, n, e)?;
    verify_quote_binding(&signed, expected)?;
    quoted_pcrs(&signed, q)
}
pub fn verify_snapshot(evidence: &Evidence, nonce: &[u8], certificate_der: &[u8]) -> Result<()> {
    if nonce.len() != 32 {
        return Err("Expected 32-byte nonce".into());
    }
    let h = hcl(&evidence.report)?;
    let signed = quote_signature(&evidence.quote, &h.n, &h.e)?;
    snapshot_binding(&signed, evidence, nonce, certificate_der)?;
    quoted_pcrs(&signed, &evidence.quote)
}

#[cfg(test)]
mod tests;
