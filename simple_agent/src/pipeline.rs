/// JWE + JSON transformer pipeline -- pure Rust, no OpenSSL.
///
/// Mirrors the server's "jwe,json" transformer pipeline:
///   Construct (outbound): JSON encode then JWE encrypt
///   Deconstruct (inbound): JWE decrypt then JSON decode
///
/// JWE message body (pkg/transformer/encrypters/jwe/jwe.go):
///   alg: PBES2-HS512+A256KW, p2c=3000, password=sha256(PSK)
///   enc: A256GCM
///
/// JWT Authorization header (pkg/core/crypto/jwt.go, go-jose):
///   Nested signed-then-encrypted token:
///     Inner: JWS compact, alg=HS256, key=sha256(PSK)
///     Outer: JWE compact, alg=dir, enc=A256GCM, key=sha256(PSK)

use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce,
};
use aes_kw::KekAes256;
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
use hmac::{Hmac, Mac};
use pbkdf2::pbkdf2_hmac;
use rand::RngCore;
use sha2::{Digest, Sha256, Sha512};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

use crate::protocol::Base;

#[allow(dead_code)]
type HmacSha512 = Hmac<Sha512>;
type HmacSha256 = Hmac<Sha256>;

fn b64u(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

fn b64u_decode(s: &str) -> anyhow::Result<Vec<u8>> {
    URL_SAFE_NO_PAD.decode(s).map_err(|e| anyhow::anyhow!("base64url: {}", e))
}

/// Returns sha256(PSK) as a 32-byte array, matching the server.
pub fn derive_psk_key(psk: &str) -> [u8; 32] {
    Sha256::digest(psk.as_bytes()).into()
}

/// Derives a 32-byte key-wrap key via PBKDF2-HMAC-SHA512.
/// salt = UTF8("PBES2-HS512+A256KW") || 0x00 || salt_input  (RFC 8018 s6.2)
fn pbes2_derive_wrap_key(password: &[u8], salt_input: &[u8], iterations: u32) -> [u8; 32] {
    let prefix = b"PBES2-HS512+A256KW";
    let mut full_salt = Vec::with_capacity(prefix.len() + 1 + salt_input.len());
    full_salt.extend_from_slice(prefix);
    full_salt.push(0x00);
    full_salt.extend_from_slice(salt_input);

    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha512>(password, &full_salt, iterations, &mut key);
    key
}

/// AES-256-GCM encrypt. Returns (ciphertext, 12-byte nonce, 16-byte tag).
/// AAD = ASCII of base64url JWE header per JWE spec s5.1.
fn gcm_encrypt(key: &[u8; 32], plaintext: &[u8], aad: &[u8]) -> anyhow::Result<(Vec<u8>, [u8; 12], [u8; 16])> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Aes256Gcm::generate_nonce(&mut OsRng);

    let ct_tag = cipher
        .encrypt(&nonce, aes_gcm::aead::Payload { msg: plaintext, aad })
        .map_err(|e| anyhow::anyhow!("gcm encrypt: {:?}", e))?;

    let tpos = ct_tag.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&ct_tag[tpos..]);
    Ok((ct_tag[..tpos].to_vec(), nonce.into(), tag))
}

/// AES-256-GCM decrypt.
fn gcm_decrypt(key: &[u8; 32], iv: &[u8], ct: &[u8], tag: &[u8], aad: &[u8]) -> anyhow::Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(key.into());
    let nonce = Nonce::from_slice(iv);
    let mut ct_tag = ct.to_vec();
    ct_tag.extend_from_slice(tag);
    cipher
        .decrypt(nonce, aes_gcm::aead::Payload { msg: &ct_tag, aad })
        .map_err(|e| anyhow::anyhow!("gcm decrypt: {:?}", e))
}

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt a messages.Base with dir + A256GCM (direct key agreement).
/// Key = sha256(PSK). No PBKDF2 — fast for interactive tunnels.
/// Returns compact JWE bytes (the transport sends these as the POST body).
pub fn encrypt_message(msg: &Base, psk: &str) -> anyhow::Result<Vec<u8>> {
    let plaintext = serde_json::to_vec(msg)?;
    let key = derive_psk_key(psk); // sha256(PSK) = AES-256-GCM CEK

    let hdr = serde_json::json!({
        "alg": "dir",
        "enc": "A256GCM",
    });
    let hdr_b64 = b64u(serde_json::to_string(&hdr)?.as_bytes());

    let (ct, nonce, tag) = gcm_encrypt(&key, &plaintext, hdr_b64.as_bytes())?;

    // dir algorithm: encrypted_key is empty (second segment)
    let compact = format!("{}..{}.{}.{}", hdr_b64, b64u(&nonce), b64u(&ct), b64u(&tag));
    Ok(compact.into_bytes())
}

/// Decrypt compact JWE message body back to messages.Base.
/// Supports both dir (fast) and PBES2 (legacy) algorithms.
pub fn decrypt_message(data: &[u8], psk: &str) -> anyhow::Result<Base> {
    let token = std::str::from_utf8(data)?;
    let parts: Vec<&str> = token.split('.').collect();
    if parts.len() != 5 {
        anyhow::bail!("JWE: expected 5 parts, got {}", parts.len());
    }

    let hdr_bytes = b64u_decode(parts[0])?;
    let hdr: serde_json::Value = serde_json::from_slice(&hdr_bytes)?;
    let alg = hdr["alg"].as_str().unwrap_or("dir");

    let cek = if alg == "dir" {
        // Direct key agreement: CEK = sha256(PSK), encrypted_key segment is empty
        derive_psk_key(psk)
    } else {
        // PBES2 fallback for legacy compatibility
        let password = derive_psk_key(psk);
        let p2c = hdr["p2c"].as_u64().unwrap_or(3000) as u32;
        let salt_input = b64u_decode(hdr["p2s"].as_str().ok_or_else(|| anyhow::anyhow!("missing p2s"))?)?;
        let wrap_key = pbes2_derive_wrap_key(&password, &salt_input, p2c);
        let kek = KekAes256::from(wrap_key);
        let mut cek = [0u8; 32];
        kek.unwrap(&b64u_decode(parts[1])?, &mut cek).map_err(|e| anyhow::anyhow!("kw unwrap: {:?}", e))?;
        cek
    };

    let plain = gcm_decrypt(&cek, &b64u_decode(parts[2])?, &b64u_decode(parts[3])?, &b64u_decode(parts[4])?, parts[0].as_bytes())?;
    Ok(serde_json::from_slice(&plain)?)
}

/// Builds Authorization header for an unauthenticated agent.
/// Bearer <JWE(dir+A256GCM, cty=JWT) containing JWS(HS256 claims)>
pub fn build_auth_jwt(agent_id: Uuid, psk: &str) -> anyhow::Result<String> {
    let key = derive_psk_key(psk);
    let now = SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs();

    // Inner JWS: HS256
    let jws_hdr = b64u(serde_json::to_string(&serde_json::json!({"alg":"HS256"}))?.as_bytes());
    let jws_pay = b64u(serde_json::to_string(&serde_json::json!({
        "jti": agent_id.to_string(),
        "nbf": now,
        "iat": now,
        "exp": now + 1800u64,
    }))?.as_bytes());
    let msg = format!("{}.{}", jws_hdr, jws_pay);
    let mut mac = <HmacSha256 as hmac::Mac>::new_from_slice(&key)?;
    mac.update(msg.as_bytes());
    let sig = hmac::Mac::finalize(mac).into_bytes();
    let jws = format!("{}.{}", msg, b64u(&sig));

    // Outer JWE: dir + A256GCM, cty=JWT (go-jose nested JWT convention)
    let jwe_hdr = b64u(serde_json::to_string(&serde_json::json!({"alg":"dir","enc":"A256GCM","cty":"JWT"}))?.as_bytes());
    let (ct, nonce, tag) = gcm_encrypt(&key, jws.as_bytes(), jwe_hdr.as_bytes())?;

    // DIRECT: encrypted-key part is empty string
    let jwe = format!("{}..{}.{}.{}", jwe_hdr, b64u(&nonce), b64u(&ct), b64u(&tag));

    Ok(format!("Bearer {}", jwe))
}

/// For authenticated agents: wrap the server-issued token string.
pub fn build_auth_header_from_token(token: &str) -> String {
    if token.starts_with("Bearer ") {
        token.to_string()
    } else {
        format!("Bearer {}", token)
    }
}
