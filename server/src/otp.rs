//! Two-step verification: RFC 6238 TOTP, the secret sealed at rest, and
//! recovery codes.
//!
//! Two properties make this a second factor rather than a second password,
//! and both live in this file as plain functions so a test can pin them:
//!
//!   * **the drift window is bounded** (`DRIFT_STEPS`, one 30 s step either
//!     side). Every extra step hands away another 10^-6 of the code space
//!     and another half minute during which a code read over someone's
//!     shoulder still works;
//!   * **a step is spent once** (`verify` takes `last_step` and only ever
//!     returns a LATER one). A code that worked is dead, and so is every
//!     code from before it -- not just its own. Without this a code is
//!     replayable for up to 90 s, which is all a phishing page needs.
//!
//! The secret is stored sealed under the server key, so a database dump does
//! not hand over everyone's second factor.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chacha20poly1305::aead::{Aead, KeyInit};
use chacha20poly1305::{XChaCha20Poly1305, XNonce};
use hmac::{Hmac, Mac};
use rand::RngCore;
use sha1::Sha1;
use sha2::{Digest, Sha256};

use raye_account_common::ct_eq;

/// RFC 6238 defaults, and what every authenticator app assumes.
pub const STEP_SECS: i64 = 30;
pub const DIGITS: usize = 6;
/// One step either side: a slow reader, or a phone a few seconds off.
pub const DRIFT_STEPS: i64 = 1;
/// Bytes of shared secret (RFC 4226 recommends at least 16).
const SECRET_LEN: usize = 20;

/// The 32-byte server key the TOTP secrets are sealed with. Its `Debug` says
/// nothing: a key that reaches a log is a key to rotate.
#[derive(Clone)]
pub struct SecretKey(pub [u8; 32]);

impl std::fmt::Debug for SecretKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("SecretKey(<redacted>)")
    }
}

impl SecretKey {
    pub fn random() -> SecretKey {
        let mut k = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut k);
        SecretKey(k)
    }

    /// From `RAYE_ACCOUNT_TOTP_KEY`: 32 bytes, base64url, no padding.
    pub fn parse(s: &str) -> Option<SecretKey> {
        let raw = URL_SAFE_NO_PAD.decode(s.trim()).ok()?;
        Some(SecretKey(raw.try_into().ok()?))
    }
}

pub fn new_secret() -> Vec<u8> {
    let mut s = vec![0u8; SECRET_LEN];
    rand::rngs::OsRng.fill_bytes(&mut s);
    s
}

/// nonce (24 bytes) followed by the ciphertext and its tag.
pub fn seal(key: &SecretKey, plain: &[u8]) -> Vec<u8> {
    let cipher = XChaCha20Poly1305::new((&key.0).into());
    let mut nonce = [0u8; 24];
    rand::rngs::OsRng.fill_bytes(&mut nonce);
    let mut out = nonce.to_vec();
    out.extend(cipher.encrypt(XNonce::from_slice(&nonce), plain).expect("xchacha20poly1305 seals"));
    out
}

pub fn open(key: &SecretKey, sealed: &[u8]) -> Option<Vec<u8>> {
    if sealed.len() <= 24 {
        return None;
    }
    let (nonce, body) = sealed.split_at(24);
    XChaCha20Poly1305::new((&key.0).into())
        .decrypt(XNonce::from_slice(nonce), body)
        .ok()
}

pub fn step_at(unix: i64) -> i64 {
    unix.div_euclid(STEP_SECS)
}

fn code_for_step(secret: &[u8], step: i64) -> u32 {
    let mut mac = <Hmac<Sha1> as Mac>::new_from_slice(secret).expect("hmac accepts any key length");
    mac.update(&(step as u64).to_be_bytes());
    let tag = mac.finalize().into_bytes();
    // RFC 4226 5.3 dynamic truncation.
    let off = (tag[19] & 0x0f) as usize;
    let bin = u32::from_be_bytes([tag[off], tag[off + 1], tag[off + 2], tag[off + 3]]) & 0x7fff_ffff;
    bin % 10u32.pow(DIGITS as u32)
}

pub fn code_at(secret: &[u8], unix: i64) -> String {
    format(code_for_step(secret, step_at(unix)))
}

/// The code for a step, for tests and for the ±1 window.
pub fn code_for(secret: &[u8], step: i64) -> String {
    format(code_for_step(secret, step))
}

fn format(code: u32) -> String {
    format!("{code:0width$}", width = DIGITS)
}

/// The step this code belongs to, or None.
///
/// Refused when: the shape is wrong, no step in the window produces it, or
/// the step is not strictly later than `last_step` (already spent -- the
/// anti-replay rule). Every step in the window is tried whatever happens, so
/// the answer takes the same time for a wrong code and a replayed one.
pub fn verify(secret: &[u8], code: &str, now_unix: i64, last_step: i64) -> Option<i64> {
    let code = code.trim();
    if code.len() != DIGITS || !code.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let now = step_at(now_unix);
    let mut found = None;
    for step in (now - DRIFT_STEPS)..=(now + DRIFT_STEPS) {
        let matches = ct_eq(format(code_for_step(secret, step)).as_bytes(), code.as_bytes());
        if matches && step > last_step && found.is_none() {
            found = Some(step);
        }
    }
    found
}

/// What the QR code and "enter it by hand" both carry. The secret is base32
/// because that is what RFC 6238's `otpauth:` URI uses and every app reads.
pub fn otpauth_uri(secret: &[u8], email: &str) -> String {
    format!(
        "otpauth://totp/Raye:{}?secret={}&issuer=Raye&algorithm=SHA1&digits={}&period={}",
        uri_escape(email),
        base32(secret),
        DIGITS,
        STEP_SECS
    )
}

fn uri_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-._~@".contains(&b) {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// RFC 4648 base32, uppercase, no padding.
pub fn base32(bytes: &[u8]) -> String {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let mut out = String::new();
    let (mut acc, mut bits) = (0u32, 0u32);
    for &b in bytes {
        acc = (acc << 8) | b as u32;
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            out.push(A[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        out.push(A[((acc << (5 - bits)) & 31) as usize] as char);
    }
    out
}

/// How many recovery codes an account gets, shown once.
pub const RECOVERY_CODES: usize = 10;

/// A recovery code: 80 random bits as base32, in groups of four. High
/// entropy and never user-chosen, so it is stored as a SHA-256 and looked up
/// by that hash -- the same rule as every other token here. The design doc
/// says Argon2; a 19 MiB KDF buys nothing against 80 random bits and would
/// cost 10 hashes per try. Recorded in docs/security-review.md.
pub fn new_recovery_code() -> String {
    let mut raw = [0u8; 10];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    let s = base32(&raw);
    s.as_bytes().chunks(4).map(|c| std::str::from_utf8(c).unwrap()).collect::<Vec<_>>().join("-")
}

/// Dashes, spaces and case are what people get wrong when copying a code by
/// hand; none of them carry meaning, so they are removed before hashing.
pub fn recovery_hash(code: &str) -> Vec<u8> {
    let normal: String = code.chars().filter(|c| c.is_ascii_alphanumeric()).flat_map(|c| c.to_uppercase()).collect();
    Sha256::digest(normal.as_bytes()).to_vec()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc4648_base32_vectors() {
        assert_eq!(base32(b""), "");
        assert_eq!(base32(b"f"), "MY");
        assert_eq!(base32(b"fo"), "MZXQ");
        assert_eq!(base32(b"foo"), "MZXW6");
        assert_eq!(base32(b"foobar"), "MZXW6YTBOI");
    }

    /// RFC 6238 appendix B, the SHA-1 rows, with its 20-byte secret.
    #[test]
    fn rfc6238_appendix_b() {
        let secret = b"12345678901234567890";
        for (unix, want) in [
            (59i64, "287082"),
            (1_111_111_109, "081804"),
            (1_111_111_111, "050471"),
            (1_234_567_890, "005924"),
            (2_000_000_000, "279037"),
        ] {
            assert_eq!(code_at(secret, unix), want, "at {unix}");
        }
    }

    #[test]
    fn a_step_is_spent_once() {
        let secret = new_secret();
        let now = 1_762_400_000;
        let step = step_at(now);
        let code = code_for(&secret, step);
        assert_eq!(verify(&secret, &code, now, 0), Some(step), "first use");
        // Replay: the account has now spent that step.
        assert_eq!(verify(&secret, &code, now, step), None, "same code again");
        // And every earlier code is dead too, not just that one.
        let before = code_for(&secret, step - 1);
        assert_eq!(verify(&secret, &before, now, step), None, "the previous step as well");
    }

    #[test]
    fn the_window_is_one_step_either_side() {
        let secret = new_secret();
        let now = 1_762_400_000;
        let step = step_at(now);
        for d in [-1i64, 0, 1] {
            let code = code_for(&secret, step + d);
            assert_eq!(verify(&secret, &code, now, 0), Some(step + d), "drift {d} is allowed");
        }
        for d in [-2i64, 2, 10, -10] {
            let code = code_for(&secret, step + d);
            assert_eq!(verify(&secret, &code, now, 0), None, "drift {d} is outside the window");
        }
    }

    #[test]
    fn refuses_what_is_not_a_code() {
        let secret = new_secret();
        let now = 1_762_400_000;
        let good = code_for(&secret, step_at(now));
        for bad in ["", "12345", "1234567", "abcdef", "12 456", "+12345"] {
            assert_eq!(verify(&secret, bad, now, 0), None, "{bad:?}");
        }
        // A code from another secret never works.
        assert_eq!(verify(&new_secret(), &good, now, 0), None);
        // Surrounding space is a copy-paste artefact, not a wrong code.
        assert!(verify(&secret, &format!("  {good} "), now, 0).is_some());
    }

    #[test]
    fn sealed_secrets_need_the_right_key() {
        let key = SecretKey::random();
        let secret = new_secret();
        let sealed = seal(&key, &secret);
        assert_ne!(sealed, secret, "stored sealed, never in the clear");
        assert!(!sealed.windows(secret.len()).any(|w| w == secret.as_slice()), "no plaintext inside");
        assert_eq!(open(&key, &sealed).as_deref(), Some(secret.as_slice()));
        assert_eq!(open(&SecretKey::random(), &sealed), None, "another key");
        // Sealing twice gives different bytes: a fresh nonce each time, so
        // two accounts with the same secret do not look the same in a dump.
        assert_ne!(seal(&key, &secret), sealed);
        let mut torn = sealed.clone();
        *torn.last_mut().unwrap() ^= 1;
        assert_eq!(open(&key, &torn), None, "a flipped bit is refused, not decrypted");
        assert_eq!(open(&key, &[0u8; 8]), None, "too short to hold a nonce");
    }

    #[test]
    fn key_debug_does_not_print_the_key() {
        let key = SecretKey([7u8; 32]);
        let shown = format!("{key:?}");
        assert!(!shown.contains('7'), "{shown}");
        assert!(shown.contains("redacted"));
    }

    #[test]
    fn key_round_trips_through_the_environment_form() {
        let key = SecretKey::random();
        let text = URL_SAFE_NO_PAD.encode(key.0);
        assert_eq!(SecretKey::parse(&text).unwrap().0, key.0);
        assert!(SecretKey::parse("too short").is_none());
        assert!(SecretKey::parse(&URL_SAFE_NO_PAD.encode([0u8; 16])).is_none(), "16 bytes is not a key");
    }

    #[test]
    fn recovery_codes_are_distinct_and_forgiving() {
        let codes: Vec<_> = (0..RECOVERY_CODES).map(|_| new_recovery_code()).collect();
        let mut seen: Vec<_> = codes.iter().map(|c| recovery_hash(c)).collect();
        seen.sort();
        seen.dedup();
        assert_eq!(seen.len(), RECOVERY_CODES, "no two the same");
        let c = &codes[0];
        assert_eq!(c.len(), 19, "16 base32 characters in four groups: {c}");
        assert_eq!(recovery_hash(c), recovery_hash(&c.to_lowercase()));
        assert_eq!(recovery_hash(c), recovery_hash(&c.replace('-', "")));
        assert_eq!(recovery_hash(c), recovery_hash(&c.replace('-', " ")));
        assert_ne!(recovery_hash(c), recovery_hash(&codes[1]));
    }

    #[test]
    fn otpauth_uri_is_readable_by_an_app() {
        let uri = otpauth_uri(b"12345678901234567890", "ana+x@example.com");
        assert!(uri.starts_with("otpauth://totp/Raye:ana%2Bx@example.com?"), "{uri}");
        assert!(uri.contains("secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"), "{uri}");
        assert!(uri.contains("issuer=Raye") && uri.contains("digits=6") && uri.contains("period=30"));
        assert!(!uri.contains("12345678901234567890"), "the secret is base32, not raw");
    }
}
