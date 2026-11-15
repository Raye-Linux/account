//! What the server and the desktop client must agree on: the list of
//! settings that may sync and how each one is checked, PKCE, the message
//! a device signs to refresh its tokens, and the JSON shapes of the API.

pub mod api;
pub mod keys;
pub mod pkce;
pub mod table;

use sha2::{Digest, Sha256};
use uuid::Uuid;

/// The desktop app's OAuth client id. There is no client secret: a desktop
/// app cannot keep one, PKCE and the loopback redirect do that job.
pub const DESKTOP_CLIENT_ID: &str = "raye-desktop";

/// How far a refresh proof's timestamp may drift from the server clock.
pub const REFRESH_PROOF_SKEW_SECS: i64 = 300;

/// Bytes a device signs with its Ed25519 key when it refreshes. Binding the
/// refresh token to a key held by the device means a refresh token that
/// leaks on its own (a log, a backup, a copy of the keyring file without
/// the key) cannot be used from somewhere else.
pub fn refresh_proof_message(device_id: &Uuid, ts: i64, refresh_token: &str) -> Vec<u8> {
    format!(
        "raye-account refresh v1\n{}\n{}\n{}",
        device_id,
        ts,
        hex(&Sha256::digest(refresh_token.as_bytes()))
    )
    .into_bytes()
}

pub fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(DIGITS[(b >> 4) as usize] as char);
        out.push(DIGITS[(b & 15) as usize] as char);
    }
    out
}

/// A random token for URLs and headers: 32 bytes, base64url without padding.
pub fn random_token() -> String {
    use base64::Engine;
    use rand::RngCore;
    let mut buf = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut buf);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn proof_message_is_stable() {
        let id = Uuid::parse_str("6f1c2c8e-1d1b-4c55-9a3e-2f6a1b0c9d10").unwrap();
        let msg = String::from_utf8(refresh_proof_message(&id, 1_700_000_000, "abc")).unwrap();
        assert_eq!(
            msg,
            "raye-account refresh v1\n6f1c2c8e-1d1b-4c55-9a3e-2f6a1b0c9d10\n1700000000\n\
             ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn random_tokens_differ() {
        let a = random_token();
        assert_eq!(a.len(), 43);
        assert_ne!(a, random_token());
    }
}

/// Compares two byte strings without an early exit, so how long the answer
/// takes says nothing about how much of a secret was guessed right. Used for
/// PKCE challenges, TOTP codes and anything else compared against a value
/// the caller supplied.
///
/// Lengths are compared first and in the clear: the length of a code or a
/// challenge is public, only its contents are not.
pub fn ct_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod ct_tests {
    use super::ct_eq;

    #[test]
    fn constant_time_compare() {
        assert!(ct_eq(b"", b""));
        assert!(ct_eq(b"123456", b"123456"));
        assert!(!ct_eq(b"123456", b"123457"), "last byte differs");
        assert!(!ct_eq(b"123456", b"023456"), "first byte differs");
        assert!(!ct_eq(b"123456", b"12345"), "shorter");
        assert!(!ct_eq(b"12345", b"123456"), "longer");
    }
}
