//! PKCE (RFC 7636), S256 only. "plain" is refused on purpose.

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use sha2::{Digest, Sha256};

/// A fresh code verifier: 43 characters of base64url, the shortest the RFC allows,
/// from 32 random bytes.
pub fn new_verifier() -> String {
    crate::random_token()
}

pub fn challenge(verifier: &str) -> String {
    URL_SAFE_NO_PAD.encode(Sha256::digest(verifier.as_bytes()))
}

/// RFC 7636 4.1: 43 to 128 characters from [A-Za-z0-9-._~].
pub fn verifier_is_well_formed(verifier: &str) -> bool {
    (43..=128).contains(&verifier.len())
        && verifier
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'_' | b'~'))
}

/// A challenge is the base64url of a SHA-256: exactly 43 characters.
pub fn challenge_is_well_formed(challenge: &str) -> bool {
    challenge.len() == 43
        && challenge
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

pub fn verify(verifier: &str, expected_challenge: &str) -> bool {
    if !verifier_is_well_formed(verifier) {
        return false;
    }
    // Both sides are public once the code is redeemed, but compare in
    // constant time anyway so this never becomes a timing oracle.
    crate::ct_eq(challenge(verifier).as_bytes(), expected_challenge.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc7636_appendix_b() {
        let verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
        assert_eq!(challenge(verifier), "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM");
        assert!(verify(verifier, "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"));
    }

    #[test]
    fn wrong_or_malformed_verifier_fails() {
        let v = new_verifier();
        let c = challenge(&v);
        assert!(challenge_is_well_formed(&c));
        assert!(verify(&v, &c));
        assert!(!verify(&new_verifier(), &c));
        assert!(!verify("short", &challenge("short")));
        assert!(!verify(&format!("{v} "), &c));
    }
}
