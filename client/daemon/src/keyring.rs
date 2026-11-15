//! Tokens and the device key, kept in the desktop keyring through the
//! Secret Service API (KWallet answers it on Raye, GNOME Keyring elsewhere).

use std::collections::HashMap;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::SigningKey;
use secret_service::{EncryptionType, SecretService};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

#[derive(Clone, Serialize, Deserialize)]
pub struct Secrets {
    pub access_token: String,
    pub refresh_token: String,
    /// Unix time the access token stops working.
    pub access_expires: i64,
    pub device_id: Uuid,
    /// Ed25519 seed, base64url.
    pub device_key: String,
}

impl Secrets {
    pub fn signing_key(&self) -> Option<SigningKey> {
        let seed: [u8; 32] = URL_SAFE_NO_PAD.decode(&self.device_key).ok()?.try_into().ok()?;
        Some(SigningKey::from_bytes(&seed))
    }
}

impl std::fmt::Debug for Secrets {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Secrets").field("device_id", &self.device_id).finish_non_exhaustive()
    }
}

const LABEL: &str = "Raye account";

fn attributes(server: &str) -> HashMap<&str, &str> {
    HashMap::from([("application", "org.raye.account"), ("server", server)])
}

/// Only in builds with the insecure-test-keyring feature (the headless
/// demo): the secrets go to a 0600 file instead of the keyring.
#[cfg(feature = "insecure-test-keyring")]
fn test_file() -> Option<std::path::PathBuf> {
    std::env::var_os("RAYE_ACCOUNT_TEST_KEYRING_FILE").map(Into::into)
}

#[cfg(not(feature = "insecure-test-keyring"))]
fn test_file() -> Option<std::path::PathBuf> {
    None
}

/// secret-service 5 sends its DH public key without leading zero bytes, so
/// about one session in 256 is refused by KWallet ("Client public key size
/// is invalid"). A new session gets a new key.
async fn connect() -> Result<SecretService<'static>, String> {
    let mut last = String::new();
    for _ in 0..6 {
        match SecretService::connect(EncryptionType::Dh).await {
            Ok(ss) => return Ok(ss),
            Err(e) => {
                last = err(e);
                if !is_short_key(&last) {
                    break;
                }
            }
        }
    }
    Err(last)
}

fn is_short_key(message: &str) -> bool {
    message.contains("public key size is invalid")
}

pub async fn store(server: &str, s: &Secrets) -> Result<(), String> {
    let bytes = serde_json::to_vec(s).map_err(|e| e.to_string())?;
    if let Some(path) = test_file() {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)
            .map_err(|e| e.to_string())?;
        return f.write_all(&bytes).map_err(|e| e.to_string());
    }
    let ss = connect().await?;
    let collection = ss.get_default_collection().await.map_err(err)?;
    if collection.is_locked().await.map_err(err)? {
        collection.unlock().await.map_err(err)?;
    }
    collection
        .create_item(LABEL, attributes(server), &bytes, true, "application/json")
        .await
        .map_err(err)?;
    Ok(())
}

pub async fn load(server: &str) -> Result<Option<Secrets>, String> {
    if let Some(path) = test_file() {
        return Ok(std::fs::read(path).ok().and_then(|b| serde_json::from_slice(&b).ok()));
    }
    let ss = connect().await?;
    let found = ss.search_items(attributes(server)).await.map_err(err)?;
    let item = match (found.unlocked.into_iter().next(), found.locked.into_iter().next()) {
        (Some(i), _) => i,
        (None, Some(i)) => {
            i.unlock().await.map_err(err)?;
            i
        }
        (None, None) => return Ok(None),
    };
    let bytes = item.get_secret().await.map_err(err)?;
    Ok(serde_json::from_slice(&bytes).ok())
}

pub async fn delete(server: &str) -> Result<(), String> {
    if let Some(path) = test_file() {
        let _ = std::fs::remove_file(path);
        return Ok(());
    }
    let ss = connect().await?;
    let found = ss.search_items(attributes(server)).await.map_err(err)?;
    for item in found.unlocked.into_iter().chain(found.locked) {
        item.delete().await.map_err(err)?;
    }
    Ok(())
}

fn err(e: secret_service::Error) -> String {
    format!("keyring: {e}")
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A build that is not the headless demo must have no way to put secrets
    /// in a file, whatever the environment says.
    ///
    /// `RAYE_ACCOUNT_TEST_KEYRING_FILE` is read only under the
    /// `insecure-test-keyring` feature, which no package build enables. If
    /// that ever stopped being true, an attacker who can set one environment
    /// variable in the session could have the tokens written where they can
    /// read them -- and `store()` would report success.
    #[test]
    fn the_environment_alone_cannot_divert_secrets_to_a_file() {
        let diverted = cfg!(feature = "insecure-test-keyring");
        // SAFETY: single-threaded test, and the variable is read, never kept.
        unsafe { std::env::set_var("RAYE_ACCOUNT_TEST_KEYRING_FILE", "/tmp/should-never-be-written") }
        assert_eq!(
            test_file().is_some(),
            diverted,
            "the file store answered without the insecure-test-keyring feature"
        );
        unsafe { std::env::remove_var("RAYE_ACCOUNT_TEST_KEYRING_FILE") }
        assert!(test_file().is_none(), "and nothing at all without the variable");
    }

    /// `Secrets` is carried through logs and error paths; its Debug must not
    /// be the thing that writes a refresh token to a journal.
    #[test]
    fn the_debug_of_secrets_shows_no_secret() {
        let s = Secrets {
            access_token: "ACCESS-TOKEN-VALUE".into(),
            refresh_token: "REFRESH-TOKEN-VALUE".into(),
            access_expires: 1,
            device_id: Uuid::nil(),
            device_key: "DEVICE-KEY-SEED".into(),
        };
        let shown = format!("{s:?}");
        for secret in ["ACCESS-TOKEN-VALUE", "REFRESH-TOKEN-VALUE", "DEVICE-KEY-SEED"] {
            assert!(!shown.contains(secret), "{secret} is in {shown}");
        }
        assert!(shown.contains("device_id"), "the one field worth logging stays: {shown}");
    }

    #[test]
    fn a_device_key_round_trips_through_its_stored_form() {
        use ed25519_dalek::Signer;
        let key = ed25519_dalek::SigningKey::generate(&mut rand::rngs::OsRng);
        let s = Secrets {
            access_token: String::new(),
            refresh_token: String::new(),
            access_expires: 0,
            device_id: Uuid::nil(),
            device_key: URL_SAFE_NO_PAD.encode(key.to_bytes()),
        };
        let back = s.signing_key().expect("the seed parses");
        assert_eq!(back.verifying_key().to_bytes(), key.verifying_key().to_bytes());
        assert_eq!(back.sign(b"x").to_bytes(), key.sign(b"x").to_bytes());

        // Junk must not panic the daemon, and must not pretend to be a key.
        for bad in ["", "not base64url!!", "c2hvcnQ"] {
            let s = Secrets { device_key: bad.into(), ..s.clone() };
            assert!(s.signing_key().is_none(), "{bad:?}");
        }
    }
}

#[cfg(test)]
mod short_key_tests {
    #[test]
    fn only_the_short_key_refusal_is_retried() {
        assert!(super::is_short_key("zbus error: org.freedesktop.DBus.Error.InvalidArgs: Client public key size is invalid"));
        assert!(!super::is_short_key("org.freedesktop.DBus.Error.ServiceUnknown"));
    }
}
