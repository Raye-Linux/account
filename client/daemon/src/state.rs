//! What the client remembers between runs, outside the keyring: nothing in
//! here would let anyone act as the account. Tokens and the device key live
//! in the keyring (see keyring.rs).

use std::collections::BTreeMap;
use std::io::Write;
use std::path::PathBuf;

use serde::{Deserialize, Serialize};

pub const DEFAULT_SERVER: &str = "https://account.rayelinux.com";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum ProfileMode {
    /// Picture and name from the account, the Windows default.
    #[default]
    Both,
    Picture,
    Name,
    None,
}

impl ProfileMode {
    pub fn parse(s: &str) -> Option<ProfileMode> {
        match s {
            "both" => Some(ProfileMode::Both),
            "picture" => Some(ProfileMode::Picture),
            "name" => Some(ProfileMode::Name),
            "none" => Some(ProfileMode::None),
            _ => None,
        }
    }

    pub fn id(self) -> &'static str {
        match self {
            ProfileMode::Both => "both",
            ProfileMode::Picture => "picture",
            ProfileMode::Name => "name",
            ProfileMode::None => "none",
        }
    }

    pub fn picture(self) -> bool {
        matches!(self, ProfileMode::Both | ProfileMode::Picture)
    }

    pub fn name(self) -> bool {
        matches!(self, ProfileMode::Both | ProfileMode::Name)
    }
}

/// Last value both sides agreed on for one key.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Synced {
    pub rev: i64,
    pub hash: String,
}

/// The local account as it was before the Raye account changed it, so
/// signing out can put it back.
#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
pub struct OriginalProfile {
    pub real_name: String,
    pub icon_file: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(default)]
pub struct State {
    pub server: String,
    pub email: String,
    pub display_name: String,
    pub device_name: String,
    pub signed_in: bool,
    /// Categories turned off by the user ("Raye backup" switches). Absent means on.
    pub sync_off: Vec<String>,
    /// Whether this PC's installed apps go to the Store library.
    pub apps_sync: bool,
    pub profile_mode: ProfileMode,
    pub settings_rev: i64,
    pub keys: BTreeMap<String, Synced>,
    pub installs_hash: String,
    pub avatar_etag: String,
    /// The picture last handed to AccountsService.
    pub avatar_applied: String,
    pub original_profile: Option<OriginalProfile>,
    /// RFC 3339 time of the last sync that went through.
    pub last_sync: String,
    pub last_error: String,
    /// The account already had other settings at sign-in: nothing syncs
    /// until the person picks this PC's or the account's.
    pub choose_pending: bool,
    pub choose_differ: usize,
    /// Signed in, but the account hasn't been compared with this PC yet
    /// (offline, or the keyring failed right after the sign-in).
    pub first_sync_pending: bool,
}

impl Default for State {
    fn default() -> Self {
        State {
            server: DEFAULT_SERVER.into(),
            email: String::new(),
            display_name: String::new(),
            device_name: String::new(),
            signed_in: false,
            sync_off: Vec::new(),
            apps_sync: true,
            profile_mode: ProfileMode::Both,
            settings_rev: 0,
            keys: BTreeMap::new(),
            installs_hash: String::new(),
            avatar_etag: String::new(),
            avatar_applied: String::new(),
            original_profile: None,
            last_sync: String::new(),
            last_error: String::new(),
            choose_pending: false,
            choose_differ: 0,
            first_sync_pending: false,
        }
    }
}

pub fn state_dir() -> PathBuf {
    std::env::var_os("XDG_STATE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".local/state"))
        .join("raye-account")
}

pub fn cache_dir() -> PathBuf {
    std::env::var_os("XDG_CACHE_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".cache"))
        .join("raye-account")
}

pub fn config_dir() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .filter(|p| p.is_absolute())
        .unwrap_or_else(|| home().join(".config"))
}

pub fn home() -> PathBuf {
    std::env::var_os("HOME").map(PathBuf::from).unwrap_or_else(|| PathBuf::from("/"))
}

impl State {
    pub fn path() -> PathBuf {
        state_dir().join("state.json")
    }

    pub fn load() -> State {
        let mut s: State = std::fs::read(State::path())
            .ok()
            .and_then(|b| serde_json::from_slice(&b).ok())
            .unwrap_or_default();
        if let Some(server) = server_override() {
            s.server = server;
        }
        s
    }

    /// Written to a temporary file then renamed: a crash never leaves half a file.
    pub fn save(&self) -> std::io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt;
        let dir = state_dir();
        std::fs::create_dir_all(&dir)?;
        let tmp = dir.join(".state.json.tmp");
        let mut f = std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&tmp)?;
        f.write_all(&serde_json::to_vec_pretty(self).unwrap_or_default())?;
        f.sync_all()?;
        std::fs::rename(tmp, State::path())
    }

    pub fn avatar_applied_etag(&self) -> &str {
        &self.avatar_applied
    }

    pub fn mark_avatar_applied(&mut self) {
        self.avatar_applied = self.avatar_etag.clone();
    }

    pub fn category_on(&self, id: &str) -> bool {
        !self.sync_off.iter().any(|c| c == id)
    }

    pub fn set_category(&mut self, id: &str, on: bool) {
        self.sync_off.retain(|c| c != id);
        if !on {
            self.sync_off.push(id.to_owned());
        }
    }

    /// Back to signed out, keeping the user's switches and the server.
    pub fn sign_out(&mut self) {
        *self = State {
            server: std::mem::take(&mut self.server),
            sync_off: std::mem::take(&mut self.sync_off),
            apps_sync: self.apps_sync,
            profile_mode: self.profile_mode,
            ..State::default()
        };
    }
}

/// Where the account server is: RAYE_ACCOUNT_SERVER, then `server=` in
/// /etc/raye/account.conf. Plain http is refused except on loopback, so a
/// wrong config cannot send tokens over the network in clear.
pub fn server_override() -> Option<String> {
    let raw = std::env::var("RAYE_ACCOUNT_SERVER").ok().or_else(|| {
        std::fs::read_to_string("/etc/raye/account.conf").ok().and_then(|c| {
            c.lines()
                .filter_map(|l| l.trim().strip_prefix("server="))
                .map(|v| v.trim().to_owned())
                .next()
        })
    })?;
    let url = raw.trim_end_matches('/').to_owned();
    server_url_ok(&url).then_some(url)
}

pub fn server_url_ok(url: &str) -> bool {
    url.starts_with("https://")
        || url.starts_with("http://127.0.0.1:")
        || url.starts_with("http://[::1]:")
        || url.starts_with("http://localhost:")
}

/// The hidden switch: the account stays out of sight unless this is set.
pub fn preview_enabled() -> bool {
    std::env::var("RAYE_ACCOUNT_PREVIEW").is_ok_and(|v| v == "1")
        || std::path::Path::new("/etc/raye/account-preview").exists()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn modes() {
        for m in [ProfileMode::Both, ProfileMode::Picture, ProfileMode::Name, ProfileMode::None] {
            assert_eq!(ProfileMode::parse(m.id()), Some(m));
        }
        assert!(ProfileMode::Both.picture() && ProfileMode::Both.name());
        assert!(ProfileMode::Picture.picture() && !ProfileMode::Picture.name());
        assert!(!ProfileMode::None.picture() && !ProfileMode::None.name());
    }

    #[test]
    fn sign_out_keeps_choices_only() {
        let mut s = State {
            email: "a@b.c".into(),
            signed_in: true,
            settings_rev: 9,
            profile_mode: ProfileMode::Name,
            ..State::default()
        };
        s.set_category("accessibility", false);
        s.sign_out();
        assert!(!s.signed_in && s.email.is_empty() && s.settings_rev == 0);
        assert_eq!(s.profile_mode, ProfileMode::Name);
        assert!(!s.category_on("accessibility"));
    }


    /// What the state file is allowed to hold, and who may read it.
    ///
    /// The claim in docs/security-review.md is "state file 0600 holds nothing
    /// usable". This is that claim as a test: every field is filled with a
    /// marker, the file is written, and the bytes are searched for anything
    /// that would let a reader act as the account. Tokens and the device key
    /// live in the keyring (keyring.rs) and must never appear here.
    #[test]
    fn the_state_file_holds_nothing_that_could_act_as_the_account() {
        let dir = tempdir("state-secrets");
        // SAFETY: single-threaded test.
        unsafe { std::env::set_var("XDG_STATE_HOME", &dir) }

        let mut s = State {
            server: "https://account.rayelinux.com".into(),
            email: "ana@example.com".into(),
            display_name: "Ana Tremblay".into(),
            device_name: "Bureau".into(),
            signed_in: true,
            apps_sync: true,
            profile_mode: ProfileMode::Both,
            settings_rev: 42,
            installs_hash: "deadbeef".into(),
            avatar_etag: "0123456789ab".into(),
            avatar_applied: "0123456789ab".into(),
            original_profile: Some(OriginalProfile {
                real_name: "Test Raye".into(),
                icon_file: "/home/testr/.face".into(),
            }),
            last_sync: "2026-11-06T10:00:00Z".into(),
            last_error: String::new(),
            ..State::default()
        };
        s.keys.insert("appearance.accentColor".into(), Synced { rev: 7, hash: "abc".into() });
        s.save().expect("saved");

        let path = State::path();
        let text = std::fs::read_to_string(&path).expect("read back");

        // Only the owner, and no execute bit.
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "state.json is {mode:o}, not 0600");

        // No field of the keyring's `Secrets` may be a key of this file.
        for forbidden in ["access_token", "refresh_token", "device_key", "password", "secret"] {
            assert!(!text.contains(forbidden), "{forbidden} is in the state file:\n{text}");
        }
        // And what it does hold is only what signing out would throw away
        // anyway: a name, an address, switches, revisions and hashes.
        let back: State = serde_json::from_str(&text).unwrap();
        assert_eq!(back, s, "the file reads back as what was written");

        unsafe { std::env::remove_var("XDG_STATE_HOME") }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Signing out must leave nothing behind that names the account.
    #[test]
    fn signing_out_drops_the_address_and_the_revisions() {
        let mut s = State {
            email: "ana@example.com".into(),
            display_name: "Ana".into(),
            signed_in: true,
            settings_rev: 42,
            avatar_etag: "0123456789ab".into(),
            ..State::default()
        };
        s.keys.insert("appearance.accentColor".into(), Synced { rev: 7, hash: "abc".into() });
        s.sign_out();
        let text = serde_json::to_string(&s).unwrap();
        for gone in ["ana@example.com", "0123456789ab", "accentColor"] {
            assert!(!text.contains(gone), "{gone} survived signing out: {text}");
        }
        assert!(s.keys.is_empty() && s.settings_rev == 0);
    }

    fn tempdir(tag: &str) -> std::path::PathBuf {
        let p = std::env::temp_dir().join(format!("raye-account-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&p).unwrap();
        p
    }

    #[test]
    fn server_urls() {
        assert!(server_url_ok("https://account.rayelinux.com"));
        assert!(server_url_ok("http://127.0.0.1:8787"));
        assert!(!server_url_ok("http://192.168.50.213:8787"));
        assert!(!server_url_ok("ftp://x"));
    }
}
