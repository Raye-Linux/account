//! JSON bodies of the v1 API.

use serde::{Deserialize, Serialize};
use serde_json::Value;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TokenResponse {
    pub access_token: String,
    pub token_type: String,
    pub expires_in: i64,
    pub refresh_token: String,
    pub device_id: Uuid,
}

/// Sent with the authorization code: who this device is, and the public half
/// of the key it will sign refreshes with.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceInfo {
    pub name: String,
    pub model: String,
    pub raye_version: String,
    /// Ed25519 public key, base64url.
    pub public_key: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Me {
    pub id: Uuid,
    pub email: String,
    pub email_verified: bool,
    /// Whether signing in on a new PC will ask for a code as well.
    #[serde(default)]
    pub totp_enabled: bool,
    /// Whether signing in asks for a code sent by email.
    #[serde(default)]
    pub email_code_signin: bool,
    pub display_name: String,
    /// Changes whenever the picture changes; absent when there is none.
    pub avatar_etag: Option<String>,
    pub created_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Device {
    pub id: Uuid,
    pub name: String,
    pub model: String,
    pub raye_version: String,
    pub created_at: String,
    pub last_seen_at: String,
    pub this_device: bool,
    pub app_count: i64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingItem {
    pub key: String,
    /// `None` means the setting was removed.
    pub value: Option<Value>,
    /// Server revision of this key.
    pub rev: i64,
    /// When the change was made on the device that made it (RFC 3339).
    pub modified_at: String,
    pub device_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsPage {
    /// The account's highest revision. Pass it back as `since` next time.
    pub rev: i64,
    pub items: Vec<SettingItem>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingChange {
    pub key: String,
    pub value: Option<Value>,
    /// The revision of this key the device last saw (0 if never).
    pub base_rev: i64,
    pub modified_at: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SettingsPush {
    pub changes: Vec<SettingChange>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PushOutcome {
    /// Stored as sent.
    Accepted,
    /// Another device changed this key after the base revision and its change
    /// is newer: the server kept it. `item` carries the value to apply locally.
    Superseded,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResult {
    pub key: String,
    pub outcome: PushOutcome,
    pub item: SettingItem,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PushResponse {
    pub rev: i64,
    pub results: Vec<PushResult>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LibraryApp {
    pub app_id: String,
    pub source: String,
    pub added_at: String,
    /// Devices of this account that have it installed now.
    pub installed_on: Vec<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApps {
    pub apps: Vec<InstalledApp>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InstalledApp {
    pub app_id: String,
    pub source: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiError {
    pub error: String,
    pub message: String,
}
