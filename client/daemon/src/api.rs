//! The account API over HTTPS. Blocking calls: they run on tokio's
//! blocking threads, never on the thread that answers D-Bus.

use std::io::Read;
use std::time::Duration;

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::Signer;
use raye_account_common::api::TokenResponse;
use raye_account_common::{refresh_proof_message, DESKTOP_CLIENT_ID};
use serde::de::DeserializeOwned;
use serde_json::Value;

use crate::keyring::Secrets;

#[derive(Debug)]
pub enum ApiError {
    /// The server no longer knows this device: sign in again.
    SignedOut,
    Offline(String),
    Server(u16, String),
}

impl std::fmt::Display for ApiError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ApiError::SignedOut => f.write_str("signed out"),
            ApiError::Offline(e) => write!(f, "can't reach the account server: {e}"),
            ApiError::Server(code, m) => write!(f, "account server said {code}: {m}"),
        }
    }
}

pub type Result<T> = std::result::Result<T, ApiError>;

pub fn agent() -> ureq::Agent {
    ureq::AgentBuilder::new()
        .timeout_connect(Duration::from_secs(10))
        .timeout(Duration::from_secs(30))
        // Nothing in the API redirects; following one could carry the token elsewhere.
        .redirects(0)
        .user_agent(concat!("raye-accountd/", env!("CARGO_PKG_VERSION")))
        .build()
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn map_err(e: ureq::Error) -> ApiError {
    match e {
        ureq::Error::Status(401, _) => ApiError::SignedOut,
        ureq::Error::Status(code, r) => {
            let msg = r
                .into_json::<Value>()
                .ok()
                .and_then(|v| v["message"].as_str().map(str::to_owned))
                .unwrap_or_default();
            if code == 400 && msg == "sign in again" {
                ApiError::SignedOut
            } else {
                ApiError::Server(code, msg)
            }
        }
        ureq::Error::Transport(t) => ApiError::Offline(t.to_string()),
    }
}

pub fn token_from(resp: TokenResponse, device_key: String) -> Secrets {
    Secrets {
        access_expires: now() + resp.expires_in - 30,
        access_token: resp.access_token,
        refresh_token: resp.refresh_token,
        device_id: resp.device_id,
        device_key,
    }
}

pub struct Client {
    pub server: String,
    pub secrets: Secrets,
    /// Set when a refresh replaced the tokens: the caller writes them back to the keyring.
    pub refreshed: bool,
    agent: ureq::Agent,
}

pub enum Body<'a> {
    None,
    Json(&'a Value),
    Png(&'a [u8]),
}

impl Client {
    pub fn new(server: String, secrets: Secrets) -> Client {
        Client { server, secrets, refreshed: false, agent: agent() }
    }

    pub fn refresh(&mut self) -> Result<()> {
        let key = self.secrets.signing_key().ok_or(ApiError::SignedOut)?;
        let ts = now();
        let device = self.secrets.device_id.to_string();
        let sig = key.sign(&refresh_proof_message(&self.secrets.device_id, ts, &self.secrets.refresh_token));
        let resp: TokenResponse = self
            .agent
            .post(&format!("{}/v1/oauth/token", self.server))
            .send_form(&[
                ("grant_type", "refresh_token"),
                ("client_id", DESKTOP_CLIENT_ID),
                ("refresh_token", &self.secrets.refresh_token),
                ("device_id", &device),
                ("proof_ts", &ts.to_string()),
                ("proof", &URL_SAFE_NO_PAD.encode(sig.to_bytes())),
            ])
            .map_err(map_err)?
            .into_json()
            .map_err(|e| ApiError::Offline(e.to_string()))?;
        self.secrets = token_from(resp, self.secrets.device_key.clone());
        self.refreshed = true;
        Ok(())
    }

    fn send(&self, method: &str, path: &str, body: &Body, etag: Option<&str>) -> std::result::Result<ureq::Response, ureq::Error> {
        let mut req = self
            .agent
            .request(method, &format!("{}{}", self.server, path))
            .set("Authorization", &format!("Bearer {}", self.secrets.access_token));
        if let Some(e) = etag {
            req = req.set("If-None-Match", &format!("\"{e}\""));
        }
        match body {
            Body::None => req.call(),
            Body::Json(v) => req.send_json(*v),
            Body::Png(b) => req.set("Content-Type", "image/png").send_bytes(b),
        }
    }

    /// One request, refreshing the access token first when it is due, and
    /// once more if the server says it is no longer good.
    pub fn request(&mut self, method: &str, path: &str, body: Body, etag: Option<&str>) -> Result<ureq::Response> {
        if self.secrets.access_expires <= now() {
            self.refresh()?;
        }
        match self.send(method, path, &body, etag) {
            Err(ureq::Error::Status(401, _)) => {
                self.refresh()?;
                self.send(method, path, &body, etag).map_err(map_err)
            }
            other => other.map_err(map_err),
        }
    }

    pub fn json<T: DeserializeOwned>(&mut self, method: &str, path: &str, body: Option<&Value>) -> Result<T> {
        let body = body.map(Body::Json).unwrap_or(Body::None);
        self.request(method, path, body, None)?
            .into_json()
            .map_err(|e| ApiError::Offline(e.to_string()))
    }

    pub fn no_content(&mut self, method: &str, path: &str, body: Option<&Value>) -> Result<()> {
        let body = body.map(Body::Json).unwrap_or(Body::None);
        self.request(method, path, body, None).map(|_| ())
    }

    /// The account picture, or None when it has not changed since `etag`
    /// (or there is none).
    pub fn avatar(&mut self, etag: &str) -> Result<Option<Vec<u8>>> {
        let etag = (!etag.is_empty()).then_some(etag);
        match self.request("GET", "/v1/me/avatar", Body::None, etag) {
            Ok(r) if r.status() == 304 => Ok(None),
            Ok(r) => {
                let mut buf = Vec::new();
                r.into_reader()
                    .take(1024 * 1024)
                    .read_to_end(&mut buf)
                    .map_err(|e| ApiError::Offline(e.to_string()))?;
                Ok(Some(buf))
            }
            Err(ApiError::Server(404, _)) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
