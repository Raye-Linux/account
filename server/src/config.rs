use std::net::SocketAddr;

use crate::mail::Mailer;
use crate::otp::SecretKey;

#[derive(Clone, Debug)]
pub struct Config {
    pub database_url: String,
    pub listen: SocketAddr,
    /// Behind the Cloudflare tunnel the peer is always the tunnel connector;
    /// then the client address comes from CF-Connecting-IP. Off by default:
    /// trusting that header without a proxy in front lets anyone pick their
    /// own address and walk around the rate limits.
    pub trust_proxy: bool,
    /// Pages are served over https in production; this only drops the
    /// "upgrade-insecure-requests" hint for local tests over plain http.
    pub https: bool,
    pub heavy_jobs: usize,
    pub access_ttl_secs: i64,
    pub refresh_ttl_secs: i64,
    pub max_devices: i64,
    /// Where this server answers from the outside: what the links in mail
    /// point at. https, or loopback for local work -- a link that sent a
    /// password-reset token over plain http would hand it to the network.
    pub base_url: String,
    pub mail_from: String,
    pub mailer: Mailer,
    /// Seals the TOTP secrets. None means two-step verification is refused
    /// rather than run on a key that dies with the process.
    pub totp_key: Option<SecretKey>,
}

/// Plain http only on the loopback, the same rule the desktop client applies
/// to the server address it is given.
pub fn base_url_ok(url: &str) -> bool {
    (url.starts_with("https://") && url.len() > 8)
        || url.starts_with("http://127.0.0.1:")
        || url.starts_with("http://localhost:")
}

impl Config {
    pub fn from_env() -> Result<Config, String> {
        let var = |k: &str| std::env::var(k).ok().filter(|v| !v.is_empty());
        let database_url = var("RAYE_ACCOUNT_DATABASE_URL")
            .ok_or("RAYE_ACCOUNT_DATABASE_URL is not set")?;
        let listen = var("RAYE_ACCOUNT_LISTEN")
            .unwrap_or_else(|| "127.0.0.1:8787".into())
            .parse()
            .map_err(|e| format!("RAYE_ACCOUNT_LISTEN: {e}"))?;
        let flag = |k: &str| matches!(var(k).as_deref(), Some("1" | "true" | "yes"));
        let base_url = match var("RAYE_ACCOUNT_BASE_URL") {
            Some(u) => {
                let u = u.trim_end_matches('/').to_owned();
                if !base_url_ok(&u) {
                    return Err(format!("RAYE_ACCOUNT_BASE_URL: {u} is not https (or loopback)"));
                }
                u
            }
            None => return Err("RAYE_ACCOUNT_BASE_URL is not set: mail would carry no link".into()),
        };
        let mailer = match var("RAYE_ACCOUNT_SENDMAIL") {
            Some(p) => Mailer::Sendmail(p.into()),
            None => {
                tracing::warn!(
                    "RAYE_ACCOUNT_SENDMAIL is not set: no mail is sent. \
                     Address confirmation and password reset will not reach anyone."
                );
                Mailer::Outbox
            }
        };
        let totp_key = match var("RAYE_ACCOUNT_TOTP_KEY") {
            Some(k) => match SecretKey::parse(&k) {
                Some(k) => Some(k),
                None => return Err("RAYE_ACCOUNT_TOTP_KEY: want 32 bytes as base64url".into()),
            },
            None => {
                tracing::warn!(
                    "RAYE_ACCOUNT_TOTP_KEY is not set: two-step verification is refused. \
                     A key invented at startup would stop opening at the next restart."
                );
                None
            }
        };
        Ok(Config {
            database_url,
            listen,
            trust_proxy: flag("RAYE_ACCOUNT_TRUST_PROXY"),
            https: flag("RAYE_ACCOUNT_HTTPS"),
            base_url,
            mail_from: var("RAYE_ACCOUNT_MAIL_FROM").unwrap_or_else(|| "bonjour@rayelinux.com".into()),
            mailer,
            totp_key,
            ..Config::defaults(String::new())
        })
    }

    pub fn defaults(database_url: String) -> Config {
        Config {
            database_url,
            listen: "127.0.0.1:8787".parse().unwrap(),
            trust_proxy: false,
            https: false,
            heavy_jobs: 2,
            access_ttl_secs: 15 * 60,
            refresh_ttl_secs: 60 * 24 * 3600,
            max_devices: 20,
            base_url: "http://127.0.0.1:8787".into(),
            mail_from: "bonjour@rayelinux.com".into(),
            mailer: Mailer::Outbox,
            // Tests and local work get a key; production must set one.
            totp_key: Some(SecretKey::random()),
        }
    }

    #[cfg(test)]
    pub fn test() -> Config {
        Config::defaults(String::new())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn links_must_not_go_out_in_the_clear() {
        assert!(base_url_ok("https://account.rayelinux.com"));
        assert!(base_url_ok("http://127.0.0.1:8787"));
        assert!(base_url_ok("http://localhost:8787"));
        assert!(!base_url_ok("http://account.rayelinux.com"), "a reset token over plain http");
        assert!(!base_url_ok("http://192.168.50.213:8787"), "the LAN is not loopback");
        assert!(!base_url_ok("https://"), "no host");
        assert!(!base_url_ok("account.rayelinux.com"), "no scheme");
    }

    /// `Config` derives Debug and carries the key that opens every TOTP
    /// secret. One `tracing::debug!(?config)` would put it in a log file.
    #[test]
    fn the_config_debug_does_not_print_the_totp_key() {
        let mut c = Config::defaults("postgres://x".into());
        c.totp_key = Some(SecretKey([0xAB; 32]));
        let shown = format!("{c:?}");
        assert!(shown.contains("SecretKey(<redacted>)"), "{shown}");
        // Neither the array Debug would print nor a hex dump of it. ("ab"
        // alone is no good as a needle: "database_url" contains it.)
        assert!(!shown.contains("171, 171"), "the bytes themselves: {shown}");
        assert!(!shown.contains("abababab"), "nor in hex: {shown}");
    }
}
