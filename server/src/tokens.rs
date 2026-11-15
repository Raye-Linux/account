use std::net::{IpAddr, SocketAddr};

use axum::extract::{ConnectInfo, FromRequestParts};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap};
use sha2::{Digest, Sha256};
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::{ratelimit, Shared};
use raye_account_common::random_token;

pub fn hash(token: &str) -> Vec<u8> {
    Sha256::digest(token.as_bytes()).to_vec()
}

pub struct Pair {
    pub access: String,
    pub refresh: String,
}

pub async fn issue(
    conn: &mut PgConnection,
    state: &Shared,
    account_id: Uuid,
    device_id: Uuid,
) -> Result<Pair> {
    let now = OffsetDateTime::now_utc();
    let pair = Pair { access: random_token(), refresh: random_token() };
    sqlx::query("DELETE FROM access_tokens WHERE device_id = $1 AND expires_at < $2")
        .bind(device_id)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    sqlx::query("DELETE FROM refresh_tokens WHERE device_id = $1 AND expires_at < $2")
        .bind(device_id)
        .bind(now)
        .execute(&mut *conn)
        .await?;
    sqlx::query(
        "INSERT INTO access_tokens (token_hash, device_id, account_id, expires_at) VALUES ($1, $2, $3, $4)",
    )
    .bind(hash(&pair.access))
    .bind(device_id)
    .bind(account_id)
    .bind(now + Duration::seconds(state.config.access_ttl_secs))
    .execute(&mut *conn)
    .await?;
    sqlx::query("INSERT INTO refresh_tokens (token_hash, device_id, expires_at) VALUES ($1, $2, $3)")
        .bind(hash(&pair.refresh))
        .bind(device_id)
        .bind(now + Duration::seconds(state.config.refresh_ttl_secs))
        .execute(&mut *conn)
        .await?;
    Ok(pair)
}

/// The device behind a valid access token.
#[derive(Clone, Copy, Debug)]
pub struct AuthDevice {
    pub account_id: Uuid,
    pub device_id: Uuid,
}

impl FromRequestParts<Shared> for AuthDevice {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self> {
        let token = bearer(&parts.headers).ok_or(Error::Unauthorized)?;
        let row: Option<(Uuid, Uuid)> = sqlx::query_as(
            "SELECT t.account_id, t.device_id FROM access_tokens t JOIN accounts a ON a.id = t.account_id \
             WHERE t.token_hash = $1 AND t.expires_at > now() AND a.email_verified",
        )
        .bind(hash(token))
        .fetch_optional(&state.db)
        .await?;
        let (account_id, device_id) = row.ok_or(Error::Unauthorized)?;
        if !state.limits.take("api", &device_id.to_string(), ratelimit::API_DEVICE) {
            return Err(Error::TooMany);
        }
        // "Last seen" in Your devices; written at most once a minute per device.
        sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1 AND last_seen_at < now() - interval '1 minute'")
            .bind(device_id)
            .execute(&state.db)
            .await?;
        Ok(AuthDevice { account_id, device_id })
    }
}

fn bearer(headers: &HeaderMap) -> Option<&str> {
    let v = headers.get(header::AUTHORIZATION)?.to_str().ok()?;
    let (scheme, token) = v.split_once(' ')?;
    (scheme.eq_ignore_ascii_case("bearer") && !token.is_empty()).then_some(token.trim())
}

/// Address used for rate limits. An IPv6 client is its /64: one home or one
/// rented server owns a whole /64, so a full address would hand it 2^64 buckets.
pub struct ClientIp(pub IpAddr);

pub fn limit_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V4(_) => ip,
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6(std::net::Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
            }
        },
    }
}

impl FromRequestParts<Shared> for ClientIp {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, state: &Shared) -> Result<Self> {
        if state.config.trust_proxy {
            if let Some(ip) = parts
                .headers
                .get("cf-connecting-ip")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.trim().parse().ok())
            {
                return Ok(ClientIp(limit_key(ip)));
            }
        }
        let ConnectInfo(addr) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(|_| Error::Internal("no peer address".into()))?;
        Ok(ClientIp(limit_key(addr.ip())))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn one_ipv6_network_is_one_client() {
        let a: IpAddr = "2001:db8:1:2:aaaa::1".parse().unwrap();
        let b: IpAddr = "2001:db8:1:2:ffff:1:2:3".parse().unwrap();
        let other: IpAddr = "2001:db8:1:3::1".parse().unwrap();
        assert_eq!(limit_key(a), limit_key(b));
        assert_ne!(limit_key(a), limit_key(other));
        let v4: IpAddr = "203.0.113.7".parse().unwrap();
        assert_eq!(limit_key(v4), v4);
        let mapped: IpAddr = "::ffff:203.0.113.7".parse().unwrap();
        assert_eq!(limit_key(mapped), v4);
    }

    #[test]
    fn reads_bearer() {
        let mut h = HeaderMap::new();
        assert_eq!(bearer(&h), None);
        h.insert(header::AUTHORIZATION, "Bearer abc".parse().unwrap());
        assert_eq!(bearer(&h), Some("abc"));
        h.insert(header::AUTHORIZATION, "Basic abc".parse().unwrap());
        assert_eq!(bearer(&h), None);
        h.insert(header::AUTHORIZATION, "Bearer ".parse().unwrap());
        assert_eq!(bearer(&h), None);
    }
}
