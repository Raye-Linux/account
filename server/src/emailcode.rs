//! The code sent by email at sign-in.
//!
//! On by default for every account without an authenticator app. One live
//! code per account: asking again replaces it. Six digits, ten minutes,
//! five wrong tries and it is gone. Kept as an HMAC under a key only this
//! process holds, so a copy of the table is not a list of codes to try.

use axum::extract::State;
use axum::Json;
use hmac::{Hmac, Mac};
use rand::Rng;
use serde::Deserialize;
use sha2::Sha256;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::mail;
use crate::oauth::check_password;
use crate::tokens::AuthDevice;
use crate::{ratelimit, Shared};
use raye_account_common::api::Me;

pub const CODE_TTL_MINUTES: i64 = 10;
pub const MAX_TRIES: i32 = 5;
/// Wrong codes in an hour, whatever code they were aimed at, before the
/// code step is closed for the rest of that hour.
pub const MAX_FAILURES_PER_HOUR: i32 = 10;

fn digest(app: &Shared, account_id: &Uuid, code: &str) -> Vec<u8> {
    let mut m = <Hmac<Sha256>>::new_from_slice(&app.form_key).expect("any key length");
    m.update(format!("email-code\n{account_id}\n{code}").as_bytes());
    m.finalize().into_bytes().to_vec()
}

/// Whether sign-in asks this account for a code by email.
pub async fn is_on(app: &Shared, account_id: Uuid) -> Result<bool> {
    let (on,): (bool,) = sqlx::query_as("SELECT email_code_signin FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(&app.db)
        .await?;
    Ok(on)
}

/// Makes a new code and mails it. `false` when the account asked too often:
/// the old code, if any, stays good.
pub async fn send(app: &Shared, account_id: Uuid) -> Result<bool> {
    let key = account_id.to_string();
    if !app.limits.take("email-code-send", &key, ratelimit::EMAIL_CODE_SEND)
        || !app.limits.take("email-code-day", &key, ratelimit::EMAIL_CODE_DAY)
    {
        return Ok(false);
    }
    let (email,): (String,) = sqlx::query_as("SELECT email FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(&app.db)
        .await?;
    let code = format!("{:06}", rand::rngs::OsRng.gen_range(0..1_000_000u32));
    // A code less than a minute old stays: someone who has the password
    // must not be able to keep replacing the owner's code as it arrives.
    let written = sqlx::query(
        "INSERT INTO signin_codes (account_id, code_hash, expires_at, tries) VALUES ($1, $2, $3, 0)
         ON CONFLICT (account_id) DO UPDATE SET code_hash = $2, expires_at = $3, tries = 0, created_at = now()
         WHERE signin_codes.created_at < now() - interval '60 seconds' OR signin_codes.expires_at < now()",
    )
    .bind(account_id)
    .bind(digest(app, &account_id, &code))
    .bind(OffsetDateTime::now_utc() + Duration::minutes(CODE_TTL_MINUTES))
    .execute(&app.db)
    .await?;
    if written.rows_affected() == 1 {
        app.post(&email, mail::sign_in_code_letter(&code));
    }
    Ok(true)
}

/// Spends the code if it is the right one. A wrong one counts against it.
pub async fn check(app: &Shared, account_id: Uuid, code: &str) -> Result<bool> {
    let code: String = code.chars().filter(|c| !c.is_whitespace()).collect();
    if code.len() != 6 || !code.bytes().all(|b| b.is_ascii_digit()) {
        return Ok(false);
    }
    let mut tx = app.db.begin().await?;
    let (failures, failed_at): (i32, Option<OffsetDateTime>) = sqlx::query_as(
        "SELECT email_code_failures, email_code_failed_at FROM accounts WHERE id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_one(&mut *tx)
    .await?;
    let recent = failed_at.is_some_and(|t| t > OffsetDateTime::now_utc() - Duration::hours(1));
    if recent && failures >= MAX_FAILURES_PER_HOUR {
        return Ok(false);
    }
    let row: Option<(Vec<u8>, OffsetDateTime, i32)> = sqlx::query_as(
        "SELECT code_hash, expires_at, tries FROM signin_codes WHERE account_id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((stored, expires_at, tries)) = row else {
        return Ok(false);
    };
    if expires_at < OffsetDateTime::now_utc() || tries >= MAX_TRIES {
        sqlx::query("DELETE FROM signin_codes WHERE account_id = $1").bind(account_id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Ok(false);
    }
    if raye_account_common::ct_eq(&stored, &digest(app, &account_id, &code)) {
        sqlx::query("DELETE FROM signin_codes WHERE account_id = $1").bind(account_id).execute(&mut *tx).await?;
        sqlx::query("UPDATE accounts SET email_code_failures = 0, email_code_failed_at = NULL WHERE id = $1")
            .bind(account_id)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
        return Ok(true);
    }
    sqlx::query("UPDATE signin_codes SET tries = tries + 1 WHERE account_id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "UPDATE accounts SET email_code_failures = CASE WHEN $2 THEN email_code_failures + 1 ELSE 1 END,
                email_code_failed_at = now() WHERE id = $1",
    )
    .bind(account_id)
    .bind(recent)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(false)
}

#[derive(Deserialize)]
pub struct SwitchBody {
    enabled: bool,
    #[serde(default)]
    password: String,
}

/// `POST /v1/me/email-code`: turning it on is free, turning it off needs the
/// password again, like taking two-step verification off.
pub async fn switch(State(app): State<Shared>, auth: AuthDevice, Json(b): Json<SwitchBody>) -> Result<Json<Me>> {
    if !b.enabled {
        let (stored,): (String,) = sqlx::query_as("SELECT password_hash FROM accounts WHERE id = $1")
            .bind(auth.account_id)
            .fetch_optional(&app.db)
            .await?
            .ok_or(Error::Unauthorized)?;
        if !app.limits.has("email-code-off", &auth.account_id.to_string(), ratelimit::SIGN_IN_ACCOUNT) {
            return Err(Error::TooMany);
        }
        if !check_password(&app, b.password, stored).await? {
            app.limits.take("email-code-off", &auth.account_id.to_string(), ratelimit::SIGN_IN_ACCOUNT);
            return Err(Error::Unauthorized);
        }
    }
    set(&app, auth.account_id, b.enabled).await?;
    crate::me::get_me(State(app), auth).await
}

pub async fn set(app: &Shared, account_id: Uuid, enabled: bool) -> Result<()> {
    sqlx::query("UPDATE accounts SET email_code_signin = $2, updated_at = now() WHERE id = $1")
        .bind(account_id)
        .bind(enabled)
        .execute(&app.db)
        .await?;
    tracing::info!(%account_id, enabled, "sign-in code by email switched");
    Ok(())
}
