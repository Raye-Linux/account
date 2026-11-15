//! Turning two-step verification on and off, and the check the sign-in page
//! runs. The arithmetic lives in `otp.rs`; this file is where it meets the
//! database, and the two rules it has to carry across are:
//!
//!   * the accepted step is **written back** (`totp_last_step`), which is
//!     what makes a code single-use. Verifying without storing the step
//!     leaves every code replayable for the width of the window;
//!   * the secret is **never** returned once enrolment is confirmed. It is
//!     handed out once, while the user is adding it to their phone.

use axum::extract::State;
use axum::Json;
use serde::{Deserialize, Serialize};
use serde_json::json;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::oauth::check_password;
use crate::otp;
use crate::tokens::AuthDevice;
use crate::{ratelimit, Shared};
use raye_account_common::api::Me;

#[derive(Serialize)]
pub struct Enrolment {
    /// For typing into an app by hand.
    pub secret: String,
    /// For the QR code.
    pub otpauth_uri: String,
}

/// The server key, or a refusal.
///
/// Without `RAYE_ACCOUNT_TOTP_KEY` enrolment is refused rather than done with
/// a key invented at startup: a second factor that stops working at the next
/// restart would lock people out of their own accounts, and they would only
/// find out when they needed it.
fn key(app: &Shared) -> Result<&otp::SecretKey> {
    app.config.totp_key.as_ref().ok_or(Error::Unsupported("two-step verification is not configured on this server"))
}

/// `POST /v1/me/totp/start`: a fresh secret, not yet in force.
pub async fn start(State(app): State<Shared>, auth: AuthDevice) -> Result<Json<Enrolment>> {
    let key = key(&app)?;
    let (email, enabled): (String, bool) = sqlx::query_as("SELECT email, totp_enabled FROM accounts WHERE id = $1")
        .bind(auth.account_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(Error::Unauthorized)?;
    if enabled {
        return Err(Error::BadRequest("two-step verification is already on; turn it off first"));
    }
    let secret = otp::new_secret();
    sqlx::query("UPDATE accounts SET totp_secret = $2, updated_at = now() WHERE id = $1")
        .bind(auth.account_id)
        .bind(otp::seal(key, &secret))
        .execute(&app.db)
        .await?;
    Ok(Json(Enrolment { secret: otp::base32(&secret), otpauth_uri: otp::otpauth_uri(&secret, &email) }))
}

#[derive(Deserialize)]
pub struct CodeBody {
    code: String,
}

/// `POST /v1/me/totp/confirm`: proves the phone has the secret, turns it on,
/// and hands over the ten recovery codes -- the only time they are shown.
pub async fn confirm(
    State(app): State<Shared>,
    auth: AuthDevice,
    Json(b): Json<CodeBody>,
) -> Result<Json<serde_json::Value>> {
    let key = key(&app)?;
    if !app.limits.take("totp-try", &auth.account_id.to_string(), ratelimit::TOTP_ACCOUNT) {
        return Err(Error::TooMany);
    }
    let mut tx = app.db.begin().await?;
    let row: Option<(Option<Vec<u8>>, bool, i64)> =
        sqlx::query_as("SELECT totp_secret, totp_enabled, totp_last_step FROM accounts WHERE id = $1 FOR UPDATE")
            .bind(auth.account_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((Some(sealed), enabled, last_step)) = row else {
        return Err(Error::BadRequest("start two-step verification first"));
    };
    if enabled {
        return Err(Error::BadRequest("two-step verification is already on"));
    }
    let secret = otp::open(key, &sealed).ok_or_else(|| {
        // The stored secret will not open: the server key changed. Say so in
        // the log, where it can be acted on, not to the user.
        Error::Internal("the stored TOTP secret does not open with the current server key".into())
    })?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    let Some(step) = otp::verify(&secret, &b.code, now, last_step) else {
        return Err(Error::BadRequest("that code is not right"));
    };
    sqlx::query(
        "UPDATE accounts SET totp_enabled = true, totp_confirmed_at = now(), totp_last_step = $2,
                updated_at = now() WHERE id = $1",
    )
    .bind(auth.account_id)
    .bind(step)
    .execute(&mut *tx)
    .await?;
    let codes = write_recovery_codes(&mut tx, auth.account_id).await?;
    tx.commit().await?;
    tracing::info!(account_id = %auth.account_id, "two-step verification turned on");
    Ok(Json(json!({ "recovery_codes": codes })))
}

#[derive(Deserialize)]
pub struct DisableBody {
    password: String,
}

/// `POST /v1/me/totp/disable`: needs the password again.
///
/// A stolen access token must not be able to take the second factor off --
/// that is the one thing the second factor is there to survive.
pub async fn disable(
    State(app): State<Shared>,
    auth: AuthDevice,
    Json(b): Json<DisableBody>,
) -> Result<Json<Me>> {
    let (stored,): (String,) = sqlx::query_as("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(auth.account_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(Error::Unauthorized)?;
    if !app.limits.take("totp-disable", &auth.account_id.to_string(), ratelimit::SIGN_IN_ACCOUNT) {
        return Err(Error::TooMany);
    }
    if !check_password(&app, b.password, stored).await? {
        return Err(Error::Unauthorized);
    }
    turn_off(&app, auth.account_id).await?;
    crate::me::get_me(State(app), auth).await
}

pub async fn turn_off(app: &Shared, account_id: Uuid) -> Result<()> {
    let mut tx = app.db.begin().await?;
    sqlx::query(
        "UPDATE accounts SET totp_enabled = false, totp_secret = NULL, totp_confirmed_at = NULL,
                totp_last_step = 0, updated_at = now() WHERE id = $1",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id = $1").bind(account_id).execute(&mut *tx).await?;
    tx.commit().await?;
    tracing::info!(%account_id, "two-step verification turned off");
    Ok(())
}

async fn write_recovery_codes(conn: &mut sqlx::PgConnection, account_id: Uuid) -> Result<Vec<String>> {
    sqlx::query("DELETE FROM totp_recovery_codes WHERE account_id = $1").bind(account_id).execute(&mut *conn).await?;
    let mut codes = Vec::with_capacity(otp::RECOVERY_CODES);
    for _ in 0..otp::RECOVERY_CODES {
        let code = otp::new_recovery_code();
        sqlx::query("INSERT INTO totp_recovery_codes (code_hash, account_id) VALUES ($1, $2)")
            .bind(otp::recovery_hash(&code))
            .bind(account_id)
            .execute(&mut *conn)
            .await?;
        codes.push(code);
    }
    Ok(codes)
}

/// Ten new recovery codes; the old ones stop working.
pub async fn replace_recovery_codes(app: &Shared, account_id: Uuid) -> Result<Vec<String>> {
    if !is_on(app, account_id).await? {
        return Err(Error::BadRequest("two-step verification is off"));
    }
    let mut tx = app.db.begin().await?;
    let codes = write_recovery_codes(&mut tx, account_id).await?;
    tx.commit().await?;
    Ok(codes)
}

/// Wrong codes in an hour, on every path together, before the code step is
/// closed for the rest of that hour.
pub const MAX_FAILURES_PER_HOUR: i32 = 10;

/// What the sign-in page runs after the password: a TOTP code, or one of the
/// recovery codes. Either way the thing used is spent before this returns.
///
/// The caller rate-limits: six digits is a million, and a million is small.
pub async fn check_second_factor(app: &Shared, account_id: Uuid, code: &str) -> Result<bool> {
    let key = key(app)?;
    let mut tx = app.db.begin().await?;
    let row: Option<(Option<Vec<u8>>, bool, i64, i32, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT totp_secret, totp_enabled, totp_last_step, totp_failures, totp_failed_at FROM accounts WHERE id = $1 FOR UPDATE",
    )
    .bind(account_id)
    .fetch_optional(&mut *tx)
    .await?;
    let Some((sealed, true, last_step, failures, failed_at)) = row else {
        return Ok(false);
    };
    let recent = failed_at.is_some_and(|t| t > OffsetDateTime::now_utc() - time::Duration::hours(1));
    if recent && failures >= MAX_FAILURES_PER_HOUR {
        return Ok(false);
    }
    if let Some(secret) = sealed.as_deref().and_then(|s| otp::open(key, s)) {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if let Some(step) = otp::verify(&secret, code, now, last_step) {
            // Writing the step is what spends the code. Under the same row
            // lock as the read, so two tries with one code cannot both win.
            sqlx::query("UPDATE accounts SET totp_last_step = $2, totp_failures = 0, totp_failed_at = NULL WHERE id = $1")
                .bind(account_id)
                .bind(step)
                .execute(&mut *tx)
                .await?;
            tx.commit().await?;
            return Ok(true);
        }
    }
    // Not a TOTP code: it may be one of the ten recovery codes. Looked up by
    // hash, and the UPDATE only touches a row that is still unused, so the
    // database decides single-use rather than a read-then-write race.
    let spent = sqlx::query(
        "UPDATE totp_recovery_codes SET used_at = now()
         WHERE code_hash = $1 AND account_id = $2 AND used_at IS NULL",
    )
    .bind(otp::recovery_hash(code))
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    if spent.rows_affected() == 1 {
        tx.commit().await?;
        tracing::warn!(%account_id, "signed in with a recovery code");
        return Ok(true);
    }
    sqlx::query(
        "UPDATE accounts SET totp_failures = CASE WHEN $2 THEN totp_failures + 1 ELSE 1 END,
                totp_failed_at = now() WHERE id = $1",
    )
    .bind(account_id)
    .bind(recent)
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(false)
}

/// Whether this account will be asked for a second factor.
pub async fn is_on(app: &Shared, account_id: Uuid) -> Result<bool> {
    let (on,): (bool,) = sqlx::query_as("SELECT totp_enabled FROM accounts WHERE id = $1")
        .bind(account_id)
        .fetch_one(&app.db)
        .await?;
    Ok(on)
}
