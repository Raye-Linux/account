//! Confirming an address, and resetting a forgotten password.
//!
//! Both are the same shape, and the shape is the security:
//!
//!   * the token is 32 random bytes; the row is keyed by its SHA-256, so what
//!     the user holds is never what the database holds, and a lookup is an
//!     index probe on the hash of what was presented -- never a comparison
//!     against a stored secret;
//!   * it expires (24 h to confirm an address, 30 min to reset a password);
//!   * it is spent once. `used_at` is set rather than the row deleted, so a
//!     link that comes back can be refused *and logged* instead of looking
//!     like a link that never existed;
//!   * it belongs to one account, and the account comes from the row -- never
//!     from the request. Presenting someone else's token while signed in as
//!     yourself is refused, not applied to whoever asked.
//!
//! A reset link is the shortest road into an account that exists, so the
//! answer to "please reset ana@example.com" is the same page, at the same
//! cost, whether that address has an account, has no account, or has one
//! whose address was never confirmed.

use axum::extract::{Query, State};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde::Deserialize;
use sqlx::PgConnection;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::mail;
use crate::oauth::{normalize_email, password_ok};
use crate::pages::{self, Lang, Msg};
use crate::tokens::{self, AuthDevice, ClientIp};
use crate::{ratelimit, Shared};
use raye_account_common::{api::Me, random_token};

const VERIFY_TTL_HOURS: i64 = 24;
const RESET_TTL_MINUTES: i64 = 30;

/// Why a token was refused. The caller turns this into one message for the
/// user -- the distinctions are for the log, not for whoever is trying.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Refused {
    Unknown,
    Expired,
    AlreadyUsed,
    OtherAccount,
    AddressChanged,
    /// A sign-up link opened after someone else confirmed the address.
    AddressTaken,
}

impl Refused {
    fn log(self, kind: &str) {
        match self {
            // Someone holding a spent link is worth a line: either a person
            // clicked twice, or a link leaked and is being tried.
            Refused::AlreadyUsed => tracing::warn!(%kind, "a spent {kind} token was presented again"),
            Refused::OtherAccount => tracing::warn!(%kind, "a {kind} token was presented by another account"),
            _ => tracing::debug!(%kind, ?self, "{kind} token refused"),
        }
    }
}

// ------------------------------------------------------------------- sign-ups

/// What `start_signup` did. The page shown is the same either way.
#[derive(Debug, PartialEq, Eq)]
pub enum SignUp {
    LetterSent,
    AlreadyRegistered,
    Throttled,
}

/// Keeps a sign-up until its address is confirmed, and writes the letter.
///
/// The password is hashed before the lookup, so a taken address costs the
/// same time as a free one. A taken address gets a letter too, pointing its
/// owner at the reset page; nothing on the screen tells the two apart.
pub async fn start_signup(app: &Shared, email: &str, password: &str, name: &str) -> Result<SignUp> {
    // Before the hash: this bucket is spent the same way for a free and a
    // taken address, so it says nothing, and a throttled try costs no Argon2.
    if !app.limits.take("signup-email", email, ratelimit::MAIL_PER_ACCOUNT) {
        return Ok(SignUp::Throttled);
    }
    let hash = crate::oauth::new_hash(app, password.to_owned()).await?;
    // An account whose address was never confirmed (made before sign-ups
    // needed it) does not hold the address either.
    let taken: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM accounts WHERE email = $1 AND email_verified")
        .bind(email)
        .fetch_optional(&app.db)
        .await?;
    if taken.is_some() {
        let link = format!("{}/reset-password", app.config.base_url);
        app.post(email, mail::already_registered_letter(&link));
        return Ok(SignUp::AlreadyRegistered);
    }
    let token = random_token();
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM pending_signups WHERE expires_at < now()").execute(&mut *tx).await?;
    sqlx::query(
        "INSERT INTO pending_signups (token_hash, email, password_hash, display_name, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tokens::hash(&token))
    .bind(email)
    .bind(hash)
    .bind(name)
    .bind(OffsetDateTime::now_utc() + Duration::hours(VERIFY_TTL_HOURS))
    .execute(&mut *tx)
    .await?;
    tx.commit().await?;
    app.post(email, mail::confirm_signup_letter(&app.link("/verify-email", &token)));
    Ok(SignUp::LetterSent)
}

/// Turns a confirmed sign-up into an account. `None` when the token is not
/// a sign-up's, so the caller can try the address-confirmation tokens.
pub async fn redeem_signup(db: &sqlx::PgPool, token: &str) -> Result<Option<std::result::Result<Uuid, Refused>>> {
    let mut tx = db.begin().await?;
    let row: Option<(String, String, String, OffsetDateTime)> = sqlx::query_as(
        "DELETE FROM pending_signups WHERE token_hash = $1 RETURNING email, password_hash, display_name, expires_at",
    )
    .bind(tokens::hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((email, password_hash, name, expires_at)) = row else {
        return Ok(None);
    };
    if expires_at < OffsetDateTime::now_utc() {
        tx.commit().await?;
        return Ok(Some(Err(Refused::Expired)));
    }
    sqlx::query("DELETE FROM accounts WHERE email = $1 AND NOT email_verified")
        .bind(&email)
        .execute(&mut *tx)
        .await?;
    let id = Uuid::new_v4();
    let done = sqlx::query(
        "INSERT INTO accounts (id, email, email_verified, password_hash, display_name)
         VALUES ($1, $2, true, $3, $4) ON CONFLICT (email) DO NOTHING",
    )
    .bind(id)
    .bind(&email)
    .bind(password_hash)
    .bind(name)
    .execute(&mut *tx)
    .await?;
    if done.rows_affected() == 0 {
        tx.commit().await?;
        return Ok(Some(Err(Refused::AddressTaken)));
    }
    // The address has its owner now: other waiting sign-ups for it are void.
    sqlx::query("DELETE FROM pending_signups WHERE email = $1").bind(&email).execute(&mut *tx).await?;
    tx.commit().await?;
    tracing::info!(account_id = %id, "account created");
    Ok(Some(Ok(id)))
}

// --------------------------------------------------------------- email tokens

async fn issue_email_token(conn: &mut PgConnection, account_id: Uuid, email: &str) -> Result<String> {
    let token = random_token();
    sqlx::query("DELETE FROM email_tokens WHERE expires_at < now()").execute(&mut *conn).await?;
    sqlx::query("INSERT INTO email_tokens (token_hash, account_id, email, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(tokens::hash(&token))
        .bind(account_id)
        .bind(email)
        .bind(OffsetDateTime::now_utc() + Duration::hours(VERIFY_TTL_HOURS))
        .execute(&mut *conn)
        .await?;
    Ok(token)
}

/// Spends a confirmation token and marks the address confirmed.
///
/// `expect_account` is `Some` when a signed-in session presents the token: the
/// token's own account must be that one. The public page passes `None`,
/// because the reader of the mail is not signed in -- the token is the proof.
pub async fn redeem_email_token(
    db: &sqlx::PgPool,
    token: &str,
    expect_account: Option<Uuid>,
) -> Result<std::result::Result<Uuid, Refused>> {
    let mut tx = db.begin().await?;
    // FOR UPDATE: two clicks at once must not both find it unused.
    let row: Option<(Uuid, String, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT account_id, email, expires_at, used_at FROM email_tokens WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(tokens::hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((account_id, email, expires_at, used_at)) = row else {
        return Ok(Err(Refused::Unknown));
    };
    if let Some(want) = expect_account {
        if want != account_id {
            return Ok(Err(Refused::OtherAccount));
        }
    }
    if used_at.is_some() {
        return Ok(Err(Refused::AlreadyUsed));
    }
    if expires_at < OffsetDateTime::now_utc() {
        return Ok(Err(Refused::Expired));
    }
    // The address is on the row, so a link mailed to the old address cannot
    // confirm an address that has changed since.
    let current: Option<(String,)> =
        sqlx::query_as("SELECT email FROM accounts WHERE id = $1").bind(account_id).fetch_optional(&mut *tx).await?;
    if current.map(|c| c.0).as_deref() != Some(email.as_str()) {
        return Ok(Err(Refused::AddressChanged));
    }
    sqlx::query("UPDATE email_tokens SET used_at = now() WHERE token_hash = $1")
        .bind(tokens::hash(token))
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET email_verified = true, updated_at = now() WHERE id = $1")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Ok(account_id))
}

/// `POST /v1/me/email/verify/send`: Settings asking for the letter again.
pub async fn send_verification(State(app): State<Shared>, auth: AuthDevice) -> Result<StatusCode> {
    let (email, verified): (String, bool) =
        sqlx::query_as("SELECT email, email_verified FROM accounts WHERE id = $1")
            .bind(auth.account_id)
            .fetch_optional(&app.db)
            .await?
            .ok_or(Error::Unauthorized)?;
    if verified {
        return Ok(StatusCode::NO_CONTENT);
    }
    if !app.limits.take("verify-send", &auth.account_id.to_string(), ratelimit::MAIL_PER_ACCOUNT) {
        return Err(Error::TooMany);
    }
    let mut conn = app.db.acquire().await?;
    let token = issue_email_token(&mut conn, auth.account_id, &email).await?;
    app.post(&email, mail::verify_email_letter(&app.link("/verify-email", &token)));
    Ok(StatusCode::NO_CONTENT)
}

#[derive(Deserialize)]
pub struct TokenBody {
    token: String,
}

/// `POST /v1/me/email/verify`: the desktop pasting the token it was given.
pub async fn verify_from_api(
    State(app): State<Shared>,
    auth: AuthDevice,
    Json(b): Json<TokenBody>,
) -> Result<Json<Me>> {
    match redeem_email_token(&app.db, &b.token, Some(auth.account_id)).await? {
        Ok(_) => crate::me::get_me(State(app), auth).await,
        Err(r) => {
            r.log("email");
            Err(Error::BadRequest("this confirmation link does not work any more"))
        }
    }
}

#[derive(Deserialize)]
pub struct TokenQuery {
    token: Option<String>,
}

/// `GET /verify-email?token=…`: shows a button, changes nothing.
///
/// Confirming on the GET would let a mail scanner that fetches links -- which
/// many do -- spend the token before the person ever sees it.
pub async fn verify_page(lang: Lang, State(app): State<Shared>, Query(q): Query<TokenQuery>) -> Response {
    match q.token.filter(|t| token_shaped(t)) {
        Some(t) => pages::confirm_button(&app, lang, &t),
        None => pages::notice(&app, lang, Msg::VerifyBad, StatusCode::BAD_REQUEST),
    }
}

/// `POST /verify-email`: the button.
pub async fn verify_submit(
    lang: Lang,
    State(app): State<Shared>,
    axum::Form(f): axum::Form<TokenBody>,
) -> Response {
    if !token_shaped(&f.token) {
        return pages::notice(&app, lang, Msg::VerifyBad, StatusCode::BAD_REQUEST);
    }
    match redeem_signup(&app.db, &f.token).await {
        Ok(Some(Ok(_))) => return pages::notice(&app, lang, Msg::SignUpDone, StatusCode::OK),
        Ok(Some(Err(r))) => {
            r.log("signup");
            return pages::notice(&app, lang, Msg::VerifyBad, StatusCode::BAD_REQUEST);
        }
        Ok(None) => {}
        Err(e) => return e.into_response(),
    }
    match redeem_email_token(&app.db, &f.token, None).await {
        Ok(Ok(_)) => pages::notice(&app, lang, Msg::VerifyDone, StatusCode::OK),
        Ok(Err(r)) => {
            r.log("email");
            pages::notice(&app, lang, Msg::VerifyBad, StatusCode::BAD_REQUEST)
        }
        Err(e) => e.into_response(),
    }
}

/// A token is 32 bytes of base64url. Checking the shape before touching the
/// database turns a flood of junk into a cheap refusal.
pub fn token_shaped(t: &str) -> bool {
    t.len() == 43 && t.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

// ------------------------------------------------------------ password resets

/// `GET /reset-password` (ask for the address) and `GET /reset-password?token=…`
/// (choose a new one). Neither changes anything.
pub async fn reset_page(lang: Lang, State(app): State<Shared>, Query(q): Query<TokenQuery>) -> Response {
    match q.token {
        Some(t) if token_shaped(&t) => pages::reset_form(&app, lang, &t, None),
        Some(_) => pages::notice(&app, lang, Msg::ResetBad, StatusCode::BAD_REQUEST),
        None => pages::reset_ask(&app, lang, None, StatusCode::OK),
    }
}

#[derive(Deserialize)]
pub struct ResetForm {
    action: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    token: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    password2: String,
    #[serde(default)]
    code: String,
}

/// Proving it is you with the authenticator app instead of the mailed link.
/// One answer for no account, no app and a wrong code.
async fn reset_by_app(app: &Shared, lang: Lang, ip: std::net::IpAddr, raw: &str, code: &str) -> Response {
    if !app.limits.take("reset-ip", &ip.to_string(), ratelimit::RESET_IP) {
        return pages::notice(app, lang, Msg::TooMany, StatusCode::TOO_MANY_REQUESTS);
    }
    let refused = || pages::reset_ask(app, lang, Some(Msg::ResetAppBad), StatusCode::UNAUTHORIZED);
    let Some(email) = normalize_email(raw) else { return refused() };
    if !app.limits.take("reset-app", &email, ratelimit::TOTP_ACCOUNT) {
        return refused();
    }
    let row: Option<(Uuid,)> =
        match sqlx::query_as("SELECT id FROM accounts WHERE email = $1 AND email_verified AND totp_enabled")
            .bind(&email)
            .fetch_optional(&app.db)
            .await
        {
            Ok(r) => r,
            Err(e) => return Error::from(e).into_response(),
        };
    let Some((account_id,)) = row else { return refused() };
    match crate::twofactor::check_second_factor(app, account_id, code).await {
        Ok(true) => {}
        Ok(false) => return refused(),
        Err(e) => return e.into_response(),
    }
    match issue_reset_for(app, account_id).await {
        Ok(token) => {
            app.post(&email, mail::reset_started_letter());
            pages::reset_form(app, lang, &token, None)
        }
        Err(e) => e.into_response(),
    }
}

pub async fn reset_submit(
    lang: Lang,
    State(app): State<Shared>,
    ClientIp(ip): ClientIp,
    axum::Form(f): axum::Form<ResetForm>,
) -> Response {
    match f.action.as_str() {
        "request" => request_reset(&app, lang, ip, &f.email).await,
        "app" => reset_by_app(&app, lang, ip, &f.email, &f.code).await,
        "set" => set_password(&app, lang, ip, &f).await,
        _ => pages::notice(&app, lang, Msg::ResetBad, StatusCode::BAD_REQUEST),
    }
}

/// Always the same page. Whether the address has an account, and whether that
/// account ever confirmed it, are exactly what this must not say.
async fn request_reset(app: &Shared, lang: Lang, ip: std::net::IpAddr, raw: &str) -> Response {
    let sent = pages::notice(app, lang, Msg::ResetSent, StatusCode::OK);
    if !app.limits.take("reset-ip", &ip.to_string(), ratelimit::RESET_IP) {
        return pages::notice(app, lang, Msg::TooMany, StatusCode::TOO_MANY_REQUESTS);
    }
    let Some(email) = normalize_email(raw) else {
        // Not even a well-formed address: say the same thing, so a probe
        // cannot use the error page to sort real addresses from junk.
        return sent;
    };
    if !app.limits.take("reset-email", &email, ratelimit::MAIL_PER_ACCOUNT) {
        return sent;
    }
    match issue_reset(app, &email).await {
        Ok(Some(token)) => {
            app.post(&email, mail::reset_password_letter(&app.link("/reset-password", &token)));
        }
        // No account, or an address never confirmed (design section 6: reset
        // is off until then). Nothing is sent, and nothing is said.
        Ok(None) => tracing::debug!("reset asked for an address with no reset available"),
        Err(e) => tracing::error!(?e, "reset token could not be issued"),
    }
    sent
}

async fn issue_reset(app: &Shared, email: &str) -> Result<Option<String>> {
    let row: Option<(Uuid, bool)> = sqlx::query_as("SELECT id, email_verified FROM accounts WHERE email = $1")
        .bind(email)
        .fetch_optional(&app.db)
        .await?;
    let Some((account_id, verified)) = row.filter(|r| r.1) else {
        return Ok(None);
    };
    debug_assert!(verified);
    issue_reset_for(app, account_id).await.map(Some)
}

/// A reset link for an account that has just proven itself some other way
/// (a passkey, or its authenticator app): it is shown, not mailed.
pub async fn issue_reset_for(app: &Shared, account_id: Uuid) -> Result<String> {
    let token = random_token();
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM password_resets WHERE expires_at < now()").execute(&mut *tx).await?;
    // One live link at a time: asking again replaces the last one, so an old
    // mail left in an inbox stops working.
    sqlx::query("DELETE FROM password_resets WHERE account_id = $1 AND used_at IS NULL")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO password_resets (token_hash, account_id, expires_at) VALUES ($1, $2, $3)")
        .bind(tokens::hash(&token))
        .bind(account_id)
        .bind(OffsetDateTime::now_utc() + Duration::minutes(RESET_TTL_MINUTES))
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(token)
}

async fn set_password(app: &Shared, lang: Lang, ip: std::net::IpAddr, f: &ResetForm) -> Response {
    if !token_shaped(&f.token) {
        return pages::notice(app, lang, Msg::ResetBad, StatusCode::BAD_REQUEST);
    }
    if f.password != f.password2 {
        return pages::reset_form(app, lang, &f.token, Some(Msg::PasswordsDiffer));
    }
    if !password_ok(&f.password) {
        return pages::reset_form(app, lang, &f.token, Some(Msg::ShortPassword));
    }
    if !app.limits.take("reset-set-ip", &ip.to_string(), ratelimit::SIGN_IN_IP) {
        return pages::notice(app, lang, Msg::TooMany, StatusCode::TOO_MANY_REQUESTS);
    }
    // Hashing takes one of the few heavy slots: only a link that can still be
    // spent is worth one. spend_reset checks again under the row lock.
    match reset_is_live(app, &f.token).await {
        Ok(true) => {}
        Ok(false) => return pages::notice(app, lang, Msg::ResetBad, StatusCode::BAD_REQUEST),
        Err(e) => return e.into_response(),
    }
    let hash = match crate::oauth::new_hash(app, f.password.clone()).await {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    match spend_reset(app, &f.token, &hash).await {
        Ok(Ok(())) => pages::notice(app, lang, Msg::ResetDone, StatusCode::OK),
        Ok(Err(r)) => {
            r.log("reset");
            pages::notice(app, lang, Msg::ResetBad, StatusCode::BAD_REQUEST)
        }
        Err(e) => e.into_response(),
    }
}

async fn reset_is_live(app: &Shared, token: &str) -> Result<bool> {
    let row: Option<(bool,)> = sqlx::query_as(
        "SELECT used_at IS NULL AND expires_at > now() FROM password_resets WHERE token_hash = $1",
    )
    .bind(tokens::hash(token))
    .fetch_optional(&app.db)
    .await?;
    Ok(row.is_some_and(|r| r.0))
}

/// Spends the link, sets the password, and signs every PC out.
///
/// The devices stay in Your devices (design section 6) but their tokens go:
/// if the password was reset because someone else had it, the point is to put
/// whoever holds a token back behind the new password.
async fn spend_reset(
    app: &Shared,
    token: &str,
    password_hash: &str,
) -> Result<std::result::Result<(), Refused>> {
    let mut tx = app.db.begin().await?;
    let row: Option<(Uuid, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT account_id, expires_at, used_at FROM password_resets WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(tokens::hash(token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((account_id, expires_at, used_at)) = row else {
        return Ok(Err(Refused::Unknown));
    };
    if used_at.is_some() {
        return Ok(Err(Refused::AlreadyUsed));
    }
    if expires_at < OffsetDateTime::now_utc() {
        return Ok(Err(Refused::Expired));
    }
    sqlx::query("UPDATE password_resets SET used_at = now() WHERE token_hash = $1")
        .bind(tokens::hash(token))
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE accounts SET password_hash = $2, updated_at = now() WHERE id = $1")
        .bind(account_id)
        .bind(password_hash)
        .execute(&mut *tx)
        .await?;
    sqlx::query("DELETE FROM access_tokens WHERE account_id = $1").bind(account_id).execute(&mut *tx).await?;
    // And every browser signed in to the website.
    sqlx::query("DELETE FROM web_sessions WHERE account_id = $1").bind(account_id).execute(&mut *tx).await?;
    sqlx::query(
        "DELETE FROM refresh_tokens WHERE device_id IN (SELECT id FROM devices WHERE account_id = $1)",
    )
    .bind(account_id)
    .execute(&mut *tx)
    .await?;
    // A code half-way through a sign-in was authorised by the old password.
    sqlx::query("DELETE FROM oauth_codes WHERE account_id = $1").bind(account_id).execute(&mut *tx).await?;
    // Any other link that was asked for before this one.
    sqlx::query("DELETE FROM password_resets WHERE account_id = $1 AND used_at IS NULL")
        .bind(account_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    tracing::info!(%account_id, "password reset, every device signed out");
    Ok(Ok(()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_shape() {
        for _ in 0..20 {
            assert!(token_shaped(&random_token()), "every token this server issues");
        }
        assert!(!token_shaped(""));
        assert!(!token_shaped("short"));
        assert!(!token_shaped(&"a".repeat(42)), "too short");
        assert!(!token_shaped(&"a".repeat(44)), "too long");
        assert!(!token_shaped(&format!("{}=", "a".repeat(42))), "base64 padding is not in our alphabet");
        assert!(!token_shaped(&format!("{}/", "a".repeat(42))), "nor is standard base64");
        assert!(!token_shaped(&format!("{}'", "a".repeat(42))), "nor anything that could reach SQL or HTML");
    }
}
