//! Signing in: OAuth 2.0 authorization code with PKCE for the desktop app
//! (RFC 6749, 7636, and 8252 for the loopback redirect). The password is only
//! ever typed into the account website in the user's browser, never into an app.

use argon2::password_hash::{PasswordHash, PasswordHasher, PasswordVerifier, SaltString};
use argon2::{Algorithm, Argon2, Params, Version};
use axum::extract::{Query, State};
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Form, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signature, Verifier, VerifyingKey};
use hmac::{Hmac, Mac};
use serde::Deserialize;
use sha2::Sha256;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::pages::{self, Lang, Msg, Prefill, Screen};
use crate::tokens::{self, AuthDevice, ClientIp};
use crate::{ratelimit, Shared};
use raye_account_common::api::TokenResponse;
use raye_account_common::{pkce, random_token, refresh_proof_message, DESKTOP_CLIENT_ID, REFRESH_PROOF_SKEW_SECS};

const CODE_TTL_SECS: i64 = 60;
const FORM_TTL_SECS: i64 = 15 * 60;

fn argon2() -> Argon2<'static> {
    // OWASP's first choice for argon2id: 19 MiB, 2 passes, 1 lane.
    Argon2::new(Algorithm::Argon2id, Version::V0x13, Params::new(19 * 1024, 2, 1, None).unwrap())
}

pub fn hash_password(password: &str) -> std::result::Result<String, argon2::password_hash::Error> {
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    Ok(argon2().hash_password(password.as_bytes(), &salt)?.to_string())
}

fn password_matches(password: &str, stored: &str) -> bool {
    PasswordHash::new(stored)
        .map(|h| argon2().verify_password(password.as_bytes(), &h).is_ok())
        .unwrap_or(false)
}

/// Runs Argon2 off the async threads, a few at a time.
pub async fn check_password(state: &Shared, password: String, stored: String) -> Result<bool> {
    let _permit = state.heavy.acquire().await.map_err(|e| Error::Internal(e.to_string()))?;
    tokio::task::spawn_blocking(move || password_matches(&password, &stored))
        .await
        .map_err(|e| Error::Internal(e.to_string()))
}

pub async fn new_hash(state: &Shared, password: String) -> Result<String> {
    let _permit = state.heavy.acquire().await.map_err(|e| Error::Internal(e.to_string()))?;
    tokio::task::spawn_blocking(move || hash_password(&password))
        .await
        .map_err(|e| Error::Internal(e.to_string()))?
        .map_err(|e| Error::Internal(e.to_string()))
}

/// Only a loopback redirect on the callback path is accepted for the desktop
/// client (RFC 8252 7.3): the code can only travel to the PC that asked.
/// IPv4 only: raye-accountd listens on 127.0.0.1, and browsers reject an
/// IPv6 literal in the CSP form-action that has to allow the redirect.
pub fn redirect_ok(uri: &str) -> bool {
    let Some(rest) = uri.strip_prefix("http://127.0.0.1:") else { return false };
    let Some(port) = rest.strip_suffix("/callback") else { return false };
    !port.starts_with('0') && port.parse::<u16>().is_ok_and(|p| p >= 1024)
}

/// The state is echoed into a Location header, so it gets the strictest check.
fn state_ok(s: &str) -> bool {
    (16..=128).contains(&s.len()) && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

#[derive(Deserialize)]
pub struct AuthorizeQuery {
    response_type: Option<String>,
    client_id: Option<String>,
    redirect_uri: Option<String>,
    state: Option<String>,
    code_challenge: Option<String>,
    code_challenge_method: Option<String>,
    screen: Option<String>,
}

/// What a sign-in form carries from the authorize request to the POST.
#[derive(Clone)]
pub struct Flow {
    pub redirect_uri: String,
    pub state: String,
    pub code_challenge: String,
    pub ts: i64,
    pub csrf: String,
}

impl Flow {
    fn mac(key: &[u8; 32], redirect_uri: &str, state: &str, challenge: &str, ts: i64) -> String {
        let mut m = <Hmac<Sha256>>::new_from_slice(key).unwrap();
        m.update(format!("authorize\n{redirect_uri}\n{state}\n{challenge}\n{ts}").as_bytes());
        URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
    }

    fn new(app: &Shared, redirect_uri: String, state: String, code_challenge: String) -> Flow {
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        let csrf = Flow::mac(&app.form_key, &redirect_uri, &state, &code_challenge, ts);
        Flow { redirect_uri, state, code_challenge, ts, csrf }
    }

    fn verify(app: &Shared, f: &SubmitForm) -> Option<Flow> {
        let now = OffsetDateTime::now_utc().unix_timestamp();
        if f.ts > now + 5 || now - f.ts > FORM_TTL_SECS {
            return None;
        }
        let mut m = <Hmac<Sha256>>::new_from_slice(&app.form_key).unwrap();
        m.update(format!("authorize\n{}\n{}\n{}\n{}", f.redirect_uri, f.state, f.code_challenge, f.ts).as_bytes());
        m.verify_slice(&URL_SAFE_NO_PAD.decode(&f.csrf).ok()?).ok()?;
        Some(Flow {
            redirect_uri: f.redirect_uri.clone(),
            state: f.state.clone(),
            code_challenge: f.code_challenge.clone(),
            ts: f.ts,
            csrf: f.csrf.clone(),
        })
    }
}

/// How long the page that asks for a code stays usable. Short: it is proof
/// that a password was checked, and that proof should not outlive the person
/// standing at the keyboard.
const TOTP_STAGE_TTL_SECS: i64 = 10 * 60;

/// Proof, made by this server, that the password of `account_id` was just
/// checked for this exact sign-in.
///
/// This is the whole reason the second screen is not a free oracle. The code
/// form carries the account id in a hidden field, and a hidden field is
/// whatever the browser sends; the HMAC is what makes it the server's word.
/// The domain string differs from the first-stage form's ("authorize"), so
/// neither MAC can be presented in the other's place.
/// `kind` is "totp" or "email": a proof for one screen does not open the other.
fn stage_mac(
    key: &[u8; 32],
    kind: &str,
    account_id: &Uuid,
    redirect_uri: &str,
    state: &str,
    challenge: &str,
    ts: i64,
) -> String {
    let mut m = <Hmac<Sha256>>::new_from_slice(key).unwrap();
    m.update(format!("{kind}\n{account_id}\n{redirect_uri}\n{state}\n{challenge}\n{ts}").as_bytes());
    URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
}

fn stage_ok(app: &Shared, kind: &str, f: &SubmitForm, account_id: &Uuid) -> bool {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    if f.ts > now + 5 || now - f.ts > TOTP_STAGE_TTL_SECS {
        return false;
    }
    let want = stage_mac(&app.form_key, kind, account_id, &f.redirect_uri, &f.state, &f.code_challenge, f.ts);
    raye_account_common::ct_eq(want.as_bytes(), f.csrf.as_bytes())
}

pub async fn authorize_page(State(app): State<Shared>, lang: Lang, Query(q): Query<AuthorizeQuery>) -> Response {
    let valid = q.response_type.as_deref() == Some("code")
        && q.client_id.as_deref() == Some(DESKTOP_CLIENT_ID)
        && q.code_challenge_method.as_deref() == Some("S256")
        && q.redirect_uri.as_deref().is_some_and(redirect_ok)
        && q.state.as_deref().is_some_and(state_ok)
        && q.code_challenge.as_deref().is_some_and(pkce::challenge_is_well_formed);
    if !valid {
        // Never redirect on a bad request: the redirect itself is what is in doubt.
        return pages::problem(&app, lang, Msg::BadLink);
    }
    let flow = Flow::new(&app, q.redirect_uri.unwrap(), q.state.unwrap(), q.code_challenge.unwrap());
    let screen = if q.screen.as_deref() == Some("signup") { Screen::SignUp } else { Screen::SignIn };
    pages::sign_in(&app, lang, &flow, screen, Prefill { email: "", display_name: "" }, None, StatusCode::OK)
}

#[derive(Deserialize)]
pub struct SubmitForm {
    action: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    display_name: String,
    /// Second stage only: the TOTP or recovery code.
    #[serde(default)]
    code: String,
    /// Second stage only: which account the password was checked for. Only
    /// meaningful together with the `csrf` MAC, which covers it.
    #[serde(default)]
    account: String,
    redirect_uri: String,
    state: String,
    code_challenge: String,
    ts: i64,
    csrf: String,
}

pub fn normalize_email(raw: &str) -> Option<String> {
    let e = raw.trim().to_lowercase();
    let (local, domain) = e.split_once('@')?;
    // One plain mailbox: the address goes into a To: header and to sendmail,
    // where a comma or a quoted part would name more than one recipient.
    let local_ok = !local.is_empty()
        && local.len() <= 64
        && !local.starts_with('.')
        && !local.ends_with('.')
        && !local.contains("..")
        && local.bytes().all(|b| b.is_ascii_alphanumeric() || b"#$&'*+=?^_`{}~.-".contains(&b));
    let labels: Vec<&str> = domain.split('.').collect();
    let domain_ok = labels.len() >= 2
        && labels.iter().all(|l| {
            !l.is_empty()
                && l.len() <= 63
                && !l.starts_with('-')
                && !l.ends_with('-')
                && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
        });
    (e.len() <= 254 && local_ok && domain_ok).then_some(e)
}

pub fn display_name_ok(name: &str) -> bool {
    let n = name.trim();
    !n.is_empty() && n.chars().count() <= 64 && !n.chars().any(char::is_control)
}

pub fn password_ok(p: &str) -> bool {
    p.chars().count() >= 10 && p.len() <= 1024
}

pub async fn authorize_submit(
    State(app): State<Shared>,
    ClientIp(ip): ClientIp,
    lang: Lang,
    Form(f): Form<SubmitForm>,
) -> Response {
    // The second stage first, and the order is the point: the two screens
    // carry DIFFERENT proofs in the same `csrf` field -- `Flow::verify`
    // checks the one the password screen issues ("authorize\n..."), and the
    // code screen's is a `stage_mac` ("totp\n<account>\n..."). Letting
    // `Flow::verify` run first makes every valid code screen look expired.
    if f.action == "totp" {
        return second_factor(&app, lang, ip, &f).await;
    }
    if f.action == "emailcode" || f.action == "emailcode-resend" {
        return email_code_stage(&app, lang, ip, &f).await;
    }
    let Some(flow) = Flow::verify(&app, &f) else {
        return pages::problem(&app, lang, Msg::Expired);
    };
    if !redirect_ok(&flow.redirect_uri) || !state_ok(&flow.state) {
        return pages::problem(&app, lang, Msg::BadLink);
    }
    let signup = f.action == "signup";
    let screen = if signup { Screen::SignUp } else { Screen::SignIn };
    let again = |m: Msg, status| {
        let prefill = Prefill { email: &f.email, display_name: &f.display_name };
        pages::sign_in(&app, lang, &flow, screen, prefill, Some(m), status)
    };

    let ip_key = ip.to_string();
    let rule = if signup { ratelimit::SIGN_UP_IP } else { ratelimit::SIGN_IN_IP };
    if !app.limits.take(if signup { "signup-ip" } else { "signin-ip" }, &ip_key, rule) {
        return again(Msg::TooMany, StatusCode::TOO_MANY_REQUESTS);
    }

    let Some(email) = normalize_email(&f.email) else {
        return again(Msg::BadEmail, StatusCode::BAD_REQUEST);
    };

    let account_id = if signup {
        if !display_name_ok(&f.display_name) {
            return again(Msg::NeedName, StatusCode::BAD_REQUEST);
        }
        if !password_ok(&f.password) {
            return again(Msg::ShortPassword, StatusCode::BAD_REQUEST);
        }
        // Taken or free, the answer is this page: whoever owns the address
        // learns the rest from their mailbox.
        return match crate::email::start_signup(&app, &email, &f.password, f.display_name.trim()).await {
            Ok(_) => pages::signup_sent(&app, lang, &flow),
            Err(e) => e.into_response(),
        };
    } else {
        if !app.limits.has("signin-account", &email, ratelimit::SIGN_IN_ACCOUNT) {
            return again(Msg::TooMany, StatusCode::TOO_MANY_REQUESTS);
        }
        match sign_in(&app, &email, &f.password).await {
            Ok(Some(id)) => {
                match crate::twofactor::is_on(&app, id).await {
                    Ok(true) => {
                        // The password was right. Nothing else happens until a
                        // code arrives, and the proof of that goes in the form.
                        let ts = OffsetDateTime::now_utc().unix_timestamp();
                        let stage = stage_mac(
                            &app.form_key,
                            "totp",
                            &id,
                            &flow.redirect_uri,
                            &flow.state,
                            &flow.code_challenge,
                            ts,
                        );
                        return pages::totp_form(
                            &app,
                            lang,
                            &id.to_string(),
                            &flow.redirect_uri,
                            &flow.state,
                            &flow.code_challenge,
                            ts,
                            &stage,
                            None,
                            StatusCode::OK,
                        );
                    }
                    Ok(false) => match crate::emailcode::is_on(&app, id).await {
                        Ok(true) => {
                            let ts = OffsetDateTime::now_utc().unix_timestamp();
                            let stage = stage_mac(
                                &app.form_key,
                                "email",
                                &id,
                                &flow.redirect_uri,
                                &flow.state,
                                &flow.code_challenge,
                                ts,
                            );
                            let sent = match crate::emailcode::send(&app, id).await {
                                Ok(sent) => sent,
                                Err(e) => return e.into_response(),
                            };
                            let stage = pages::Stage {
                                account_id: &id.to_string(),
                                redirect_uri: &flow.redirect_uri,
                                state: &flow.state,
                                code_challenge: &flow.code_challenge,
                                ts,
                                mac: &stage,
                            };
                            return if sent {
                                pages::email_code_form(&app, lang, &stage, None, StatusCode::OK)
                            } else {
                                pages::email_code_form(&app, lang, &stage, Some(Msg::TooMany), StatusCode::TOO_MANY_REQUESTS)
                            };
                        }
                        Ok(false) => id,
                        Err(e) => return e.into_response(),
                    },
                    Err(e) => return e.into_response(),
                }
            }
            Ok(None) => {
                app.limits.take("signin-account", &email, ratelimit::SIGN_IN_ACCOUNT);
                return again(Msg::WrongPassword, StatusCode::UNAUTHORIZED);
            }
            Err(e) => return e.into_response(),
        }
    };

    match new_code(&app, account_id, &flow).await {
        Ok(code) => {
            let to = format!("{}?code={}&state={}", flow.redirect_uri, code, flow.state);
            let mut res = Redirect::to(&to).into_response();
            res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            res
        }
        Err(e) => e.into_response(),
    }
}

/// The code screen's submission.
///
/// Order matters here. The MAC is checked *first*: without it this is a
/// stranger asking to try codes on an account, and no number of tries should
/// be spent, no code read, and nothing said about whether the account exists.
async fn second_factor(app: &Shared, lang: Lang, ip: std::net::IpAddr, f: &SubmitForm) -> Response {
    let Ok(account_id) = f.account.parse::<Uuid>() else {
        return pages::problem(app, lang, Msg::Expired);
    };
    if !stage_ok(app, "totp", f, &account_id) {
        return pages::problem(app, lang, Msg::Expired);
    }
    if !redirect_ok(&f.redirect_uri) || !state_ok(&f.state) || !pkce::challenge_is_well_formed(&f.code_challenge) {
        return pages::problem(app, lang, Msg::BadLink);
    }
    // The proof keeps the time of the password check: retries do not extend it.
    let ts = f.ts;
    let stage = stage_mac(&app.form_key, "totp", &account_id, &f.redirect_uri, &f.state, &f.code_challenge, ts);
    let again = |m: Msg, status| {
        pages::totp_form(
            app,
            lang,
            &f.account,
            &f.redirect_uri,
            &f.state,
            &f.code_challenge,
            ts,
            &stage,
            Some(m),
            status,
        )
    };
    // Six digits is a million, so guessing is the realistic attack and the
    // limit is the defence. Per account and per address.
    if !app.limits.take("totp-try", &account_id.to_string(), ratelimit::TOTP_ACCOUNT)
        || !app.limits.take("totp-ip", &ip.to_string(), ratelimit::SIGN_IN_IP)
    {
        return again(Msg::TooMany, StatusCode::TOO_MANY_REQUESTS);
    }
    match crate::twofactor::check_second_factor(app, account_id, &f.code).await {
        Ok(true) => {}
        Ok(false) => return again(Msg::BadCode, StatusCode::UNAUTHORIZED),
        Err(e) => return e.into_response(),
    }
    let flow = Flow {
        redirect_uri: f.redirect_uri.clone(),
        state: f.state.clone(),
        code_challenge: f.code_challenge.clone(),
        ts: f.ts,
        csrf: f.csrf.clone(),
    };
    match new_code(app, account_id, &flow).await {
        Ok(code) => {
            let to = format!("{}?code={}&state={}", flow.redirect_uri, code, flow.state);
            let mut res = Redirect::to(&to).into_response();
            res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            res
        }
        Err(e) => e.into_response(),
    }
}

/// The screen that asks for the code sent by email. Same order as the TOTP
/// screen: the server's MAC first, then the limits, then the code.
async fn email_code_stage(app: &Shared, lang: Lang, ip: std::net::IpAddr, f: &SubmitForm) -> Response {
    let Ok(account_id) = f.account.parse::<Uuid>() else {
        return pages::problem(app, lang, Msg::Expired);
    };
    if !stage_ok(app, "email", f, &account_id) {
        return pages::problem(app, lang, Msg::Expired);
    }
    if !redirect_ok(&f.redirect_uri) || !state_ok(&f.state) || !pkce::challenge_is_well_formed(&f.code_challenge) {
        return pages::problem(app, lang, Msg::BadLink);
    }
    let ts = f.ts;
    let mac = stage_mac(&app.form_key, "email", &account_id, &f.redirect_uri, &f.state, &f.code_challenge, ts);
    let id = account_id.to_string();
    let stage = pages::Stage {
        account_id: &id,
        redirect_uri: &f.redirect_uri,
        state: &f.state,
        code_challenge: &f.code_challenge,
        ts,
        mac: &mac,
    };
    // Turned on since the password was checked: the app's code is asked now.
    match crate::twofactor::is_on(app, account_id).await {
        Ok(false) => {}
        Ok(true) => return pages::problem(app, lang, Msg::Expired),
        Err(e) => return e.into_response(),
    }
    if f.action == "emailcode-resend" {
        return match crate::emailcode::send(app, account_id).await {
            Ok(true) => pages::email_code_form(app, lang, &stage, Some(Msg::CodeResent), StatusCode::OK),
            Ok(false) => pages::email_code_form(app, lang, &stage, Some(Msg::TooMany), StatusCode::TOO_MANY_REQUESTS),
            Err(e) => e.into_response(),
        };
    }
    if !app.limits.take("email-code-try", &id, ratelimit::TOTP_ACCOUNT)
        || !app.limits.take("email-code-ip", &ip.to_string(), ratelimit::SIGN_IN_IP)
    {
        return pages::email_code_form(app, lang, &stage, Some(Msg::TooMany), StatusCode::TOO_MANY_REQUESTS);
    }
    match crate::emailcode::check(app, account_id, &f.code).await {
        Ok(true) => {}
        Ok(false) => return pages::email_code_form(app, lang, &stage, Some(Msg::BadEmailCode), StatusCode::UNAUTHORIZED),
        Err(e) => return e.into_response(),
    }
    let flow = Flow {
        redirect_uri: f.redirect_uri.clone(),
        state: f.state.clone(),
        code_challenge: f.code_challenge.clone(),
        ts: f.ts,
        csrf: f.csrf.clone(),
    };
    match new_code(app, account_id, &flow).await {
        Ok(code) => {
            let to = format!("{}?code={}&state={}", flow.redirect_uri, code, flow.state);
            let mut res = Redirect::to(&to).into_response();
            res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
            res
        }
        Err(e) => e.into_response(),
    }
}

pub(crate) async fn sign_in(app: &Shared, email: &str, password: &str) -> Result<Option<Uuid>> {
    let row: Option<(Uuid, String)> =
        sqlx::query_as("SELECT id, password_hash FROM accounts WHERE email = $1 AND email_verified")
            .bind(email)
            .fetch_optional(&app.db)
            .await?;
    // An unknown email still costs one hash, so the answer takes as long
    // as for a wrong password and does not tell who has an account.
    let (id, stored) = match row {
        Some((id, h)) => (Some(id), h),
        None => (None, app.dummy_hash.clone()),
    };
    let ok = check_password(app, password.to_owned(), stored).await?;
    Ok(if ok { id } else { None })
}

async fn new_code(app: &Shared, account_id: Uuid, flow: &Flow) -> Result<String> {
    let code = random_token();
    sqlx::query("DELETE FROM oauth_codes WHERE expires_at < now()").execute(&app.db).await?;
    sqlx::query(
        "INSERT INTO oauth_codes (code_hash, account_id, redirect_uri, code_challenge, expires_at)
         VALUES ($1, $2, $3, $4, $5)",
    )
    .bind(tokens::hash(&code))
    .bind(account_id)
    .bind(&flow.redirect_uri)
    .bind(&flow.code_challenge)
    .bind(OffsetDateTime::now_utc() + Duration::seconds(CODE_TTL_SECS))
    .execute(&app.db)
    .await?;
    Ok(code)
}

#[derive(Deserialize)]
pub struct TokenForm {
    grant_type: String,
    client_id: Option<String>,
    // authorization_code
    code: Option<String>,
    redirect_uri: Option<String>,
    code_verifier: Option<String>,
    device_name: Option<String>,
    device_model: Option<String>,
    raye_version: Option<String>,
    device_key: Option<String>,
    // refresh_token
    refresh_token: Option<String>,
    device_id: Option<Uuid>,
    proof_ts: Option<i64>,
    proof: Option<String>,
}

fn short_text(s: Option<&str>, max: usize) -> Option<String> {
    let s = s?.trim();
    (!s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control)).then(|| s.to_owned())
}

fn token_json(pair: tokens::Pair, device_id: Uuid, app: &Shared) -> Response {
    let mut res = Json(TokenResponse {
        access_token: pair.access,
        token_type: "Bearer".into(),
        expires_in: app.config.access_ttl_secs,
        refresh_token: pair.refresh,
        device_id,
    })
    .into_response();
    res.headers_mut().insert(header::CACHE_CONTROL, "no-store".parse().unwrap());
    res
}

pub async fn token(State(app): State<Shared>, ClientIp(ip): ClientIp, Form(f): Form<TokenForm>) -> Result<Response> {
    if !app.limits.take("token-ip", &ip.to_string(), ratelimit::TOKEN_IP) {
        return Err(Error::TooMany);
    }
    if f.client_id.as_deref() != Some(DESKTOP_CLIENT_ID) {
        return Err(Error::BadRequest("unknown client"));
    }
    match f.grant_type.as_str() {
        "authorization_code" => redeem_code(&app, f).await,
        "refresh_token" => refresh(&app, f).await,
        _ => Err(Error::BadRequest("unsupported grant_type")),
    }
}

async fn redeem_code(app: &Shared, f: TokenForm) -> Result<Response> {
    let code = f.code.ok_or(Error::BadRequest("code missing"))?;
    let verifier = f.code_verifier.ok_or(Error::BadRequest("code_verifier missing"))?;
    let redirect_uri = f.redirect_uri.ok_or(Error::BadRequest("redirect_uri missing"))?;
    let name = short_text(f.device_name.as_deref(), 64).ok_or(Error::BadRequest("device_name"))?;
    let model = short_text(f.device_model.as_deref(), 96).unwrap_or_else(|| "PC".into());
    let version = short_text(f.raye_version.as_deref(), 32).ok_or(Error::BadRequest("raye_version"))?;
    let key = f
        .device_key
        .as_deref()
        .and_then(|k| URL_SAFE_NO_PAD.decode(k).ok())
        .filter(|k| k.len() == 32 && VerifyingKey::from_bytes(k.as_slice().try_into().unwrap()).is_ok())
        .ok_or(Error::BadRequest("device_key"))?;

    let mut tx = app.db.begin().await?;
    // Deleting first makes the code single-use even with two racing requests.
    let row: Option<(Uuid, String, String, OffsetDateTime)> = sqlx::query_as(
        "DELETE FROM oauth_codes WHERE code_hash = $1 RETURNING account_id, redirect_uri, code_challenge, expires_at",
    )
    .bind(tokens::hash(&code))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((account_id, want_uri, challenge, expires_at)) = row else {
        tx.commit().await?;
        return Err(Error::InvalidGrant);
    };
    if expires_at < OffsetDateTime::now_utc() || want_uri != redirect_uri || !pkce::verify(&verifier, &challenge) {
        tx.commit().await?;
        return Err(Error::InvalidGrant);
    }
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM devices WHERE account_id = $1")
        .bind(account_id)
        .fetch_one(&mut *tx)
        .await?;
    if count >= app.config.max_devices {
        tx.commit().await?;
        return Err(Error::BadRequest("too many devices: remove one from your account first"));
    }
    let device_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO devices (id, account_id, name, model, raye_version, public_key) VALUES ($1, $2, $3, $4, $5, $6)",
    )
    .bind(device_id)
    .bind(account_id)
    .bind(name)
    .bind(model)
    .bind(version)
    .bind(key)
    .execute(&mut *tx)
    .await?;
    let pair = tokens::issue(&mut tx, app, account_id, device_id).await?;
    tx.commit().await?;
    Ok(token_json(pair, device_id, app))
}

async fn refresh(app: &Shared, f: TokenForm) -> Result<Response> {
    let token = f.refresh_token.ok_or(Error::BadRequest("refresh_token missing"))?;
    let device_id = f.device_id.ok_or(Error::BadRequest("device_id missing"))?;
    let ts = f.proof_ts.ok_or(Error::BadRequest("proof_ts missing"))?;
    let proof = f
        .proof
        .as_deref()
        .and_then(|p| URL_SAFE_NO_PAD.decode(p).ok())
        .and_then(|p| Signature::from_slice(&p).ok())
        .ok_or(Error::BadRequest("proof"))?;

    let mut tx = app.db.begin().await?;
    let row: Option<(Uuid, OffsetDateTime, Option<OffsetDateTime>)> = sqlx::query_as(
        "SELECT device_id, expires_at, used_at FROM refresh_tokens WHERE token_hash = $1 FOR UPDATE",
    )
    .bind(tokens::hash(&token))
    .fetch_optional(&mut *tx)
    .await?;
    let Some((owner, expires_at, used_at)) = row else {
        return Err(Error::InvalidGrant);
    };
    if owner != device_id {
        return Err(Error::InvalidGrant);
    }
    let dev: Option<(Uuid, Vec<u8>)> =
        sqlx::query_as("SELECT account_id, public_key FROM devices WHERE id = $1 FOR UPDATE")
            .bind(device_id)
            .fetch_optional(&mut *tx)
            .await?;
    let Some((account_id, public_key)) = dev else {
        return Err(Error::InvalidGrant);
    };
    let key = VerifyingKey::from_bytes(public_key.as_slice().try_into().map_err(|_| Error::InvalidGrant)?)
        .map_err(|_| Error::InvalidGrant)?;
    let now = OffsetDateTime::now_utc();
    let fresh = (now.unix_timestamp() - ts).abs() <= REFRESH_PROOF_SKEW_SECS;
    if !fresh || key.verify(&refresh_proof_message(&device_id, ts, &token), &proof).is_err() {
        return Err(Error::InvalidGrant);
    }
    if used_at.is_some() {
        // A refresh token that comes back after use was copied: one of the two
        // holders is not the device. End the device; the owner signs in again.
        tracing::warn!(%device_id, "refresh token reused, device signed out");
        sqlx::query("DELETE FROM devices WHERE id = $1").bind(device_id).execute(&mut *tx).await?;
        tx.commit().await?;
        return Err(Error::InvalidGrant);
    }
    if expires_at < now {
        return Err(Error::InvalidGrant);
    }
    sqlx::query("UPDATE refresh_tokens SET used_at = now() WHERE token_hash = $1")
        .bind(tokens::hash(&token))
        .execute(&mut *tx)
        .await?;
    sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
        .bind(device_id)
        .execute(&mut *tx)
        .await?;
    let pair = tokens::issue(&mut tx, app, account_id, device_id).await?;
    tx.commit().await?;
    Ok(token_json(pair, device_id, app))
}

/// Signing out on a PC: the device goes away with all its tokens.
pub async fn revoke(State(app): State<Shared>, auth: AuthDevice) -> Result<StatusCode> {
    sqlx::query("DELETE FROM devices WHERE id = $1").bind(auth.device_id).execute(&app.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_loopback_callbacks() {
        assert!(redirect_ok("http://127.0.0.1:50123/callback"));
        assert!(!redirect_ok("http://[::1]:50123/callback"));
        assert!(!redirect_ok("http://127.0.0.1:80/callback"));
        assert!(!redirect_ok("http://127.0.0.1:050123/callback"));
        assert!(!redirect_ok("http://127.0.0.1:99999/callback"));
        assert!(!redirect_ok("http://localhost:50123/callback"));
        assert!(!redirect_ok("https://evil.example/callback"));
        assert!(!redirect_ok("http://127.0.0.1:50123/callback?x=1"));
        assert!(!redirect_ok("http://127.0.0.1:50123@evil.example/callback"));
    }

    #[test]
    fn state_is_strict() {
        assert!(state_ok("abcdefghijklmnop"));
        assert!(!state_ok("short"));
        assert!(!state_ok("abcdefghijklmnop\r\nSet-Cookie: x"));
    }

    #[test]
    fn emails() {
        assert_eq!(normalize_email("  Ana@Example.COM "), Some("ana@example.com".into()));
        assert_eq!(normalize_email("ana@example"), None);
        assert_eq!(normalize_email("@example.com"), None);
        assert_eq!(normalize_email("a b@example.com"), None);
        assert_eq!(normalize_email("a@example.com."), None);
        assert_eq!(normalize_email("ana+raye@example.com"), Some("ana+raye@example.com".into()));
        assert_eq!(normalize_email("o'neil@ex-ample.co.uk"), Some("o'neil@ex-ample.co.uk".into()));
    }

    #[test]
    fn an_email_names_exactly_one_mailbox() {
        for bad in [
            "a@x.com,b@y.com",
            "a@x.com;b@y.com",
            "\"a,b\"@x.com",
            "a(c)@x.com",
            "a@b@x.com",
            "a@[127.0.0.1]",
            "a@x..com",
            "a@-x.com",
            "a:b@x.com",
            "a%b@x.com",
            "a!b@x.com",
            "a|b@x.com",
            "a/b@x.com",
        ] {
            assert_eq!(normalize_email(bad), None, "{bad}");
        }
    }

    #[test]
    fn password_round_trip() {
        let h = hash_password("correct horse battery").unwrap();
        assert!(h.starts_with("$argon2id$v=19$m=19456,t=2,p=1$"));
        assert!(password_matches("correct horse battery", &h));
        assert!(!password_matches("correct horse batterz", &h));
        assert!(!password_matches("x", "not a hash"));
    }
}
