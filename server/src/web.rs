//! The account website on account.rayelinux.com: sign in with a cookie,
//! then Your info, Security, Devices and Privacy.
//!
//! Every page is server-made HTML. The one script (`/static/account.js`)
//! only runs the passkey ceremonies, which a browser cannot do from a form.
//! Every POST carries the session's CSRF token; the cookie is HttpOnly and
//! SameSite=Lax as well. The API handlers do the work: a web session acts as
//! the account, with no device.

use axum::extract::{FromRequestParts, Multipart, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, HeaderMap, HeaderValue, StatusCode};
use axum::response::{Html, IntoResponse, Redirect, Response};
use axum::{Form, Json};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use hmac::{Hmac, Mac};
use serde::Deserialize;
use serde_json::json;
use sha2::Sha256;
use time::{Duration, OffsetDateTime};
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::pages::{escape, Lang};
use crate::tokens::{self, AuthDevice, ClientIp};
use crate::{ratelimit, Shared};
use raye_account_common::{ct_eq, random_token};

const SESSION_DAYS: i64 = 14;
/// How long a proven password counts as "just now" for changing what
/// protects the account.
pub const RECENT_MINUTES: i64 = 10;
const STAGE_TTL_SECS: i64 = 10 * 60;

pub fn cookie_name(app: &Shared) -> &'static str {
    if app.config.https {
        "__Host-raye_session"
    } else {
        "raye_session"
    }
}

fn cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers.get_all(header::COOKIE).iter().filter_map(|v| v.to_str().ok()).find_map(|v| {
        v.split(';').filter_map(|p| p.trim().split_once('=')).find(|(k, _)| *k == name).map(|(_, v)| v)
    })
}

/// The signed-in visitor.
#[derive(Clone)]
pub struct Web {
    pub account_id: Uuid,
    token_hash: Vec<u8>,
    pub csrf: String,
    pub recent: bool,
    pub name: String,
    pub email: String,
    pub has_photo: bool,
    pub lang: Lang,
}

impl Web {
    /// The API handlers take a device; the website is the account itself.
    fn as_auth(&self) -> AuthDevice {
        AuthDevice { account_id: self.account_id, device_id: Uuid::nil() }
    }

    fn csrf_ok(&self, presented: &str) -> bool {
        ct_eq(self.csrf.as_bytes(), presented.as_bytes())
    }
}

/// `Some` when the cookie names a live session.
pub struct MaybeWeb(pub Option<Web>);

impl FromRequestParts<Shared> for MaybeWeb {
    type Rejection = Error;

    async fn from_request_parts(parts: &mut Parts, app: &Shared) -> Result<Self> {
        let lang = Lang::from_request_parts(parts, app).await.unwrap_or(Lang::En);
        let Some(token) = cookie_value(&parts.headers, cookie_name(app)) else { return Ok(MaybeWeb(None)) };
        if token.len() != 43 {
            return Ok(MaybeWeb(None));
        }
        let hash = tokens::hash(token);
        let row: Option<(Uuid, String, bool, String, String, bool)> = sqlx::query_as(
            "SELECT s.account_id, s.csrf, s.auth_at > now() - make_interval(mins => $2), a.display_name, a.email,
                    a.avatar_png IS NOT NULL
             FROM web_sessions s JOIN accounts a ON a.id = s.account_id
             WHERE s.token_hash = $1 AND s.expires_at > now() AND a.email_verified",
        )
        .bind(&hash)
        .bind(RECENT_MINUTES as i32)
        .fetch_optional(&app.db)
        .await?;
        let Some((account_id, csrf, recent, name, email, has_photo)) = row else { return Ok(MaybeWeb(None)) };
        sqlx::query("UPDATE web_sessions SET last_seen_at = now() WHERE token_hash = $1 AND last_seen_at < now() - interval '1 minute'")
            .bind(&hash)
            .execute(&app.db)
            .await?;
        Ok(MaybeWeb(Some(Web { account_id, token_hash: hash, csrf, recent, name, email, has_photo, lang })))
    }
}

async fn open_session(app: &Shared, account_id: Uuid) -> Result<String> {
    let token = random_token();
    sqlx::query("DELETE FROM web_sessions WHERE expires_at < now()").execute(&app.db).await?;
    sqlx::query("INSERT INTO web_sessions (token_hash, account_id, csrf, expires_at) VALUES ($1, $2, $3, $4)")
        .bind(tokens::hash(&token))
        .bind(account_id)
        .bind(random_token())
        .bind(OffsetDateTime::now_utc() + Duration::days(SESSION_DAYS))
        .execute(&app.db)
        .await?;
    Ok(token)
}

fn set_cookie(app: &Shared, res: &mut Response, token: Option<&str>) {
    let secure = if app.config.https { "; Secure" } else { "" };
    let v = match token {
        Some(t) => format!("{}={t}; Path=/; HttpOnly; SameSite=Lax; Max-Age={}{secure}", cookie_name(app), SESSION_DAYS * 86400),
        None => format!("{}=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0{secure}", cookie_name(app)),
    };
    res.headers_mut().append(header::SET_COOKIE, HeaderValue::from_str(&v).unwrap());
}

/// Where a sign-in may send the visitor back to: a page of this site.
fn next_ok(n: &str) -> bool {
    n.starts_with("/account") && n.len() < 200 && n.bytes().all(|b| b.is_ascii_alphanumeric() || b"/-_".contains(&b))
}

/// A form posted from another site is refused before anything reads it:
/// browsers name the page's origin on every cross-site POST. This is what
/// stops a page elsewhere from signing a visitor in to someone else's account.
pub async fn same_origin(
    State(app): State<Shared>,
    req: axum::extract::Request,
    next: axum::middleware::Next,
) -> Response {
    if req.method() == axum::http::Method::POST {
        if let Some(origin) = req.headers().get(header::ORIGIN) {
            if origin.as_bytes() != app.config.base_url.trim_end_matches('/').as_bytes() {
                return StatusCode::FORBIDDEN.into_response();
            }
        }
    }
    next.run(req).await
}

fn tr(lang: Lang, en: &'static str, fr: &'static str) -> &'static str {
    if lang == Lang::Fr {
        fr
    } else {
        en
    }
}

// ------------------------------------------------------------------ layout

#[derive(Clone, Copy, PartialEq, Eq)]
enum Nav {
    Overview,
    Info,
    Security,
    Devices,
    Privacy,
}

fn initials(name: &str) -> String {
    let mut parts = name.split_whitespace().filter_map(|w| w.chars().next());
    let a = parts.next().unwrap_or('?');
    let b = parts.last();
    let mut s: String = a.to_uppercase().collect();
    if let Some(b) = b {
        s.extend(b.to_uppercase());
    }
    s
}

fn avatar(w: &Web, class: &str) -> String {
    if w.has_photo {
        format!("<img class=\"avatar {class}\" src=\"/account/photo\" alt=\"\">")
    } else {
        format!("<span class=\"avatar {class}\" aria-hidden=\"true\">{}</span>", escape(&initials(&w.name)))
    }
}

/// The bar at the top of every page: the Raye eye, the language, and the
/// account (or "Sign in").
pub fn top_bar(lang: Lang, who: Option<&Web>, here: &str) -> String {
    let other = if lang == Lang::Fr { ("en", "English") } else { ("fr", "Français") };
    let account = match who {
        None => format!("<a class=\"signin\" href=\"/signin\">{}</a>", tr(lang, "Sign in", "Se connecter")),
        Some(w) => format!(
            "<details class=\"me\"><summary aria-label=\"{label}\">{small}</summary>\
             <div class=\"flyout\" role=\"dialog\">\
             <div class=\"who\">{big}<div><strong>{name}</strong><span>{email}</span></div></div>\
             <a href=\"/account\">{mine}</a><a href=\"/account/info\">{info}</a>\
             <form method=\"post\" action=\"/signout\"><input type=\"hidden\" name=\"csrf\" value=\"{csrf}\">\
             <button type=\"submit\" class=\"link\">{out}</button></form></div></details>",
            label = tr(lang, "Account manager", "Gestionnaire de compte"),
            small = avatar(w, "small"),
            big = avatar(w, "big"),
            name = escape(&w.name),
            email = escape(&w.email),
            mine = tr(lang, "My Raye account", "Mon compte Raye"),
            info = tr(lang, "My profile", "Mon profil"),
            csrf = escape(&w.csrf),
            out = tr(lang, "Sign out", "Se déconnecter"),
        ),
    };
    format!(
        "<header class=\"bar\"><a class=\"brand\" href=\"/account\"><img src=\"/static/raye-eye.png\" alt=\"\" width=\"28\" height=\"28\">\
         <span>{brand}</span></a><nav class=\"tools\"><a class=\"lang\" href=\"/lang/{code}?back={back}\" lang=\"{code}\">{lname}</a>{account}</nav></header>",
        brand = tr(lang, "Raye account", "Compte Raye"),
        code = other.0,
        lname = other.1,
        back = escape(here),
    )
}

fn security_headers(app: &Shared, res: &mut Response, script: bool) {
    let upgrade = if app.config.https { "; upgrade-insecure-requests" } else { "" };
    let script = if script { "script-src 'self'; connect-src 'self'; " } else { "" };
    let csp = format!(
        "default-src 'none'; {script}style-src 'self'; img-src 'self'; form-action 'self'; \
         frame-ancestors 'none'; base-uri 'none'{upgrade}"
    );
    let h = res.headers_mut();
    h.insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_str(&csp).unwrap());
    h.insert(header::X_FRAME_OPTIONS, HeaderValue::from_static("DENY"));
    h.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
}

fn shell(app: &Shared, w: &Web, nav: Nav, here: &str, title: &str, body: &str) -> Response {
    let lang = w.lang;
    let item = |n: Nav, href: &str, label: &str| {
        let cur = if n == nav { " aria-current=\"page\"" } else { "" };
        format!("<a href=\"{href}\"{cur}>{label}</a>")
    };
    let side = format!(
        "<nav class=\"side\" aria-label=\"{}\">{}{}{}{}{}</nav>",
        tr(lang, "Account", "Compte"),
        item(Nav::Overview, "/account", tr(lang, "Home", "Accueil")),
        item(Nav::Info, "/account/info", tr(lang, "Your info", "Vos informations")),
        item(Nav::Security, "/account/security", tr(lang, "Security", "Sécurité")),
        item(Nav::Devices, "/account/devices", tr(lang, "Devices", "Appareils")),
        item(Nav::Privacy, "/account/privacy", tr(lang, "Privacy", "Confidentialité")),
    );
    let html = format!(
        "<!doctype html>\n<html lang=\"{l}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\">\
         <title>{t} - Raye</title><link rel=\"stylesheet\" href=\"/static/account.css\">\
         <script src=\"/static/account.js\" defer></script></head>\
         <body class=\"site\">{bar}<div class=\"layout\">{side}<main class=\"content\" data-csrf=\"{csrf}\">{body}</main></div></body></html>",
        l = if lang == Lang::Fr { "fr" } else { "en" },
        t = escape(title),
        bar = top_bar(lang, Some(w), here),
        csrf = escape(&w.csrf),
    );
    let mut res = Html(html).into_response();
    security_headers(app, &mut res, true);
    res
}

/// A page with the bar but no side menu: sign-in, a notice.
fn plain(app: &Shared, lang: Lang, who: Option<&Web>, title: &str, body: &str, status: StatusCode) -> Response {
    let html = format!(
        "<!doctype html>\n<html lang=\"{l}\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><meta name=\"robots\" content=\"noindex\">\
         <title>{t} - Raye</title><link rel=\"stylesheet\" href=\"/static/account.css\">\
         <script src=\"/static/account.js\" defer></script></head>\
         <body class=\"site\">{bar}<main class=\"card\">{body}</main></body></html>",
        l = if lang == Lang::Fr { "fr" } else { "en" },
        t = escape(title),
        bar = top_bar(lang, who, "/account"),
    );
    let mut res = (status, Html(html)).into_response();
    security_headers(app, &mut res, true);
    res
}

fn note(text: &str) -> String {
    format!("<p class=\"note\" role=\"status\">{}</p>", escape(text))
}

fn alert(text: &str) -> String {
    format!("<p class=\"error\" role=\"alert\">{}</p>", escape(text))
}

fn to_signin(next: &str) -> Response {
    Redirect::to(&format!("/signin?next={next}")).into_response()
}

fn back(path: &str) -> Response {
    Redirect::to(path).into_response()
}

#[derive(Deserialize)]
pub struct LangQuery {
    back: Option<String>,
}

/// `GET /lang/{code}`: remembers the language in a cookie and goes back.
pub async fn set_lang(State(app): State<Shared>, Path(code): Path<String>, Query(q): Query<LangQuery>) -> Response {
    let code = if code == "fr" { "fr" } else { "en" };
    let to = q.back.filter(|b| next_ok(b) || b == "/signin").unwrap_or_else(|| "/account".into());
    let mut res = Redirect::to(&to).into_response();
    res.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "raye_lang={code}; Path=/; SameSite=Lax; Max-Age=31536000{}",
            if app.config.https { "; Secure" } else { "" }
        ))
        .unwrap(),
    );
    res
}

// ----------------------------------------------------------------- sign-in

fn form_mac(app: &Shared, kind: &str, account: &str, ts: i64, next: &str) -> String {
    let mut m = <Hmac<Sha256>>::new_from_slice(&app.form_key).expect("any key length");
    m.update(format!("web-{kind}\n{account}\n{ts}\n{next}").as_bytes());
    URL_SAFE_NO_PAD.encode(m.finalize().into_bytes())
}

fn form_mac_ok(app: &Shared, kind: &str, account: &str, ts: i64, next: &str, mac: &str) -> bool {
    let now = OffsetDateTime::now_utc().unix_timestamp();
    ts <= now + 5 && now - ts <= STAGE_TTL_SECS && ct_eq(form_mac(app, kind, account, ts, next).as_bytes(), mac.as_bytes())
}

#[derive(Deserialize)]
pub struct SignInQuery {
    next: Option<String>,
}

pub async fn signin_page(State(app): State<Shared>, lang: Lang, MaybeWeb(who): MaybeWeb, Query(q): Query<SignInQuery>) -> Response {
    let next = q.next.filter(|n| next_ok(n)).unwrap_or_else(|| "/account".into());
    if who.as_ref().is_some_and(|w| w.recent) {
        return back(&next);
    }
    signin_form(&app, lang, &next, None, StatusCode::OK)
}

fn signin_form(app: &Shared, lang: Lang, next: &str, error: Option<&str>, status: StatusCode) -> Response {
    let ts = OffsetDateTime::now_utc().unix_timestamp();
    let mac = form_mac(app, "signin", "", ts, next);
    let body = format!(
        "<h1>{title}</h1><p class=\"lead\">{lead}</p>{err}\
         <form method=\"post\" action=\"/signin\"><input type=\"hidden\" name=\"action\" value=\"password\">\
         <input type=\"hidden\" name=\"next\" value=\"{next}\"><input type=\"hidden\" name=\"ts\" value=\"{ts}\">\
         <input type=\"hidden\" name=\"mac\" value=\"{mac}\">\
         <label for=\"email\">{email}</label><input id=\"email\" name=\"email\" type=\"email\" maxlength=\"254\" autocomplete=\"username webauthn\" required>\
         <label for=\"password\">{pw}</label><input id=\"password\" name=\"password\" type=\"password\" maxlength=\"1024\" autocomplete=\"current-password\" required>\
         <button type=\"submit\">{go}</button></form>\
         <button type=\"button\" class=\"secondary\" data-passkey=\"signin\" data-next=\"{next}\" hidden>{pk}</button>\
         <p class=\"switch\"><a href=\"/reset-password\">{forgot}</a></p>",
        title = tr(lang, "Sign in", "Se connecter"),
        lead = tr(lang, "Use your Raye account.", "Utilisez votre compte Raye."),
        err = error.map(alert).unwrap_or_default(),
        next = escape(next),
        email = tr(lang, "Email", "Adresse e-mail"),
        pw = tr(lang, "Password", "Mot de passe"),
        go = tr(lang, "Next", "Suivant"),
        pk = tr(lang, "Sign in with a passkey", "Se connecter avec une clé d'accès"),
        forgot = tr(lang, "Forgot your password?", "Mot de passe oublié ?"),
    );
    plain(app, lang, None, tr(lang, "Sign in", "Se connecter"), &body, status)
}

fn step_form(app: &Shared, lang: Lang, kind: &str, account: &Uuid, ts: i64, next: &str, error: Option<&str>, status: StatusCode) -> Response {
    let mac = form_mac(app, kind, &account.to_string(), ts, next);
    let (title, lead, action) = if kind == "totp" {
        (
            tr(lang, "Enter your code", "Entrez votre code"),
            tr(lang, "Enter the 6-digit code from your authenticator app, or a recovery code.", "Entrez le code à 6 chiffres de votre application d'authentification, ou un code de secours."),
            "totp",
        )
    } else {
        (
            tr(lang, "Check your email", "Consultez vos e-mails"),
            tr(lang, "We sent a 6-digit code to the address of your Raye account.", "Un code à 6 chiffres a été envoyé à l'adresse de votre compte Raye."),
            "emailcode",
        )
    };
    let hidden = format!(
        "<input type=\"hidden\" name=\"account\" value=\"{account}\"><input type=\"hidden\" name=\"ts\" value=\"{ts}\">\
         <input type=\"hidden\" name=\"next\" value=\"{}\"><input type=\"hidden\" name=\"mac\" value=\"{}\">",
        escape(next),
        escape(&mac)
    );
    let resend = if kind == "email" {
        format!(
            "<form method=\"post\" action=\"/signin\" class=\"inline\"><input type=\"hidden\" name=\"action\" value=\"emailcode-resend\">{hidden}\
             <button type=\"submit\" class=\"link\">{}</button></form>",
            tr(lang, "Send a new code", "Envoyer un nouveau code")
        )
    } else {
        String::new()
    };
    let body = format!(
        "<h1>{title}</h1><p class=\"lead\">{lead}</p>{err}<form method=\"post\" action=\"/signin\">\
         <input type=\"hidden\" name=\"action\" value=\"{action}\">{hidden}\
         <label for=\"code\">{label}</label><input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"32\" required autofocus>\
         <button type=\"submit\">{go}</button></form>{resend}",
        err = error.map(alert).unwrap_or_default(),
        label = tr(lang, "Code", "Code"),
        go = tr(lang, "Sign in", "Se connecter"),
    );
    plain(app, lang, None, title, &body, status)
}

#[derive(Deserialize)]
pub struct SignInForm {
    action: String,
    #[serde(default)]
    email: String,
    #[serde(default)]
    password: String,
    #[serde(default)]
    code: String,
    #[serde(default)]
    account: String,
    #[serde(default)]
    next: String,
    ts: i64,
    mac: String,
}

pub async fn signin_submit(
    State(app): State<Shared>,
    lang: Lang,
    ClientIp(ip): ClientIp,
    MaybeWeb(old): MaybeWeb,
    Form(f): Form<SignInForm>,
) -> Response {
    let next = if next_ok(&f.next) { f.next.clone() } else { "/account".into() };
    let expired = || signin_form(&app, lang, &next, Some(tr(lang, "This page was open too long. Try again.", "Cette page est restée ouverte trop longtemps. Réessayez.")), StatusCode::BAD_REQUEST);
    let too_many = tr(lang, "Too many tries. Wait a few minutes and try again.", "Trop de tentatives. Attendez quelques minutes, puis réessayez.");
    let ip_key = ip.to_string();
    if f.action == "password" {
        if !form_mac_ok(&app, "signin", "", f.ts, &f.next, &f.mac) {
            return expired();
        }
        if !app.limits.take("web-signin-ip", &ip_key, ratelimit::SIGN_IN_IP) {
            return signin_form(&app, lang, &next, Some(too_many), StatusCode::TOO_MANY_REQUESTS);
        }
        let Some(email) = crate::oauth::normalize_email(&f.email) else {
            return signin_form(&app, lang, &next, Some(tr(lang, "That email or password isn't right.", "L'adresse e-mail ou le mot de passe est incorrect.")), StatusCode::UNAUTHORIZED);
        };
        if !app.limits.has("signin-account", &email, ratelimit::SIGN_IN_ACCOUNT) {
            return signin_form(&app, lang, &next, Some(too_many), StatusCode::TOO_MANY_REQUESTS);
        }
        let id = match crate::oauth::sign_in(&app, &email, &f.password).await {
            Ok(Some(id)) => id,
            Ok(None) => {
                app.limits.take("signin-account", &email, ratelimit::SIGN_IN_ACCOUNT);
                return signin_form(&app, lang, &next, Some(tr(lang, "That email or password isn't right.", "L'adresse e-mail ou le mot de passe est incorrect.")), StatusCode::UNAUTHORIZED);
            }
            Err(e) => return e.into_response(),
        };
        let ts = OffsetDateTime::now_utc().unix_timestamp();
        match crate::twofactor::is_on(&app, id).await {
            Ok(true) => return step_form(&app, lang, "totp", &id, ts, &next, None, StatusCode::OK),
            Ok(false) => {}
            Err(e) => return e.into_response(),
        }
        match crate::emailcode::is_on(&app, id).await {
            Ok(true) => {
                return match crate::emailcode::send(&app, id).await {
                    Ok(true) => step_form(&app, lang, "email", &id, ts, &next, None, StatusCode::OK),
                    Ok(false) => step_form(&app, lang, "email", &id, ts, &next, Some(too_many), StatusCode::TOO_MANY_REQUESTS),
                    Err(e) => e.into_response(),
                }
            }
            Ok(false) => {}
            Err(e) => return e.into_response(),
        }
        return finish(&app, id, old, &next).await;
    }
    let kind = match f.action.as_str() {
        "totp" => "totp",
        "emailcode" | "emailcode-resend" => "email",
        _ => return expired(),
    };
    let Ok(id) = f.account.parse::<Uuid>() else { return expired() };
    if !form_mac_ok(&app, kind, &f.account, f.ts, &f.next, &f.mac) {
        return expired();
    }
    if f.action == "emailcode-resend" {
        return match crate::emailcode::send(&app, id).await {
            Ok(true) => step_form(&app, lang, kind, &id, f.ts, &next, None, StatusCode::OK),
            Ok(false) => step_form(&app, lang, kind, &id, f.ts, &next, Some(too_many), StatusCode::TOO_MANY_REQUESTS),
            Err(e) => e.into_response(),
        };
    }
    let bucket = if kind == "totp" { "totp-try" } else { "email-code-try" };
    if !app.limits.take(bucket, &f.account, ratelimit::TOTP_ACCOUNT) || !app.limits.take("web-code-ip", &ip_key, ratelimit::SIGN_IN_IP) {
        return step_form(&app, lang, kind, &id, f.ts, &next, Some(too_many), StatusCode::TOO_MANY_REQUESTS);
    }
    let totp_on = match crate::twofactor::is_on(&app, id).await {
        Ok(on) => on,
        Err(e) => return e.into_response(),
    };
    // The step must still be the one the account asks for.
    if (kind == "totp") != totp_on {
        return expired();
    }
    let ok = if kind == "totp" {
        crate::twofactor::check_second_factor(&app, id, &f.code).await
    } else {
        crate::emailcode::check(&app, id, &f.code).await
    };
    match ok {
        Ok(true) => finish(&app, id, old, &next).await,
        Ok(false) => step_form(&app, lang, kind, &id, f.ts, &next, Some(tr(lang, "That code isn't right.", "Ce code est incorrect.")), StatusCode::UNAUTHORIZED),
        Err(e) => e.into_response(),
    }
}

/// A new session for `account_id`; the one this browser had goes.
async fn finish(app: &Shared, account_id: Uuid, old: Option<Web>, next: &str) -> Response {
    if let Some(o) = old {
        let _ = sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1").bind(&o.token_hash).execute(&app.db).await;
    }
    match open_session(app, account_id).await {
        Ok(token) => {
            let mut res = back(next);
            set_cookie(app, &mut res, Some(&token));
            res
        }
        Err(e) => e.into_response(),
    }
}

#[derive(Deserialize)]
pub struct CsrfForm {
    #[serde(default)]
    csrf: String,
}

/// `POST /signout`: the session ends on the server, not only in the browser.
pub async fn signout(State(app): State<Shared>, lang: Lang, MaybeWeb(who): MaybeWeb, Form(f): Form<CsrfForm>) -> Response {
    if let Some(w) = who {
        if !w.csrf_ok(&f.csrf) {
            return bad_form(&app, lang);
        }
        if let Err(e) = sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1").bind(&w.token_hash).execute(&app.db).await {
            return Error::from(e).into_response();
        }
    }
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p><p class=\"switch\"><a href=\"/signin\">{}</a></p>",
        tr(lang, "You're signed out", "Vous êtes déconnecté"),
        tr(lang, "You signed out of your Raye account on this browser.", "Vous vous êtes déconnecté de votre compte Raye dans ce navigateur."),
        tr(lang, "Sign in again", "Se reconnecter")
    );
    let mut res = plain(&app, lang, None, tr(lang, "Signed out", "Déconnecté"), &body, StatusCode::OK);
    set_cookie(&app, &mut res, None);
    res
}

fn bad_form(app: &Shared, lang: Lang) -> Response {
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p><p class=\"switch\"><a href=\"/account\">{}</a></p>",
        tr(lang, "Something's wrong", "Un problème est survenu"),
        tr(lang, "This page was out of date. Go back and try again.", "Cette page n'était plus à jour. Revenez en arrière et réessayez."),
        tr(lang, "Back to your account", "Retour à votre compte")
    );
    plain(app, lang, None, tr(lang, "Something's wrong", "Un problème est survenu"), &body, StatusCode::FORBIDDEN)
}

// ------------------------------------------------------------------- pages

pub async fn home() -> Redirect {
    Redirect::to("/account")
}

pub async fn overview(State(app): State<Shared>, MaybeWeb(who): MaybeWeb) -> Response {
    let Some(w) = who else { return to_signin("/account") };
    let l = w.lang;
    let devices: (i64,) = match sqlx::query_as("SELECT count(*) FROM devices WHERE account_id = $1").bind(w.account_id).fetch_one(&app.db).await {
        Ok(n) => n,
        Err(e) => return Error::from(e).into_response(),
    };
    let tile = |href: &str, title: &str, text: &str| {
        format!("<a class=\"tile\" href=\"{href}\"><strong>{title}</strong><span>{text}</span></a>")
    };
    let body = format!(
        "<section class=\"hello\">{big}<div><h1>{name}</h1><p class=\"lead\">{email}</p></div></section>\
         <div class=\"tiles\">{a}{b}{c}{d}</div>",
        big = avatar(&w, "big"),
        name = escape(&w.name),
        email = escape(&w.email),
        a = tile("/account/info", tr(l, "Your info", "Vos informations"), tr(l, "Your name, photo and email.", "Votre nom, votre photo et votre adresse e-mail.")),
        b = tile("/account/security", tr(l, "Security", "Sécurité"), tr(l, "Password, sign-in codes, passkeys.", "Mot de passe, codes de connexion, clés d'accès.")),
        c = tile(
            "/account/devices",
            tr(l, "Devices", "Appareils"),
            &match (l, devices.0) {
                (Lang::Fr, n) => format!("{n} PC connecté(s) à ce compte."),
                (_, 1) => "1 PC signed in to this account.".to_owned(),
                (_, n) => format!("{n} PCs signed in to this account."),
            }
        ),
        d = tile("/account/privacy", tr(l, "Privacy", "Confidentialité"), tr(l, "Download your data or close the account.", "Téléchargez vos données ou fermez le compte.")),
    );
    shell(&app, &w, Nav::Overview, "/account", tr(l, "Your Raye account", "Votre compte Raye"), &body)
}

#[derive(Deserialize)]
pub struct Done {
    done: Option<String>,
}

fn done_note(l: Lang, d: &Done) -> String {
    let t = match d.done.as_deref() {
        Some("name") => tr(l, "Your name is changed.", "Votre nom est modifié."),
        Some("photo") => tr(l, "Your photo is changed. Your PCs pick it up within a few minutes.", "Votre photo est modifiée. Vos PC la récupèrent d'ici quelques minutes."),
        Some("photo-removed") => tr(l, "Your photo is removed.", "Votre photo est retirée."),
        Some("password") => tr(l, "Your password is changed. Other browsers are signed out.", "Votre mot de passe est changé. Les autres navigateurs sont déconnectés."),
        Some("email-code") => tr(l, "Saved.", "Enregistré."),
        Some("totp-off") => tr(l, "The authenticator app is turned off.", "L'application d'authentification est désactivée."),
        Some("passkey") => tr(l, "Saved.", "Enregistré."),
        Some("device") => tr(l, "That PC is signed out.", "Ce PC est déconnecté."),
        Some("error") => return alert(tr(l, "That didn't work. Check what you entered and try again.", "Cela n'a pas fonctionné. Vérifiez ce que vous avez entré, puis réessayez.")),
        _ => return String::new(),
    };
    note(t)
}

fn csrf_field(w: &Web) -> String {
    format!("<input type=\"hidden\" name=\"csrf\" value=\"{}\">", escape(&w.csrf))
}

pub async fn info(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Query(d): Query<Done>) -> Response {
    let Some(w) = who else { return to_signin("/account/info") };
    let l = w.lang;
    let remove = if w.has_photo {
        format!(
            "<form method=\"post\" action=\"/account/info/photo/remove\">{}<button type=\"submit\" class=\"secondary\">{}</button></form>",
            csrf_field(&w),
            tr(l, "Remove photo", "Retirer la photo")
        )
    } else {
        String::new()
    };
    let body = format!(
        "<h1>{title}</h1>{done}\
         <section class=\"panel\"><h2>{photo}</h2><div class=\"row\">{big}<div>\
         <form method=\"post\" action=\"/account/info/photo\" enctype=\"multipart/form-data\">{csrf}\
         <label for=\"photo\">{choose}</label><input id=\"photo\" name=\"photo\" type=\"file\" accept=\"image/png,image/jpeg,image/webp\" required>\
         <p class=\"hint\">{hint}</p><button type=\"submit\">{save}</button></form>{remove}</div></div></section>\
         <section class=\"panel\"><h2>{name_t}</h2><form method=\"post\" action=\"/account/info/name\">{csrf}\
         <label for=\"display_name\">{name_l}</label><input id=\"display_name\" name=\"display_name\" maxlength=\"64\" autocomplete=\"name\" required value=\"{name}\">\
         <button type=\"submit\">{save}</button></form></section>\
         <section class=\"panel\"><h2>{email_t}</h2><p>{email}</p><p class=\"hint\">{email_h}</p></section>",
        title = tr(l, "Your info", "Vos informations"),
        done = done_note(l, &d),
        photo = tr(l, "Profile photo", "Photo de profil"),
        big = avatar(&w, "big"),
        csrf = csrf_field(&w),
        choose = tr(l, "Choose a picture", "Choisir une image"),
        hint = tr(l, "PNG, JPEG or WebP, up to 2 MB. It is cropped to a square from the middle.", "PNG, JPEG ou WebP, 2 Mo au plus. L'image est recadrée en carré à partir du centre."),
        save = tr(l, "Save", "Enregistrer"),
        name_t = tr(l, "Name", "Nom"),
        name_l = tr(l, "Your name", "Votre nom"),
        name = escape(&w.name),
        email_t = tr(l, "Email", "Adresse e-mail"),
        email = escape(&w.email),
        email_h = tr(l, "This is the address you sign in with. It is confirmed.", "C'est l'adresse avec laquelle vous vous connectez. Elle est confirmée."),
    );
    shell(&app, &w, Nav::Info, "/account/info", tr(l, "Your info", "Vos informations"), &body)
}

#[derive(Deserialize)]
pub struct NameForm {
    csrf: String,
    display_name: String,
}

pub async fn set_name(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<NameForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/info") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    let body = serde_json::from_value(json!({ "display_name": f.display_name })).expect("one field");
    match crate::me::patch_me(State(app), w.as_auth(), Json(body)).await {
        Ok(_) => back("/account/info?done=name"),
        Err(_) => back("/account/info?done=error"),
    }
}

pub async fn set_photo(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, mut form: Multipart) -> Response {
    let Some(w) = who else { return to_signin("/account/info") };
    let mut csrf = String::new();
    let mut photo = None;
    while let Ok(Some(field)) = form.next_field().await {
        match field.name() {
            Some("csrf") => csrf = field.text().await.unwrap_or_default(),
            Some("photo") => photo = field.bytes().await.ok(),
            _ => {}
        }
    }
    if !w.csrf_ok(&csrf) {
        return bad_form(&app, w.lang);
    }
    let Some(bytes) = photo else { return back("/account/info?done=error") };
    match crate::me::put_avatar(State(app), w.as_auth(), bytes).await {
        Ok(_) => back("/account/info?done=photo"),
        Err(_) => back("/account/info?done=error"),
    }
}

pub async fn remove_photo(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<CsrfForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/info") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    match crate::me::delete_avatar(State(app), w.as_auth()).await {
        Ok(_) => back("/account/info?done=photo-removed"),
        Err(e) => e.into_response(),
    }
}

/// `GET /account/photo`: the signed-in account's own picture.
pub async fn photo(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, headers: HeaderMap) -> Response {
    let Some(w) = who else { return StatusCode::NOT_FOUND.into_response() };
    let mut res = match crate::me::get_avatar(State(app), w.as_auth(), headers).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("private, no-cache"));
    res.headers_mut().insert(header::CONTENT_SECURITY_POLICY, HeaderValue::from_static("default-src 'none'; sandbox"));
    res
}

// ---------------------------------------------------------------- security

pub async fn security(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Query(d): Query<Done>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    let l = w.lang;
    let row: std::result::Result<(bool, bool, i64), sqlx::Error> = sqlx::query_as(
        "SELECT totp_enabled, email_code_signin,
                (SELECT count(*) FROM totp_recovery_codes r WHERE r.account_id = a.id AND r.used_at IS NULL)
         FROM accounts a WHERE id = $1",
    )
    .bind(w.account_id)
    .fetch_one(&app.db)
    .await;
    let (totp, email_code, recovery) = match row {
        Ok(r) => r,
        Err(e) => return Error::from(e).into_response(),
    };
    let keys: Vec<(Uuid, String, OffsetDateTime)> = match sqlx::query_as(
        "SELECT id, name, created_at FROM passkeys WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(w.account_id)
    .fetch_all(&app.db)
    .await
    {
        Ok(k) => k,
        Err(e) => return Error::from(e).into_response(),
    };
    let csrf = csrf_field(&w);
    let switch = |on: bool, action: &str| {
        let (label, value) = if on { (tr(l, "Turn off", "Désactiver"), "off") } else { (tr(l, "Turn on", "Activer"), "on") };
        format!(
            "<form method=\"post\" action=\"{action}\" class=\"inline\">{csrf}<input type=\"hidden\" name=\"to\" value=\"{value}\">\
             <button type=\"submit\" class=\"secondary\">{label}</button></form>"
        )
    };
    let state = |on: bool| if on { tr(l, "On", "Activé") } else { tr(l, "Off", "Désactivé") };
    let totp_html = if totp {
        format!(
            "<p>{}</p><p class=\"hint\">{}</p>{}{}",
            state(true),
            escape(&match l {
                Lang::Fr => format!("{recovery} code(s) de secours inutilisé(s)."),
                Lang::En => format!("{recovery} unused recovery code(s)."),
            }),
            switch(true, "/account/security/totp/off"),
            format_args!(
                "<form method=\"post\" action=\"/account/security/recovery\" class=\"inline\">{csrf}<button type=\"submit\" class=\"secondary\">{}</button></form>",
                tr(l, "New recovery codes", "Nouveaux codes de secours")
            )
        )
    } else {
        format!(
            "<p>{}</p><form method=\"post\" action=\"/account/security/totp/start\" class=\"inline\">{csrf}<button type=\"submit\">{}</button></form>",
            state(false),
            tr(l, "Set up an authenticator app", "Configurer une application d'authentification")
        )
    };
    let key_rows: String = keys
        .iter()
        .map(|(id, name, created)| {
            format!(
                "<li><span><strong>{}</strong><span class=\"hint\">{}</span></span>\
                 <form method=\"post\" action=\"/account/security/passkeys/{id}/remove\" class=\"inline\">{csrf}\
                 <button type=\"submit\" class=\"secondary\">{}</button></form></li>",
                escape(name),
                escape(&format!("{}-{:02}-{:02}", created.year(), created.month() as u8, created.day())),
                tr(l, "Remove", "Retirer")
            )
        })
        .collect();
    let body = format!(
        "<h1>{title}</h1>{done}\
         <section class=\"panel\"><h2>{pw_t}</h2><form method=\"post\" action=\"/account/security/password\">{csrf}\
         <label for=\"current\">{cur}</label><input id=\"current\" name=\"current\" type=\"password\" autocomplete=\"current-password\" maxlength=\"1024\" required>\
         <label for=\"password\">{new}</label><input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"new-password\" maxlength=\"1024\" required>\
         <label for=\"password2\">{new2}</label><input id=\"password2\" name=\"password2\" type=\"password\" autocomplete=\"new-password\" maxlength=\"1024\" required>\
         <p class=\"hint\">{hint}</p><button type=\"submit\">{change}</button></form></section>\
         <section class=\"panel\"><h2>{ec_t}</h2><p class=\"hint\">{ec_h}</p><p>{ec_s}</p>{ec_sw}</section>\
         <section class=\"panel\"><h2>{totp_t}</h2><p class=\"hint\">{totp_h}</p>{totp_html}</section>\
         <section class=\"panel\"><h2>{pk_t}</h2><p class=\"hint\">{pk_h}</p><ul class=\"list\">{key_rows}</ul>\
         <div class=\"passkey-add\" hidden><label for=\"pkname\">{pk_name}</label><input id=\"pkname\" maxlength=\"64\" value=\"{pk_default}\">\
         <button type=\"button\" data-passkey=\"register\">{pk_add}</button><p class=\"error\" role=\"alert\" hidden></p></div>\
         <p class=\"hint nojs\">{pk_js}</p></section>",
        title = tr(l, "Security", "Sécurité"),
        done = done_note(l, &d),
        pw_t = tr(l, "Password", "Mot de passe"),
        cur = tr(l, "Current password", "Mot de passe actuel"),
        new = tr(l, "New password", "Nouveau mot de passe"),
        new2 = tr(l, "New password again", "Nouveau mot de passe, encore"),
        hint = tr(l, "At least 10 characters.", "Au moins 10 caractères."),
        change = tr(l, "Change password", "Changer le mot de passe"),
        ec_t = tr(l, "Code by email at sign-in", "Code par e-mail à la connexion"),
        ec_h = tr(l, "After your password, we send a code to your email. Accounts with an authenticator app use the app instead.", "Après votre mot de passe, un code est envoyé à votre adresse. Les comptes avec une application d'authentification utilisent l'application."),
        ec_s = state(email_code),
        ec_sw = switch(email_code, "/account/security/email-code"),
        totp_t = tr(l, "Authenticator app", "Application d'authentification"),
        totp_h = tr(l, "A 6-digit code from an app on your phone, asked after your password.", "Un code à 6 chiffres d'une application sur votre téléphone, demandé après votre mot de passe."),
        pk_t = tr(l, "Passkeys", "Clés d'accès"),
        pk_h = tr(l, "Sign in with your fingerprint, face or a security key, without a password.", "Connectez-vous avec votre empreinte, votre visage ou une clé de sécurité, sans mot de passe."),
        pk_name = tr(l, "Name for this passkey", "Nom de cette clé d'accès"),
        pk_default = tr(l, "My passkey", "Ma clé d'accès"),
        pk_add = tr(l, "Add a passkey", "Ajouter une clé d'accès"),
        pk_js = tr(l, "Passkeys need a browser that supports them.", "Les clés d'accès demandent un navigateur compatible."),
    );
    shell(&app, &w, Nav::Security, "/account/security", tr(l, "Security", "Sécurité"), &body)
}

#[derive(Deserialize)]
pub struct PasswordForm {
    csrf: String,
    current: String,
    password: String,
    password2: String,
}

pub async fn change_password(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<PasswordForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if f.password != f.password2 || !crate::oauth::password_ok(&f.password) {
        return back("/account/security?done=error");
    }
    let key = w.account_id.to_string();
    if !app.limits.has("web-password", &key, ratelimit::SIGN_IN_ACCOUNT) {
        return back("/account/security?done=error");
    }
    let stored: (String,) = match sqlx::query_as("SELECT password_hash FROM accounts WHERE id = $1").bind(w.account_id).fetch_one(&app.db).await {
        Ok(s) => s,
        Err(e) => return Error::from(e).into_response(),
    };
    match crate::oauth::check_password(&app, f.current, stored.0).await {
        Ok(true) => {}
        Ok(false) => {
            app.limits.take("web-password", &key, ratelimit::SIGN_IN_ACCOUNT);
            return back("/account/security?done=error");
        }
        Err(e) => return e.into_response(),
    }
    let hash = match crate::oauth::new_hash(&app, f.password).await {
        Ok(h) => h,
        Err(e) => return e.into_response(),
    };
    let done = async {
        let mut tx = app.db.begin().await?;
        sqlx::query("UPDATE accounts SET password_hash = $2, updated_at = now() WHERE id = $1").bind(w.account_id).bind(hash).execute(&mut *tx).await?;
        sqlx::query("DELETE FROM web_sessions WHERE account_id = $1 AND token_hash <> $2").bind(w.account_id).bind(&w.token_hash).execute(&mut *tx).await?;
        tx.commit().await?;
        Ok::<_, sqlx::Error>(())
    }
    .await;
    match done {
        Ok(()) => {
            tracing::info!(account_id = %w.account_id, "password changed on the website");
            back("/account/security?done=password")
        }
        Err(e) => Error::from(e).into_response(),
    }
}

#[derive(Deserialize)]
pub struct SwitchForm {
    csrf: String,
    to: String,
}

pub async fn email_code_switch(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<SwitchForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    let on = f.to == "on";
    // Taking a protection off needs the password proven a moment ago.
    if !on && !w.recent {
        return to_signin("/account/security");
    }
    match crate::emailcode::set(&app, w.account_id, on).await {
        Ok(()) => back("/account/security?done=email-code"),
        Err(e) => e.into_response(),
    }
}

pub async fn totp_off(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<CsrfForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if !w.recent {
        return to_signin("/account/security");
    }
    match crate::twofactor::turn_off(&app, w.account_id).await {
        Ok(()) => back("/account/security?done=totp-off"),
        Err(e) => e.into_response(),
    }
}

pub async fn totp_start(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<CsrfForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if !w.recent {
        return to_signin("/account/security");
    }
    let l = w.lang;
    let e = match crate::twofactor::start(State(app.clone()), w.as_auth()).await {
        Ok(e) => e.0,
        Err(_) => return back("/account/security?done=error"),
    };
    let qr = qrcode::QrCode::new(e.otpauth_uri.as_bytes())
        .map(|c| c.render::<qrcode::render::svg::Color>().min_dimensions(200, 200).dark_color(qrcode::render::svg::Color("#0e0a17")).light_color(qrcode::render::svg::Color("#ffffff")).build())
        .unwrap_or_default();
    // The renderer writes an XML declaration first; inline SVG does not want it.
    let qr = qr.find("<svg").map(|i| qr[i..].to_owned()).unwrap_or_default();
    let body = format!(
        "<h1>{t}</h1><ol class=\"steps\"><li>{s1}</li><li>{s2}</li></ol>\
         <div class=\"qr\" role=\"img\" aria-label=\"{qa}\">{qr}</div><p class=\"hint\">{manual}</p><p class=\"secret\">{secret}</p>\
         <form method=\"post\" action=\"/account/security/totp/confirm\">{csrf}\
         <label for=\"code\">{code}</label><input id=\"code\" name=\"code\" inputmode=\"numeric\" autocomplete=\"one-time-code\" maxlength=\"8\" required autofocus>\
         <button type=\"submit\">{go}</button></form>",
        t = tr(l, "Set up an authenticator app", "Configurer une application d'authentification"),
        s1 = tr(l, "In your authenticator app, add an account and scan this code.", "Dans votre application d'authentification, ajoutez un compte et scannez ce code."),
        s2 = tr(l, "Enter the 6-digit code the app shows.", "Entrez le code à 6 chiffres affiché par l'application."),
        qa = tr(l, "QR code for your authenticator app", "Code QR pour votre application d'authentification"),
        manual = tr(l, "Can't scan it? Type this key instead:", "Impossible de le scanner ? Entrez plutôt cette clé :"),
        secret = escape(&e.secret),
        csrf = csrf_field(&w),
        code = tr(l, "Code", "Code"),
        go = tr(l, "Turn on", "Activer"),
    );
    shell(&app, &w, Nav::Security, "/account/security", tr(l, "Security", "Sécurité"), &body)
}

#[derive(Deserialize)]
pub struct CodeForm {
    csrf: String,
    code: String,
}

fn recovery_page(app: &Shared, w: &Web, codes: &[String]) -> Response {
    let l = w.lang;
    let list: String = codes.iter().map(|c| format!("<li><code>{}</code></li>", escape(c))).collect();
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p><ul class=\"codes\">{list}</ul><p><a class=\"button\" href=\"/account/security\">{}</a></p>",
        tr(l, "Your recovery codes", "Vos codes de secours"),
        tr(l, "Keep these somewhere safe. Each one works once if you lose your phone. They are shown only now.", "Gardez-les en lieu sûr. Chacun fonctionne une fois si vous perdez votre téléphone. Ils ne sont affichés que maintenant."),
        tr(l, "Done", "Terminé")
    );
    shell(app, w, Nav::Security, "/account/security", tr(l, "Security", "Sécurité"), &body)
}

pub async fn totp_confirm(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<CodeForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if !w.recent {
        return to_signin("/account/security");
    }
    let body = serde_json::from_value(json!({ "code": f.code })).expect("one field");
    match crate::twofactor::confirm(State(app.clone()), w.as_auth(), Json(body)).await {
        Ok(v) => {
            let codes: Vec<String> = v.0["recovery_codes"].as_array().map(|a| a.iter().filter_map(|c| c.as_str().map(str::to_owned)).collect()).unwrap_or_default();
            recovery_page(&app, &w, &codes)
        }
        Err(_) => back("/account/security?done=error"),
    }
}

pub async fn new_recovery(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<CsrfForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if !w.recent {
        return to_signin("/account/security");
    }
    match crate::twofactor::replace_recovery_codes(&app, w.account_id).await {
        Ok(codes) => recovery_page(&app, &w, &codes),
        Err(e) => e.into_response(),
    }
}

// ----------------------------------------------------------------- devices

pub async fn devices(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Query(d): Query<Done>) -> Response {
    let Some(w) = who else { return to_signin("/account/devices") };
    let l = w.lang;
    let list = match crate::devices::list(State(app.clone()), w.as_auth()).await {
        Ok(v) => v.0,
        Err(e) => return e.into_response(),
    };
    let csrf = csrf_field(&w);
    let rows: String = list
        .iter()
        .map(|d| {
            format!(
                "<li><span><strong>{name}</strong><span class=\"hint\">{model} · Raye {ver} · {seen} {when}</span></span>\
                 <form method=\"post\" action=\"/account/devices/{id}/remove\" class=\"inline\">{csrf}\
                 <button type=\"submit\" class=\"secondary\">{out}</button></form></li>",
                name = escape(&d.name),
                model = escape(&d.model),
                ver = escape(&d.raye_version),
                seen = tr(l, "last seen", "vu le"),
                when = escape(&d.last_seen_at.replace('T', " ").chars().take(16).collect::<String>()),
                id = d.id,
                out = tr(l, "Sign out", "Déconnecter"),
            )
        })
        .collect();
    let empty = if list.is_empty() { format!("<p>{}</p>", tr(l, "No PC is signed in to this account.", "Aucun PC n'est connecté à ce compte.")) } else { String::new() };
    let body = format!(
        "<h1>{}</h1><p class=\"lead\">{}</p>{}<section class=\"panel\"><ul class=\"list\">{rows}</ul>{empty}</section>",
        tr(l, "Devices", "Appareils"),
        tr(l, "Every PC signed in to your Raye account. Signing one out also stops its sync until someone signs in again on it.", "Chaque PC connecté à votre compte Raye. En déconnecter un arrête aussi sa synchronisation jusqu'à une nouvelle connexion."),
        done_note(l, &d),
    );
    shell(&app, &w, Nav::Devices, "/account/devices", tr(l, "Devices", "Appareils"), &body)
}

pub async fn remove_device(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Path(id): Path<Uuid>, Form(f): Form<CsrfForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/devices") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    match crate::devices::remove(State(app), w.as_auth(), Path(id)).await {
        Ok(_) => back("/account/devices?done=device"),
        Err(_) => back("/account/devices?done=error"),
    }
}

// ----------------------------------------------------------------- privacy

pub async fn privacy(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Query(d): Query<Done>) -> Response {
    let Some(w) = who else { return to_signin("/account/privacy") };
    let l = w.lang;
    let body = format!(
        "<h1>{t}</h1>{done}<section class=\"panel\"><h2>{dl_t}</h2><p class=\"hint\">{dl_h}</p><p><a class=\"button\" href=\"/account/privacy/export\">{dl}</a></p></section>\
         <section class=\"panel danger\"><h2>{del_t}</h2><p class=\"hint\">{del_h}</p>\
         <form method=\"post\" action=\"/account/privacy/delete\">{csrf}<label for=\"password\">{pw}</label>\
         <input id=\"password\" name=\"password\" type=\"password\" autocomplete=\"current-password\" maxlength=\"1024\" required>\
         <label class=\"check\"><input type=\"checkbox\" name=\"sure\" value=\"yes\" required> {sure}</label>\
         <button type=\"submit\" class=\"danger\">{del}</button></form></section>",
        t = tr(l, "Privacy", "Confidentialité"),
        done = done_note(l, &d),
        dl_t = tr(l, "Download your data", "Télécharger vos données"),
        dl_h = tr(l, "One file with everything this account holds: your profile, devices, settings and Store library.", "Un fichier avec tout ce que ce compte contient : profil, appareils, paramètres et bibliothèque du Store."),
        dl = tr(l, "Download", "Télécharger"),
        del_t = tr(l, "Close your account", "Fermer votre compte"),
        del_h = tr(l, "Your account and everything in it are deleted right away. Every PC is signed out. This can't be undone.", "Votre compte et tout ce qu'il contient sont supprimés tout de suite. Chaque PC est déconnecté. C'est définitif."),
        csrf = csrf_field(&w),
        pw = tr(l, "Your password", "Votre mot de passe"),
        sure = tr(l, "I understand this deletes my account.", "Je comprends que cela supprime mon compte."),
        del = tr(l, "Close my account", "Fermer mon compte"),
    );
    shell(&app, &w, Nav::Privacy, "/account/privacy", tr(l, "Privacy", "Confidentialité"), &body)
}

pub async fn export(State(app): State<Shared>, MaybeWeb(who): MaybeWeb) -> Response {
    let Some(w) = who else { return to_signin("/account/privacy") };
    if !w.recent {
        return to_signin("/account/privacy");
    }
    let mut res = match crate::me::export(State(app), w.as_auth()).await {
        Ok(r) => r,
        Err(e) => return e.into_response(),
    };
    res.headers_mut().insert(header::CONTENT_DISPOSITION, HeaderValue::from_static("attachment; filename=\"raye-account.json\""));
    res.headers_mut().insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    res
}

#[derive(Deserialize)]
pub struct DeleteForm {
    csrf: String,
    password: String,
    #[serde(default)]
    sure: String,
}

pub async fn delete(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Form(f): Form<DeleteForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/privacy") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if !w.recent {
        return to_signin("/account/security");
    }
    if f.sure != "yes" {
        return back("/account/privacy?done=error");
    }
    let l = w.lang;
    let body = serde_json::from_value(json!({ "password": f.password })).expect("one field");
    match crate::me::delete_account(State(app.clone()), w.as_auth(), Json(body)).await {
        Ok(_) => {
            let body = format!(
                "<h1>{}</h1><p class=\"lead\">{}</p>",
                tr(l, "Your account is closed", "Votre compte est fermé"),
                tr(l, "Your Raye account and everything in it are deleted.", "Votre compte Raye et tout ce qu'il contenait sont supprimés.")
            );
            let mut res = plain(&app, l, None, tr(l, "Account closed", "Compte fermé"), &body, StatusCode::OK);
            set_cookie(&app, &mut res, None);
            res
        }
        Err(_) => back("/account/privacy?done=error"),
    }
}

// ---------------------------------------------------------------- passkeys

fn webauthn(app: &Shared) -> Result<&webauthn_rs::Webauthn> {
    app.webauthn.as_ref().ok_or(Error::Unsupported("passkeys are not available on this server"))
}

async fn keep_ceremony(app: &Shared, kind: &str, account: Option<Uuid>, state: serde_json::Value) -> Result<Uuid> {
    let id = Uuid::new_v4();
    sqlx::query("DELETE FROM webauthn_ceremonies WHERE expires_at < now()").execute(&app.db).await?;
    sqlx::query("INSERT INTO webauthn_ceremonies (id, kind, account_id, state, expires_at) VALUES ($1, $2, $3, $4, now() + interval '2 minutes')")
        .bind(id)
        .bind(kind)
        .bind(account)
        .bind(state)
        .execute(&app.db)
        .await?;
    Ok(id)
}

async fn take_ceremony(app: &Shared, id: Uuid, kind: &str) -> Result<(Option<Uuid>, serde_json::Value)> {
    let row: Option<(Option<Uuid>, serde_json::Value)> = sqlx::query_as(
        "DELETE FROM webauthn_ceremonies WHERE id = $1 AND kind = $2 AND expires_at > now() RETURNING account_id, state",
    )
    .bind(id)
    .bind(kind)
    .fetch_optional(&app.db)
    .await?;
    row.ok_or(Error::BadRequest("this request expired; try again"))
}

fn json_csrf(w: &Web, headers: &HeaderMap) -> Result<()> {
    let presented = headers.get("x-csrf-token").and_then(|v| v.to_str().ok()).unwrap_or("");
    if w.csrf_ok(presented) {
        Ok(())
    } else {
        Err(Error::Forbidden)
    }
}

pub async fn passkey_register_start(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, headers: HeaderMap) -> Result<Json<serde_json::Value>> {
    let w = who.ok_or(Error::Unauthorized)?;
    json_csrf(&w, &headers)?;
    if !w.recent {
        return Err(Error::Forbidden);
    }
    let wa = webauthn(&app)?;
    let existing: Vec<(serde_json::Value,)> = sqlx::query_as("SELECT passkey FROM passkeys WHERE account_id = $1").bind(w.account_id).fetch_all(&app.db).await?;
    let exclude: Vec<_> = existing
        .into_iter()
        .filter_map(|(p,)| serde_json::from_value::<webauthn_rs::prelude::Passkey>(p).ok())
        .map(|p| p.cred_id().clone())
        .collect();
    let (mut ccr, state) = wa
        .start_passkey_registration(w.account_id, &w.email, &w.name, Some(exclude))
        .map_err(|e| Error::Internal(e.to_string()))?;
    // Discoverable, so it can sign in without typing the address first.
    if let Some(sel) = ccr.public_key.authenticator_selection.as_mut() {
        sel.resident_key = Some(webauthn_rs_proto::ResidentKeyRequirement::Required);
        sel.require_resident_key = true;
    }
    let id = keep_ceremony(&app, "register", Some(w.account_id), serde_json::to_value(&state).map_err(|e| Error::Internal(e.to_string()))?).await?;
    Ok(Json(json!({ "ceremony": id, "options": ccr })))
}

#[derive(Deserialize)]
pub struct RegisterFinish {
    ceremony: Uuid,
    name: String,
    credential: webauthn_rs::prelude::RegisterPublicKeyCredential,
}

pub async fn passkey_register_finish(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, headers: HeaderMap, Json(b): Json<RegisterFinish>) -> Result<Json<serde_json::Value>> {
    let w = who.ok_or(Error::Unauthorized)?;
    json_csrf(&w, &headers)?;
    let wa = webauthn(&app)?;
    let (account, state) = take_ceremony(&app, b.ceremony, "register").await?;
    if account != Some(w.account_id) {
        return Err(Error::Forbidden);
    }
    let state: webauthn_rs::prelude::PasskeyRegistration = serde_json::from_value(state).map_err(|e| Error::Internal(e.to_string()))?;
    let key = wa.finish_passkey_registration(&b.credential, &state).map_err(|_| Error::BadRequest("this passkey could not be added"))?;
    let name = b.name.trim();
    let name = if crate::oauth::display_name_ok(name) { name } else { "Passkey" };
    let n: (i64,) = sqlx::query_as("SELECT count(*) FROM passkeys WHERE account_id = $1").bind(w.account_id).fetch_one(&app.db).await?;
    if n.0 >= 20 {
        return Err(Error::BadRequest("too many passkeys: remove one first"));
    }
    let done = sqlx::query("INSERT INTO passkeys (id, account_id, credential_id, passkey, name) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (credential_id) DO NOTHING")
        .bind(Uuid::new_v4())
        .bind(w.account_id)
        .bind(key.cred_id().as_ref())
        .bind(serde_json::to_value(&key).map_err(|e| Error::Internal(e.to_string()))?)
        .bind(name)
        .execute(&app.db)
        .await?;
    if done.rows_affected() == 0 {
        return Err(Error::BadRequest("this passkey is already in use"));
    }
    tracing::info!(account_id = %w.account_id, "passkey added");
    Ok(Json(json!({ "next": "/account/security?done=passkey" })))
}

pub async fn passkey_remove(State(app): State<Shared>, MaybeWeb(who): MaybeWeb, Path(id): Path<Uuid>, Form(f): Form<CsrfForm>) -> Response {
    let Some(w) = who else { return to_signin("/account/security") };
    if !w.csrf_ok(&f.csrf) {
        return bad_form(&app, w.lang);
    }
    if !w.recent {
        return to_signin("/account/security");
    }
    match sqlx::query("DELETE FROM passkeys WHERE id = $1 AND account_id = $2").bind(id).bind(w.account_id).execute(&app.db).await {
        Ok(_) => back("/account/security?done=passkey"),
        Err(e) => Error::from(e).into_response(),
    }
}

/// The start of a passkey sign-in (or of a reset by passkey): the browser
/// asks the authenticator for any passkey of this site.
pub async fn passkey_auth_start(State(app): State<Shared>, ClientIp(ip): ClientIp, Path(kind): Path<String>) -> Result<Json<serde_json::Value>> {
    let kind = if kind == "reset" { "reset" } else { "sign-in" };
    if !app.limits.take("passkey-ip", &ip.to_string(), ratelimit::SIGN_IN_IP) {
        return Err(Error::TooMany);
    }
    let wa = webauthn(&app)?;
    let (mut rcr, state) = wa.start_discoverable_authentication().map_err(|e| Error::Internal(e.to_string()))?;
    // Shown when the person presses the button, not in the address field.
    rcr.mediation = None;
    let id = keep_ceremony(&app, kind, None, serde_json::to_value(&state).map_err(|e| Error::Internal(e.to_string()))?).await?;
    Ok(Json(json!({ "ceremony": id, "options": rcr })))
}

#[derive(Deserialize)]
pub struct AuthFinish {
    ceremony: Uuid,
    #[serde(default)]
    next: String,
    credential: webauthn_rs::prelude::PublicKeyCredential,
}

/// Checks the assertion and returns the account it belongs to.
async fn passkey_account(app: &Shared, kind: &str, b: &AuthFinish) -> Result<Uuid> {
    let wa = webauthn(app)?;
    let (_, state) = take_ceremony(app, b.ceremony, kind).await?;
    let state: webauthn_rs::prelude::DiscoverableAuthentication = serde_json::from_value(state).map_err(|e| Error::Internal(e.to_string()))?;
    let (account, cred_id) = wa.identify_discoverable_authentication(&b.credential).map_err(|_| Error::Unauthorized)?;
    let row: Option<(Uuid, serde_json::Value)> = sqlx::query_as("SELECT id, passkey FROM passkeys WHERE account_id = $1 AND credential_id = $2")
        .bind(account)
        .bind(cred_id)
        .fetch_optional(&app.db)
        .await?;
    let (row_id, stored) = row.ok_or(Error::Unauthorized)?;
    let mut key: webauthn_rs::prelude::Passkey = serde_json::from_value(stored).map_err(|e| Error::Internal(e.to_string()))?;
    let result = wa.finish_discoverable_authentication(&b.credential, state, &[(&key).into()]).map_err(|e| {
        tracing::warn!(%account, error = %e, "a passkey assertion was refused");
        Error::Unauthorized
    })?;
    if !result.user_verified() {
        return Err(Error::Unauthorized);
    }
    key.update_credential(&result);
    sqlx::query("UPDATE passkeys SET passkey = $2, last_used_at = now() WHERE id = $1")
        .bind(row_id)
        .bind(serde_json::to_value(&key).map_err(|e| Error::Internal(e.to_string()))?)
        .execute(&app.db)
        .await?;
    let verified: Option<(bool,)> = sqlx::query_as("SELECT email_verified FROM accounts WHERE id = $1").bind(account).fetch_optional(&app.db).await?;
    if verified.map(|v| v.0) != Some(true) {
        return Err(Error::Unauthorized);
    }
    Ok(account)
}

pub async fn passkey_signin_finish(State(app): State<Shared>, MaybeWeb(old): MaybeWeb, Json(b): Json<AuthFinish>) -> Result<Response> {
    let account = passkey_account(&app, "sign-in", &b).await?;
    if let Some(o) = old {
        sqlx::query("DELETE FROM web_sessions WHERE token_hash = $1").bind(&o.token_hash).execute(&app.db).await?;
    }
    let token = open_session(&app, account).await?;
    let next = if next_ok(&b.next) { b.next.clone() } else { "/account".into() };
    let mut res = Json(json!({ "next": next })).into_response();
    set_cookie(&app, &mut res, Some(&token));
    Ok(res)
}

pub async fn passkey_reset_finish(State(app): State<Shared>, Json(b): Json<AuthFinish>) -> Result<Json<serde_json::Value>> {
    let account = passkey_account(&app, "reset", &b).await?;
    let token = crate::email::issue_reset_for(&app, account).await?;
    let (email,): (String,) = sqlx::query_as("SELECT email FROM accounts WHERE id = $1").bind(account).fetch_one(&app.db).await?;
    app.post(&email, crate::mail::reset_started_letter());
    Ok(Json(json!({ "next": format!("/reset-password?token={token}") })))
}

const SCRIPT: &str = include_str!("../static/account.js");

pub async fn script() -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "text/javascript; charset=utf-8"), (header::CACHE_CONTROL, "public, max-age=3600")], SCRIPT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_stays_on_the_site() {
        assert!(next_ok("/account/security"));
        assert!(!next_ok("//evil.example/account"));
        assert!(!next_ok("https://evil.example"));
        assert!(!next_ok("/account?x=1"));
        assert!(!next_ok("/accountx/../../evil"));
    }

    #[test]
    fn initials_of_a_name() {
        assert_eq!(initials("Ana Tremblay"), "AT");
        assert_eq!(initials("ana"), "A");
        assert_eq!(initials("élise de la tour"), "ÉT");
    }
}
