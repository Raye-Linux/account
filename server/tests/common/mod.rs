//! The harness the end-to-end tests share: a throwaway database per test, the
//! router in front of it, and the browser half of a sign-in.
//!
//! Set RAYE_ACCOUNT_TEST_DB to an admin URL of a throwaway server
//! (tools/dev-db.sh start prints one); without it `app()` returns None and
//! the caller returns, saying so on stderr.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::body::Body;
use axum::extract::connect_info::MockConnectInfo;
use axum::http::{header, HeaderMap, Method, Request, StatusCode};
use axum::Router;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use ed25519_dalek::{Signer, SigningKey};
use http_body_util::BodyExt;
use raye_account_common::api::TokenResponse;
use raye_account_common::{pkce, refresh_proof_message};
use raye_account_server::{router, AppState, Config, MIGRATOR};
use serde_json::Value;
use sqlx::postgres::PgPoolOptions;
use sqlx::{Connection, PgConnection, PgPool};
use tower::ServiceExt;
use uuid::Uuid;

pub const REDIRECT: &str = "http://127.0.0.1:50123/callback";
/// Long enough for `password_ok`, used by every account the tests make.
pub const PASSWORD: &str = "a long enough password";

pub struct TestDb {
    admin_url: String,
    name: String,
    pub pool: PgPool,
}

impl TestDb {
    async fn new() -> Option<TestDb> {
        let admin_url = std::env::var("RAYE_ACCOUNT_TEST_DB").ok()?;
        let name = format!("t_{}", Uuid::new_v4().simple());
        let mut admin = PgConnection::connect(&admin_url).await.expect("admin connection");
        sqlx::query(&format!("CREATE DATABASE {name}")).execute(&mut admin).await.unwrap();
        let url = with_db(&admin_url, &name);
        let pool = PgPoolOptions::new().max_connections(4).connect(&url).await.unwrap();
        MIGRATOR.run(&pool).await.unwrap();
        Some(TestDb { admin_url, name, pool })
    }

    pub async fn drop_db(self) {
        self.pool.close().await;
        let mut admin = PgConnection::connect(&self.admin_url).await.unwrap();
        sqlx::query(&format!("DROP DATABASE {} WITH (FORCE)", self.name))
            .execute(&mut admin)
            .await
            .unwrap();
    }
}

/// postgres://user@/account?host=... -> postgres://user@/<name>?host=...
fn with_db(url: &str, name: &str) -> String {
    let (base, query) = url.split_once('?').unwrap_or((url, ""));
    let base = base.rsplit_once('/').map(|(b, _)| b).unwrap_or(base);
    format!("{base}/{name}?{query}")
}

pub struct App {
    pub router: Router,
    pub state: Arc<AppState>,
    pub db: TestDb,
}

/// The app for one test, or None when there is no database to talk to.
pub async fn app() -> Option<App> {
    let Some(db) = TestDb::new().await else {
        eprintln!("RAYE_ACCOUNT_TEST_DB is not set, skipping");
        return None;
    };
    let mut config = Config::defaults(String::new());
    config.heavy_jobs = 4;
    let state: Arc<AppState> = AppState::new(db.pool.clone(), config);
    let router = router(state.clone()).layer(MockConnectInfo(SocketAddr::from(([192, 0, 2, 10], 40000))));
    Some(App { router, state, db })
}

impl App {
    pub async fn call(&self, req: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let res = self.router.clone().oneshot(req).await.unwrap();
        let status = res.status();
        let headers = res.headers().clone();
        let body = res.into_body().collect().await.unwrap().to_bytes().to_vec();
        (status, headers, body)
    }

    pub async fn json(&self, method: Method, uri: &str, token: &str, body: Option<Value>) -> (StatusCode, Value) {
        let mut b = Request::builder().method(method).uri(uri).header(header::AUTHORIZATION, format!("Bearer {token}"));
        let body = match body {
            Some(v) => {
                b = b.header(header::CONTENT_TYPE, "application/json");
                Body::from(v.to_string())
            }
            None => Body::empty(),
        };
        let (s, _, bytes) = self.call(b.body(body).unwrap()).await;
        (s, serde_json::from_slice(&bytes).unwrap_or(Value::Null))
    }

    pub async fn form(&self, uri: &str, fields: &[(&str, &str)]) -> (StatusCode, HeaderMap, String) {
        let body = fields
            .iter()
            .map(|(k, v)| format!("{}={}", enc(k), enc(v)))
            .collect::<Vec<_>>()
            .join("&");
        let req = Request::post(uri)
            .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
            .body(Body::from(body))
            .unwrap();
        let (s, h, b) = self.call(req).await;
        (s, h, String::from_utf8_lossy(&b).into_owned())
    }

    /// A GET of a website page, as HTML.
    pub async fn page(&self, uri: &str) -> (StatusCode, String) {
        let (s, _, b) = self.call(Request::get(uri).body(Body::empty()).unwrap()).await;
        (s, String::from_utf8_lossy(&b).into_owned())
    }
}

pub fn enc(s: &str) -> String {
    s.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || b"-._~".contains(&b) {
                (b as char).to_string()
            } else {
                format!("%{b:02X}")
            }
        })
        .collect()
}

pub fn hidden(html: &str, name: &str) -> String {
    let marker = format!("name=\"{name}\" value=\"");
    let start = html.find(&marker).unwrap_or_else(|| panic!("no {name} in page")) + marker.len();
    html[start..].split('"').next().unwrap().replace("&amp;", "&")
}

pub struct Device {
    pub key: SigningKey,
    pub tokens: TokenResponse,
}

/// The password screen alone: what the server answers to it.
pub async fn password_step(
    app: &App,
    action: &str,
    email: &str,
    password: &str,
    challenge: &str,
) -> (StatusCode, HeaderMap, String) {
    let state = "state-0123456789abcdef";
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id=raye-desktop&redirect_uri={}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        enc(REDIRECT)
    );
    let (s, page) = app.page(&uri).await;
    assert_eq!(s, StatusCode::OK);
    app.form(
        "/oauth/authorize",
        &[
            ("action", action),
            ("email", email),
            ("password", password),
            ("display_name", "Ana Tremblay"),
            ("redirect_uri", &hidden(&page, "redirect_uri")),
            ("state", &hidden(&page, "state")),
            ("code_challenge", &hidden(&page, "code_challenge")),
            ("ts", &hidden(&page, "ts")),
            ("csrf", &hidden(&page, "csrf")),
        ],
    )
    .await
}

/// The 6-digit code out of the last letter to `address`.
pub fn email_code_in_last_letter(app: &App, address: &str) -> String {
    let mail = app.state.outbox.last_to(address).expect("a sign-in code letter");
    let code = mail
        .body
        .lines()
        .map(str::trim)
        .find(|l| l.len() == 6 && l.bytes().all(|b| b.is_ascii_digit()))
        .expect("a 6-digit code in the letter");
    assert!(!mail.subject.contains(code), "the code stays out of the subject");
    code.to_owned()
}

/// Posts a second-step screen with `action` and `code`, keeping its proof.
pub async fn second_step(app: &App, page: &str, action: &str, code: &str) -> (StatusCode, HeaderMap, String) {
    app.form(
        "/oauth/authorize",
        &[
            ("action", action),
            ("code", code),
            ("account", &hidden(page, "account")),
            ("redirect_uri", &hidden(page, "redirect_uri")),
            ("state", &hidden(page, "state")),
            ("code_challenge", &hidden(page, "code_challenge")),
            ("ts", &hidden(page, "ts")),
            ("csrf", &hidden(page, "csrf")),
        ],
    )
    .await
}

pub fn is_email_code_page(page: &str) -> bool {
    page.contains("name=\"action\" value=\"emailcode\"")
}

/// The browser half: open the authorize page, submit the form, and the code
/// sent by email when it is asked for; return the code. An answer that is
/// not the redirect comes back as the error, so a test can assert on the
/// status and the page's words.
pub async fn browser_code(
    app: &App,
    action: &str,
    email: &str,
    password: &str,
    challenge: &str,
) -> Result<String, (StatusCode, String)> {
    let state = "state-0123456789abcdef";
    let (mut s, mut h, mut body) = password_step(app, action, email, password, challenge).await;
    if s == StatusCode::OK && is_email_code_page(&body) {
        let code = email_code_in_last_letter(app, &email.trim().to_lowercase());
        (s, h, body) = second_step(app, &body, "emailcode", &code).await;
    }
    if s != StatusCode::SEE_OTHER {
        return Err((s, body));
    }
    Ok(code_from(&h, state))
}

/// The code out of a redirect to the loopback callback.
pub fn code_from(h: &HeaderMap, state: &str) -> String {
    let loc = h.get(header::LOCATION).unwrap().to_str().unwrap().to_owned();
    assert!(loc.starts_with(&format!("{REDIRECT}?code=")), "{loc}");
    assert!(loc.ends_with(&format!("&state={state}")), "{loc}");
    loc.split("code=").nth(1).unwrap().split('&').next().unwrap().to_owned()
}

pub async fn exchange(app: &App, code: &str, verifier: &str, name: &str) -> (StatusCode, Option<Device>) {
    let key = SigningKey::generate(&mut rand::rngs::OsRng);
    let pk = URL_SAFE_NO_PAD.encode(key.verifying_key().to_bytes());
    let (s, _, body) = app
        .form(
            "/v1/oauth/token",
            &[
                ("grant_type", "authorization_code"),
                ("client_id", "raye-desktop"),
                ("code", code),
                ("redirect_uri", REDIRECT),
                ("code_verifier", verifier),
                ("device_name", name),
                ("device_model", "Dell Latitude 5420"),
                ("raye_version", "0.1"),
                ("device_key", &pk),
            ],
        )
        .await;
    if s != StatusCode::OK {
        return (s, None);
    }
    (s, Some(Device { key, tokens: serde_json::from_str(&body).unwrap() }))
}

/// The sign-up form, as far as the page that says "check your email".
pub async fn sign_up_form(app: &App, email: &str, password: &str) -> (StatusCode, String) {
    match browser_code(app, "signup", email, password, &pkce::challenge(&pkce::new_verifier())).await {
        Ok(code) => panic!("a sign-up must not hand out a code before the address is confirmed: {code}"),
        Err(e) => e,
    }
}

/// The link out of the last letter to `address`.
pub fn link_in_last_letter(app: &App, address: &str) -> String {
    let mail = app
        .state
        .outbox
        .last_to(address)
        .unwrap_or_else(|| panic!("no letter for {address}; outbox holds {:?}", app.state.outbox.all().len()));
    let at = mail.body.find("http").expect("a link in the letter");
    mail.body[at..].split_whitespace().next().unwrap().to_owned()
}

pub fn token_of(link: &str) -> String {
    link.split("token=").nth(1).expect("a token in the link").to_owned()
}

/// Sign-up, confirmation link, then the first sign-in on this PC.
pub async fn sign_up(app: &App, email: &str, device: &str) -> Device {
    let (s, page) = sign_up_form(app, email, PASSWORD).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let address = email.trim().to_lowercase();
    let token = token_of(&link_in_last_letter(app, &address));
    let (s, _, page) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    sign_in(app, &address, device).await
}

pub async fn sign_in(app: &App, email: &str, device: &str) -> Device {
    let v = pkce::new_verifier();
    let code = browser_code(app, "signin", email, PASSWORD, &pkce::challenge(&v)).await.unwrap();
    exchange(app, &code, &v, device).await.1.unwrap()
}

pub async fn refresh(app: &App, d: &Device, token: &str, ts_offset: i64) -> (StatusCode, String) {
    let id = d.tokens.device_id;
    let ts = time::OffsetDateTime::now_utc().unix_timestamp() + ts_offset;
    let sig = d.key.sign(&refresh_proof_message(&id, ts, token));
    let (s, _, body) = app
        .form(
            "/v1/oauth/token",
            &[
                ("grant_type", "refresh_token"),
                ("client_id", "raye-desktop"),
                ("refresh_token", token),
                ("device_id", &id.to_string()),
                ("proof_ts", &ts.to_string()),
                ("proof", &URL_SAFE_NO_PAD.encode(sig.to_bytes())),
            ],
        )
        .await;
    (s, body)
}
