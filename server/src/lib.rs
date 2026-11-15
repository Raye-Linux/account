pub mod config;
mod devices;
mod email;
mod emailcode;
mod error;
pub mod mail;
mod me;
mod oauth;
pub mod otp;
mod pages;
mod ratelimit;
mod settings;
mod store;
mod time_fmt;
mod tokens;
mod twofactor;
mod web;

use std::sync::Arc;

use axum::extract::DefaultBodyLimit;
use axum::http::{header, HeaderValue};
use axum::routing::{delete, get, post, put};
use axum::Router;
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tower_http::set_header::SetResponseHeaderLayer;

pub use config::Config;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("./migrations");

/// Requests are small JSON documents; only the picture upload is bigger.
const BODY_LIMIT: usize = 64 * 1024;
pub const AVATAR_UPLOAD_LIMIT: usize = 2 * 1024 * 1024;

pub struct AppState {
    pub db: PgPool,
    pub config: Config,
    /// Argon2id needs 19 MiB per hash and image decoding can need more: this
    /// caps how many run at once so a burst of sign-ins cannot eat the RAM.
    pub heavy: Semaphore,
    pub limits: ratelimit::Limits,
    /// Letters that were not sent, because no submission binary is
    /// configured. Development and the tests read their links from here.
    pub outbox: mail::Outbox,
    /// Passkeys. None when the public address is not one a browser accepts
    /// as a relying party (a bare IP in tests).
    pub webauthn: Option<webauthn_rs::Webauthn>,
    form_key: [u8; 32],
    dummy_hash: String,
}

impl AppState {
    pub fn new(db: PgPool, config: Config) -> Arc<Self> {
        use rand::RngCore;
        let mut form_key = [0u8; 32];
        rand::rngs::OsRng.fill_bytes(&mut form_key);
        let webauthn = webauthn_for(&config.base_url);
        Arc::new(AppState {
            webauthn,
            db,
            heavy: Semaphore::new(config.heavy_jobs),
            config,
            limits: ratelimit::Limits::default(),
            outbox: mail::Outbox::default(),
            form_key,
            dummy_hash: oauth::hash_password("not a real password, used for timing")
                .expect("argon2 parameters are valid"),
        })
    }

    /// A link for a letter: the public address of this server, the path, and
    /// the token as the only query.
    pub fn link(&self, path: &str, token: &str) -> String {
        format!("{}{}?token={}", self.config.base_url, path, token)
    }

    /// Hands a letter to the mailer. Errors are logged and swallowed on
    /// purpose: the caller must answer the same way whether or not the
    /// address exists, and a failure to send is exactly the kind of
    /// difference that would give it away.
    pub fn post(&self, to: &str, mut letter: mail::Mail) {
        letter.to = to.to_owned();
        if let Err(e) = self.config.mailer.send(&self.config.mail_from, &letter, &self.outbox) {
            tracing::error!(error = %e, "a letter could not be sent");
        }
    }
}

fn webauthn_for(base_url: &str) -> Option<webauthn_rs::Webauthn> {
    let url = webauthn_rs::prelude::Url::parse(base_url).ok()?;
    let host = url.host_str()?.to_owned();
    if host.parse::<std::net::IpAddr>().is_ok() {
        return None;
    }
    webauthn_rs::WebauthnBuilder::new(&host, &url).ok()?.rp_name("Raye").build().ok()
}

pub type Shared = Arc<AppState>;

/// A request that takes longer than this is cut off (slow clients, stuck
/// database): the worker goes back to serving others.
const REQUEST_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(30);

pub fn router(state: Shared) -> Router {
    let https = state.config.https;
    let api = Router::new()
        .route("/v1/oauth/token", post(oauth::token))
        .route("/v1/oauth/revoke", post(oauth::revoke))
        .route("/v1/me", get(me::get_me).patch(me::patch_me))
        .route(
            "/v1/me/avatar",
            get(me::get_avatar)
                .put(me::put_avatar)
                .delete(me::delete_avatar)
                .layer(DefaultBodyLimit::max(AVATAR_UPLOAD_LIMIT)),
        )
        .route("/v1/me/export", get(me::export))
        .route("/v1/me/delete", post(me::delete_account))
        .route("/v1/me/email/verify/send", post(email::send_verification))
        .route("/v1/me/email/verify", post(email::verify_from_api))
        .route("/v1/me/email-code", post(emailcode::switch))
        .route("/v1/me/totp/start", post(twofactor::start))
        .route("/v1/me/totp/confirm", post(twofactor::confirm))
        .route("/v1/me/totp/disable", post(twofactor::disable))
        .route("/v1/devices", get(devices::list))
        .route("/v1/devices/current", axum::routing::patch(devices::patch_current))
        .route("/v1/devices/current/installs", put(store::put_installs))
        .route("/v1/devices/{id}", delete(devices::remove))
        .route("/v1/devices/{id}/installs", get(store::device_installs))
        .route("/v1/settings", get(settings::pull).put(settings::push))
        .route("/v1/store/library", get(store::library))
        .route(
            "/v1/store/library/{app_id}",
            put(store::add_to_library).delete(store::remove_from_library),
        )
        .layer(SetResponseHeaderLayer::overriding(
            header::CACHE_CONTROL,
            HeaderValue::from_static("no-store"),
        ));

    let web = Router::new()
        .route("/oauth/authorize", get(oauth::authorize_page).post(oauth::authorize_submit))
        // GET shows a button and changes nothing: a mail scanner that fetches
        // every link in a message would otherwise spend the token before the
        // person who was written to ever sees it.
        .route("/verify-email", get(email::verify_page).post(email::verify_submit))
        .route("/reset-password", get(email::reset_page).post(email::reset_submit))
        .route("/", get(web::home))
        .route("/lang/{code}", get(web::set_lang))
        .route("/signin", get(web::signin_page).post(web::signin_submit))
        .route("/signin/passkey/{kind}", post(web::passkey_auth_start))
        .route("/signin/passkey/finish", post(web::passkey_signin_finish))
        .route("/reset-password/passkey", post(web::passkey_reset_finish))
        .route("/signout", post(web::signout))
        .route("/account", get(web::overview))
        .route("/account/info", get(web::info))
        .route("/account/info/name", post(web::set_name))
        .route(
            "/account/info/photo",
            post(web::set_photo).layer(DefaultBodyLimit::max(AVATAR_UPLOAD_LIMIT + 16 * 1024)),
        )
        .route("/account/info/photo/remove", post(web::remove_photo))
        .route("/account/photo", get(web::photo))
        .route("/account/security", get(web::security))
        .route("/account/security/password", post(web::change_password))
        .route("/account/security/email-code", post(web::email_code_switch))
        .route("/account/security/totp/start", post(web::totp_start))
        .route("/account/security/totp/confirm", post(web::totp_confirm))
        .route("/account/security/totp/off", post(web::totp_off))
        .route("/account/security/recovery", post(web::new_recovery))
        .route("/account/security/passkeys/start", post(web::passkey_register_start))
        .route("/account/security/passkeys/finish", post(web::passkey_register_finish))
        .route("/account/security/passkeys/{id}/remove", post(web::passkey_remove))
        .route("/account/devices", get(web::devices))
        .route("/account/devices/{id}/remove", post(web::remove_device))
        .route("/account/privacy", get(web::privacy))
        .route("/account/privacy/export", get(web::export))
        .route("/account/privacy/delete", post(web::delete))
        .route("/static/account.js", get(web::script))
        .route("/static/account.css", get(pages::css))
        .route("/static/raye-eye.png", get(pages::logo))
        .route("/healthz", get(|| async { "ok" }));

    let router = Router::new()
        .merge(api)
        .merge(web.layer(axum::middleware::from_fn_with_state(state.clone(), web::same_origin)))
        .layer(DefaultBodyLimit::max(BODY_LIMIT))
        .layer(tower_http::timeout::TimeoutLayer::with_status_code(
            axum::http::StatusCode::SERVICE_UNAVAILABLE,
            REQUEST_TIMEOUT,
        ))
        .layer(SetResponseHeaderLayer::overriding(
            header::X_CONTENT_TYPE_OPTIONS,
            HeaderValue::from_static("nosniff"),
        ))
        // same-origin, not no-referrer: with no-referrer browsers post this
        // site's own forms with "Origin: null", which same_origin refuses.
        .layer(SetResponseHeaderLayer::overriding(
            header::REFERRER_POLICY,
            HeaderValue::from_static("same-origin"),
        ));
    let router = if https {
        router.layer(SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ))
    } else {
        router
    };
    router.with_state(state)
}
