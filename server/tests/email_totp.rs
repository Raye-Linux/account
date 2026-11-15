//! Confirming an address, resetting a password, and two-step verification,
//! end to end against a real PostgreSQL.
//!
//! These three are the shortest roads into an account that exists, so what is
//! asserted here is mostly what is REFUSED: a link that expired, a link
//! already spent, a link belonging to someone else, a code replayed, a code
//! from outside the drift window, and the code screen reached without the
//! password. A test that only proves the happy path proves nothing about a
//! reset link.

mod common;

use axum::http::{header, Method, StatusCode};
use common::*;
use raye_account_common::pkce;
use serde_json::json;
use uuid::Uuid;

// ------------------------------------------------- address confirmation tokens
//
// Every account is confirmed when it is made, so these links only matter for
// a row that lost its confirmation (none today). They still have to hold.

async fn unconfirm(app: &App, email: &str) -> Uuid {
    let (id,): (Uuid,) = sqlx::query_as("UPDATE accounts SET email_verified = false WHERE email = $1 RETURNING id")
        .bind(email)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    id
}

async fn email_token(app: &App, id: Uuid, email: &str) -> String {
    let token = raye_account_common::random_token();
    sqlx::query("INSERT INTO email_tokens (token_hash, account_id, email, expires_at) VALUES ($1, $2, $3, now() + interval '1 hour')")
        .bind(sha(&token))
        .bind(id)
        .bind(email)
        .execute(&app.db.pool)
        .await
        .unwrap();
    token
}

fn sha(t: &str) -> Vec<u8> {
    use sha2::Digest;
    sha2::Sha256::digest(t.as_bytes()).to_vec()
}

async fn verified(app: &App, email: &str) -> bool {
    let (v,): (bool,) = sqlx::query_as("SELECT email_verified FROM accounts WHERE email = $1")
        .bind(email)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    v
}

#[tokio::test]
async fn an_unconfirmed_account_cannot_use_the_api_or_sign_in() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "ana@example.com", "Bureau").await;
    let id = unconfirm(&app, "ana@example.com").await;
    let (s, _) = app.json(Method::GET, "/v1/me", &d.tokens.access_token, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let v = pkce::new_verifier();
    let r = browser_code(&app, "signin", "ana@example.com", PASSWORD, &pkce::challenge(&v)).await;
    assert_eq!(r.unwrap_err().0, StatusCode::UNAUTHORIZED);

    let token = email_token(&app, id, "ana@example.com").await;
    let (s, page) = app.page(&format!("/verify-email?token={token}")).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Confirm this address"), "a button, not a confirmation");
    assert!(!verified(&app, "ana@example.com").await, "the GET changes nothing");
    let (s, _, page) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert!(verified(&app, "ana@example.com").await);
    let (s, _, _) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "spent");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_link_mailed_to_the_old_address_cannot_confirm_a_new_one() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "before@example.com", "A").await;
    let id = unconfirm(&app, "before@example.com").await;
    let token = email_token(&app, id, "before@example.com").await;
    sqlx::query("UPDATE accounts SET email = 'after@example.com' WHERE email = 'before@example.com'")
        .execute(&app.db.pool)
        .await
        .unwrap();
    let (s, _, _) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(!verified(&app, "after@example.com").await);
    app.db.drop_db().await;
}

#[tokio::test]
async fn junk_is_refused_without_a_database_lookup() {
    let Some(app) = app().await else { return };
    for bad in ["", "short", &"A".repeat(200)] {
        let (s, _) = app.page(&format!("/verify-email?token={}", enc(bad))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
        let (s, _, _) = app.form("/verify-email", &[("token", bad)]).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{bad:?}");
    }
    let (s, _) = app.page("/verify-email").await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "no token at all");
    app.db.drop_db().await;
}

// ----------------------------------------------------------- password resets

/// Asks for a reset link and returns its token.
async fn reset_token(app: &App, email: &str, _access: &str) -> String {
    let (s, _, page) = app.form("/reset-password", &[("action", "request"), ("email", email)]).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    token_of(&link_in_last_letter(app, email))
}

#[tokio::test]
async fn a_reset_link_changes_the_password_once_and_signs_every_pc_out() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "reset@example.com", "Bureau").await;
    let b = sign_in(&app, "reset@example.com", "Portable").await;
    let token = reset_token(&app, "reset@example.com", &a.tokens.access_token).await;

    let (s, _, page) = app
        .form("/reset-password", &[("action", "set"), ("token", &token), ("password", "a brand new password"), ("password2", "a brand new password")])
        .await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert!(page.contains("password is changed"), "{page}");

    // Every device is out: access tokens gone, refresh tokens gone.
    for (who, d) in [("Bureau", &a), ("Portable", &b)] {
        assert_eq!(
            app.json(Method::GET, "/v1/me", &d.tokens.access_token, None).await.0,
            StatusCode::UNAUTHORIZED,
            "{who} still had a working access token"
        );
        assert_eq!(
            refresh(&app, d, &d.tokens.refresh_token, 0).await.0,
            StatusCode::BAD_REQUEST,
            "{who} could still refresh"
        );
    }
    // But they are still listed, so the owner can see and remove them.
    let (count,): (i64,) = sqlx::query_as("SELECT count(*) FROM devices").fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(count, 2, "the devices stay in the account");

    // The old password is dead and the new one works.
    let ch = pkce::challenge(&pkce::new_verifier());
    let e = browser_code(&app, "signin", "reset@example.com", PASSWORD, &ch).await.unwrap_err();
    assert_eq!(e.0, StatusCode::UNAUTHORIZED, "the old password still worked");
    let v = pkce::new_verifier();
    let code = browser_code(&app, "signin", "reset@example.com", "a brand new password", &pkce::challenge(&v))
        .await
        .expect("the new password signs in");
    assert_eq!(exchange(&app, &code, &v, "Bureau").await.0, StatusCode::OK);

    // The link is spent.
    let (s, _, page) = app
        .form("/reset-password", &[("action", "set"), ("token", &token), ("password", "yet another password"), ("password2", "yet another password")])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{page}");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_made_up_reset_token_is_refused_before_any_hashing() {
    let Some(app) = app().await else { return };
    // Every hashing slot is taken: a refusal that still waited for one would
    // hang here, which is how a stream of fake tokens starves real sign-ins.
    let _held = app.state.heavy.acquire_many(4).await.unwrap();
    let fake = raye_account_common::random_token();
    let r = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        app.form(
            "/reset-password",
            &[("action", "set"), ("token", &fake), ("password", "a replacement password"), ("password2", "a replacement password")],
        ),
    )
    .await
    .expect("refused without waiting for a hashing slot");
    assert_eq!(r.0, StatusCode::BAD_REQUEST);
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_reset_link_expires_and_a_stranger_token_is_refused() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "old@example.com", "A").await;
    let token = reset_token(&app, "old@example.com", &a.tokens.access_token).await;

    sqlx::query("UPDATE password_resets SET expires_at = now() - interval '1 second'")
        .execute(&app.db.pool)
        .await
        .unwrap();
    async fn set(app: &App, token: &str) -> StatusCode {
        app.form(
            "/reset-password",
            &[
                ("action", "set"),
                ("token", token),
                ("password", "a replacement password"),
                ("password2", "a replacement password"),
            ],
        )
        .await
        .0
    }
    assert_eq!(set(&app, &token).await, StatusCode::BAD_REQUEST, "an expired link");
    let never_issued = raye_account_common::random_token();
    assert_eq!(set(&app, &never_issued).await, StatusCode::BAD_REQUEST, "a token nobody issued");

    // The password did not move: the old one still signs in.
    let ch = pkce::challenge(&pkce::new_verifier());
    assert!(browser_code(&app, "signin", "old@example.com", PASSWORD, &ch).await.is_ok());
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_answer_says_nothing_about_who_has_an_account() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "known@example.com", "A").await;
    // A sign-up that was never confirmed has no account to reset.
    let _ = sign_up_form(&app, "unconfirmed@example.com", PASSWORD).await;

    let mut pages = Vec::new();
    for address in ["known@example.com", "unconfirmed@example.com", "nobody@example.com", "not an address"] {
        let (s, _, page) = app.form("/reset-password", &[("action", "request"), ("email", address)]).await;
        assert_eq!(s, StatusCode::OK, "{address}");
        pages.push(page);
    }
    assert_eq!(pages.iter().collect::<std::collections::HashSet<_>>().len(), 1, "four addresses, one answer");

    // And only the confirmed one actually got a letter. An address nobody
    // confirmed is not a reset target (design section 6).
    assert!(app.state.outbox.last_to("known@example.com").is_some());
    assert!(app.state.outbox.last_to("nobody@example.com").is_none());
    let to_unconfirmed = app.state.outbox.all().iter().filter(|m| m.to == "unconfirmed@example.com" && m.subject.contains("Reset")).count();
    assert_eq!(to_unconfirmed, 0, "no reset letter before the address is confirmed");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_reset_form_refuses_a_weak_or_mistyped_password() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "weak@example.com", "A").await;
    let token = reset_token(&app, "weak@example.com", &a.tokens.access_token).await;

    let (s, _, page) = app
        .form("/reset-password", &[("action", "set"), ("token", &token), ("password", "one thing"), ("password2", "another thing")])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(page.contains("not the same"), "{page}");

    let (s, _, page) = app
        .form("/reset-password", &[("action", "set"), ("token", &token), ("password", "short"), ("password2", "short")])
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(page.contains("at least 10"), "{page}");

    // Neither mistake spent the link: it still works.
    let (s, _, page) = app
        .form("/reset-password", &[("action", "set"), ("token", &token), ("password", "a good long password"), ("password2", "a good long password")])
        .await;
    assert_eq!(s, StatusCode::OK, "{page}");
    app.db.drop_db().await;
}

// ------------------------------------------------------ two-step verification

/// Turns two-step verification on. Gives back the secret, the ten recovery
/// codes, and **the step the confirmation spent** -- confirming uses a real
/// code, and a real code is single use, so every later assertion has to work
/// from a step after this one.
async fn enrol(app: &App, access: &str) -> (Vec<u8>, Vec<String>, i64) {
    let (s, start) = app.json(Method::POST, "/v1/me/totp/start", access, None).await;
    assert_eq!(s, StatusCode::OK, "{start}");
    let b32 = start["secret"].as_str().expect("a secret").to_owned();
    assert!(start["otpauth_uri"].as_str().unwrap().starts_with("otpauth://totp/Raye:"));
    let secret = unbase32(&b32);
    let code = raye_account_server::otp::code_at(&secret, now());
    let (s, out) = app.json(Method::POST, "/v1/me/totp/confirm", access, Some(json!({"code": code}))).await;
    assert_eq!(s, StatusCode::OK, "{out}");
    let codes: Vec<String> =
        out["recovery_codes"].as_array().unwrap().iter().map(|c| c.as_str().unwrap().to_owned()).collect();
    assert_eq!(codes.len(), 10);
    let (_, me) = app.json(Method::GET, "/v1/me", access, None).await;
    assert_eq!(me["totp_enabled"], true);
    (secret, codes, raye_account_server::otp::step_at(now()))
}

fn now() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn unbase32(s: &str) -> Vec<u8> {
    const A: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let (mut acc, mut bits, mut out) = (0u32, 0u32, Vec::new());
    for c in s.bytes() {
        let v = A.iter().position(|&a| a == c).expect("base32") as u32;
        acc = (acc << 5) | v;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
        }
    }
    out
}

/// Signs in with the password and stops at the code screen.
async fn password_stage(app: &App, email: &str) -> (String, String) {
    let v = pkce::new_verifier();
    let challenge = pkce::challenge(&v);
    let state = "state-0123456789abcdef";
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id=raye-desktop&redirect_uri={}&state={state}&code_challenge={challenge}&code_challenge_method=S256",
        enc(REDIRECT)
    );
    let (_, page) = app.page(&uri).await;
    let (s, _, page) = app
        .form(
            "/oauth/authorize",
            &[
                ("action", "signin"),
                ("email", email),
                ("password", PASSWORD),
                ("redirect_uri", &hidden(&page, "redirect_uri")),
                ("state", &hidden(&page, "state")),
                ("code_challenge", &hidden(&page, "code_challenge")),
                ("ts", &hidden(&page, "ts")),
                ("csrf", &hidden(&page, "csrf")),
            ],
        )
        .await;
    assert_eq!(s, StatusCode::OK, "the code screen, not a redirect: {page}");
    assert!(page.contains("Two-step verification"), "{page}");
    (v, page)
}

/// Posts a code to the code screen, carrying that page's hidden fields.
async fn try_code(app: &App, page: &str, code: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    app.form(
        "/oauth/authorize",
        &[
            ("action", "totp"),
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

#[tokio::test]
async fn a_code_is_asked_after_the_password_and_works_once() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "totp@example.com", "Bureau").await;
    let (secret, _, spent) = enrol(&app, &d.tokens.access_token).await;

    let (verifier, page) = password_stage(&app, "totp@example.com").await;
    // The next code, not the one enrolment used: that one is spent.
    let code = raye_account_server::otp::code_for(&secret, spent + 1);
    let (s, h, body) = try_code(&app, &page, &code).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{body}");
    let auth_code = code_from(&h, "state-0123456789abcdef");
    assert_eq!(exchange(&app, &auth_code, &verifier, "Portable").await.0, StatusCode::OK);

    // The same code again, on a fresh sign-in: refused. This is the
    // anti-replay rule -- without it the code lives for the drift window,
    // which is all a phishing page needs.
    let (_, page2) = password_stage(&app, "totp@example.com").await;
    let (s, _, body) = try_code(&app, &page2, &code).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a replayed code was accepted: {body}");
    assert!(body.contains("isn't right"), "{body}");
    app.db.drop_db().await;
}

/// Split from the replay test on purpose: `TOTP_ACCOUNT` allows five tries
/// per account and the enrolment already spent one, so a single test cannot
/// afford every assertion. Weakening the limit to fit a test would be
/// weakening the only defence six digits has.
#[tokio::test]
async fn the_drift_window_is_bounded() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "drift@example.com", "A").await;
    let (secret, _, spent) = enrol(&app, &d.tokens.access_token).await;
    let code = |step: i64| raye_account_server::otp::code_for(&secret, step);

    let (_, page) = password_stage(&app, "drift@example.com").await;
    // Far outside either way. +3 and -2, not +2/-2, so the clock ticking into
    // the next step mid-test cannot quietly move one of them inside.
    assert_eq!(try_code(&app, &page, &code(spent + 3)).await.0, StatusCode::UNAUTHORIZED, "three steps ahead");
    assert_eq!(try_code(&app, &page, &code(spent - 2)).await.0, StatusCode::UNAUTHORIZED, "two steps behind");
    // One step ahead is inside the window and not yet spent: the code a
    // person actually reads off their phone.
    assert_eq!(try_code(&app, &page, &code(spent + 1)).await.0, StatusCode::SEE_OTHER, "the next code");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_spent_step_stays_spent_even_inside_the_window() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "spent@example.com", "A").await;
    let (secret, _, spent) = enrol(&app, &d.tokens.access_token).await;
    let code = |step: i64| raye_account_server::otp::code_for(&secret, step);

    let (_, page) = password_stage(&app, "spent@example.com").await;
    // Confirming two-step verification used the code for `spent`. It is
    // inside the drift window and it is refused anyway -- and so is the one
    // before it, because the rule is "a later step", not "a different step".
    assert_eq!(try_code(&app, &page, &code(spent)).await.0, StatusCode::UNAUTHORIZED, "the step enrolment used");
    assert_eq!(try_code(&app, &page, &code(spent - 1)).await.0, StatusCode::UNAUTHORIZED, "and the one before it");
    assert_eq!(try_code(&app, &page, &code(spent + 1)).await.0, StatusCode::SEE_OTHER, "a later step is fine");
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_code_screen_cannot_be_reached_without_the_password() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "forge@example.com", "A").await;
    let (secret, _, spent) = enrol(&app, &d.tokens.access_token).await;
    let (account,): (Uuid,) =
        sqlx::query_as("SELECT id FROM accounts WHERE email = 'forge@example.com'").fetch_one(&app.db.pool).await.unwrap();
    let good = raye_account_server::otp::code_for(&secret, spent + 1);

    // A form built from scratch: the right account, the right code, no proof
    // that any password was ever checked.
    let forged = format!(
        "<input name=\"account\" value=\"{account}\"><input name=\"redirect_uri\" value=\"{REDIRECT}\">\
         <input name=\"state\" value=\"state-0123456789abcdef\">\
         <input name=\"code_challenge\" value=\"{}\"><input name=\"ts\" value=\"{}\">\
         <input name=\"csrf\" value=\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\">",
        pkce::challenge(&pkce::new_verifier()),
        now()
    );
    let (s, h, body) = try_code(&app, &forged, &good).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "a forged stage was accepted: {body}");
    assert!(h.get(header::LOCATION).is_none(), "and it must not redirect");

    // A real code screen, but its proof reused for a different account.
    let other = sign_up(&app, "victim@example.com", "B").await;
    let (sec2, _, spent2) = enrol(&app, &other.tokens.access_token).await;
    let (_, page) = password_stage(&app, "forge@example.com").await;
    let (victim,): (Uuid,) =
        sqlx::query_as("SELECT id FROM accounts WHERE email = 'victim@example.com'").fetch_one(&app.db.pool).await.unwrap();
    let swapped = page.replace(&account.to_string(), &victim.to_string());
    let victim_code = raye_account_server::otp::code_for(&sec2, spent2 + 1);
    let (s, _, body) = try_code(&app, &swapped, &victim_code).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the account in the form was swapped: {body}");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_recovery_code_works_once() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "lost@example.com", "A").await;
    let (_, codes, _) = enrol(&app, &d.tokens.access_token).await;

    // Typed the way a person would: lower case, spaces for dashes.
    let typed = codes[0].to_lowercase().replace('-', " ");
    let (_, page) = password_stage(&app, "lost@example.com").await;
    assert_eq!(try_code(&app, &page, &typed).await.0, StatusCode::SEE_OTHER, "forgiving about case and dashes");

    let (_, page) = password_stage(&app, "lost@example.com").await;
    assert_eq!(try_code(&app, &page, &codes[0]).await.0, StatusCode::UNAUTHORIZED, "the same code twice");
    assert_eq!(try_code(&app, &page, &codes[1]).await.0, StatusCode::SEE_OTHER, "a different one still works");
    app.db.drop_db().await;
}

#[tokio::test]
async fn turning_two_step_off_needs_the_password() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "off@example.com", "A").await;
    let (_, codes, _) = enrol(&app, &d.tokens.access_token).await;
    let t = &d.tokens.access_token;

    let (s, _) = app.json(Method::POST, "/v1/me/totp/disable", t, Some(json!({"password": "not it at all"}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "an access token alone must not take the second factor off");
    let (_, me) = app.json(Method::GET, "/v1/me", t, None).await;
    assert_eq!(me["totp_enabled"], true);

    let (s, me) = app.json(Method::POST, "/v1/me/totp/disable", t, Some(json!({"password": PASSWORD}))).await;
    assert_eq!(s, StatusCode::OK, "{me}");
    assert_eq!(me["totp_enabled"], false);

    // The secret and the recovery codes went with it.
    let (secrets,): (i64,) = sqlx::query_as("SELECT count(*) FROM accounts WHERE totp_secret IS NOT NULL")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(secrets, 0, "the sealed secret is gone");
    let (left,): (i64,) =
        sqlx::query_as("SELECT count(*) FROM totp_recovery_codes").fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(left, 0, "and so are the recovery codes");

    // Signing in no longer stops at a code screen.
    let ch = pkce::challenge(&pkce::new_verifier());
    assert!(browser_code(&app, "signin", "off@example.com", PASSWORD, &ch).await.is_ok());
    // And an old recovery code is not a way back in.
    let (s, _) = app.json(Method::POST, "/v1/me/totp/start", t, None).await;
    assert_eq!(s, StatusCode::OK, "enrolling again is allowed");
    assert!(!codes.is_empty());
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_secret_is_never_stored_in_the_clear_and_is_handed_out_once() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "sealed@example.com", "A").await;
    let (secret, _, _) = enrol(&app, &d.tokens.access_token).await;

    let (stored,): (Vec<u8>,) = sqlx::query_as("SELECT totp_secret FROM accounts WHERE email = 'sealed@example.com'")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert!(!stored.windows(secret.len()).any(|w| w == secret.as_slice()), "the secret is in the row in the clear");
    assert!(stored.len() > secret.len(), "a nonce and a tag around it");

    // Nothing hands it out again once it is in force.
    let (s, body) = app.json(Method::POST, "/v1/me/totp/start", &d.tokens.access_token, None).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "{body}");
    let (_, me) = app.json(Method::GET, "/v1/me", &d.tokens.access_token, None).await;
    assert!(me.get("totp_secret").is_none(), "and it is not in /v1/me: {me}");
    let (_, export) = app.json(Method::GET, "/v1/me/export", &d.tokens.access_token, None).await;
    let text = export.to_string();
    assert!(!text.contains(&raye_account_server::otp::base32(&secret)), "nor in the export");
    assert!(!text.contains("totp_secret"), "nor the column: {text}");
    app.db.drop_db().await;
}

#[tokio::test]
async fn guessing_codes_is_rate_limited() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "guess@example.com", "A").await;
    let (secret, _, spent) = enrol(&app, &d.tokens.access_token).await;
    let (_, page) = password_stage(&app, "guess@example.com").await;

    let mut refused = 0;
    let mut throttled = 0;
    for i in 0..12 {
        match try_code(&app, &page, &format!("{:06}", 900_000 + i)).await.0 {
            StatusCode::UNAUTHORIZED => refused += 1,
            StatusCode::TOO_MANY_REQUESTS => throttled += 1,
            other => panic!("unexpected {other}"),
        }
    }
    assert!(refused <= 6, "six digits is a million: guessing must be throttled, got {refused} tries");
    assert!(throttled > 0, "nothing was throttled");

    // And the throttle holds even for the right code: the limit is the
    // defence, so it must not step aside for a correct guess.
    let good = raye_account_server::otp::code_for(&secret, spent + 1);
    assert_eq!(try_code(&app, &page, &good).await.0, StatusCode::TOO_MANY_REQUESTS);
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_authenticator_app_can_stand_in_for_the_reset_link() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "app@example.com", "Bureau").await;
    let (secret, codes, spent) = enrol(&app, &d.tokens.access_token).await;
    let before = app.state.outbox.all().len();

    for (who, code) in [("app@example.com", "000000"), ("nobody@example.com", "123456")] {
        let (s, _, page) = app.form("/reset-password", &[("action", "app"), ("email", who), ("code", code)]).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "{who}");
        assert!(page.contains("didn't work"), "one answer for both: {page}");
    }
    let code = raye_account_server::otp::code_for(&secret, spent + 1);
    let (s, _, page) = app.form("/reset-password", &[("action", "app"), ("email", "app@example.com"), ("code", &code)]).await;
    if s != StatusCode::OK {
        // The next step may not have come yet; a recovery code proves it too.
        let (s2, _, page2) = app.form("/reset-password", &[("action", "app"), ("email", "app@example.com"), ("code", &codes[0])]).await;
        assert_eq!(s2, StatusCode::OK, "{page2}");
        assert!(page2.contains("name=\"token\""));
    } else {
        assert!(page.contains("name=\"token\""), "the form to choose a new password, straight away");
    }
    assert_eq!(app.state.outbox.all().len(), before + 1, "the owner is told, and nothing else is mailed");
    let told = app.state.outbox.last_to("app@example.com").unwrap();
    assert!(told.subject.contains("reset was started") && !told.body.contains("token="), "{}", told.body);
    app.db.drop_db().await;
}

#[tokio::test]
async fn wrong_app_codes_count_on_every_path_and_survive_a_restart() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "many@example.com", "Bureau").await;
    let (secret, _, spent) = enrol(&app, &d.tokens.access_token).await;
    for _ in 0..3 {
        for _ in 0..4 {
            app.form("/reset-password", &[("action", "app"), ("email", "many@example.com"), ("code", "000000")]).await;
        }
        app.state.limits.clear();
    }
    let code = raye_account_server::otp::code_for(&secret, spent + 1);
    let (s, _, _) = app.form("/reset-password", &[("action", "app"), ("email", "many@example.com"), ("code", &code)]).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "closed for the hour, even with the right code");
    app.db.drop_db().await;
}
