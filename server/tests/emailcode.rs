//! The code sent by email at sign-in.

#[allow(dead_code)]
mod common;

use axum::http::{Method, StatusCode};
use common::*;
use raye_account_common::pkce;
use serde_json::json;

async fn code_page(app: &App, email: &str) -> String {
    let (s, _, page) = password_step(app, "signin", email, PASSWORD, &pkce::challenge(&pkce::new_verifier())).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    assert!(is_email_code_page(&page), "{page}");
    page
}

fn wrong(code: &str) -> String {
    let n: u32 = code.parse().unwrap();
    format!("{:06}", (n + 1) % 1_000_000)
}

#[tokio::test]
async fn a_code_is_mailed_after_the_password_and_works_once() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "ana@example.com", "Bureau").await;
    let page = code_page(&app, "ana@example.com").await;
    assert!(page.contains("Check your email"));
    let code = email_code_in_last_letter(&app, "ana@example.com");

    let (s, _, again) = second_step(&app, &page, "emailcode", &wrong(&code)).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    assert!(again.contains("isn't right"), "{again}");
    let (s, _, _) = second_step(&app, &again, "emailcode", &code).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _, _) = second_step(&app, &again, "emailcode", &code).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "spent");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_code_expires_and_dies_after_five_wrong_tries() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "exp@example.com", "Bureau").await;
    let page = code_page(&app, "exp@example.com").await;
    let code = email_code_in_last_letter(&app, "exp@example.com");
    sqlx::query("UPDATE signin_codes SET expires_at = now() - interval '1 second'")
        .execute(&app.db.pool)
        .await
        .unwrap();
    let (s, _, _) = second_step(&app, &page, "emailcode", &code).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "expired");

    let page = code_page(&app, "exp@example.com").await;
    let code = email_code_in_last_letter(&app, "exp@example.com");
    for _ in 0..5 {
        second_step(&app, &page, "emailcode", &wrong(&code)).await;
    }
    let (s, _, _) = second_step(&app, &page, "emailcode", &code).await;
    assert_ne!(s, StatusCode::SEE_OTHER, "the right code after five wrong ones");
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_code_screen_needs_the_server_proof() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "a@example.com", "Bureau").await;
    let page = code_page(&app, "a@example.com").await;
    let code = email_code_in_last_letter(&app, "a@example.com");
    // The TOTP screen's proof does not open this one, nor a doctored one.
    let forged = page.replace(&hidden(&page, "csrf"), "AAAA");
    let (s, _, _) = second_step(&app, &forged, "emailcode", &code).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = second_step(&app, &page, "totp", &code).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_new_code_replaces_the_old_one_and_is_limited() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "re@example.com", "Bureau").await;
    let page = code_page(&app, "re@example.com").await;
    let first = email_code_in_last_letter(&app, "re@example.com");
    let (s, _, page) = second_step(&app, &page, "emailcode-resend", "").await;
    assert_eq!(s, StatusCode::OK);
    let second = email_code_in_last_letter(&app, "re@example.com");
    if first != second {
        let (s, _, _) = second_step(&app, &page, "emailcode", &first).await;
        assert_eq!(s, StatusCode::UNAUTHORIZED, "the old code died");
    }
    let mut limited = false;
    for _ in 0..6 {
        let (s, _, _) = second_step(&app, &page, "emailcode-resend", "").await;
        limited |= s == StatusCode::TOO_MANY_REQUESTS;
    }
    assert!(limited, "resending is rate limited");
    app.db.drop_db().await;
}

#[tokio::test]
async fn turning_the_code_off_needs_the_password() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "off@example.com", "Bureau").await;
    let t = &d.tokens.access_token;
    let (_, me) = app.json(Method::GET, "/v1/me", t, None).await;
    assert_eq!(me["email_code_signin"], true, "on by default");

    let (s, _) = app.json(Method::POST, "/v1/me/email-code", t, Some(json!({"enabled": false}))).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED, "a token alone cannot turn it off");
    let (s, _) = app
        .json(Method::POST, "/v1/me/email-code", t, Some(json!({"enabled": false, "password": "wrong password!"})))
        .await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    let (s, me) = app
        .json(Method::POST, "/v1/me/email-code", t, Some(json!({"enabled": false, "password": PASSWORD})))
        .await;
    assert_eq!(s, StatusCode::OK, "{me}");
    assert_eq!(me["email_code_signin"], false);

    let (s, _, _) = password_step(&app, "signin", "off@example.com", PASSWORD, &pkce::challenge("x")).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "no code asked any more");

    let (s, me) = app.json(Method::POST, "/v1/me/email-code", t, Some(json!({"enabled": true}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["email_code_signin"], true, "turning it back on is free");
    app.db.drop_db().await;
}

#[tokio::test]
async fn new_codes_do_not_buy_new_guesses() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "guess@example.com", "Bureau").await;
    let mut failures = 0;
    for _ in 0..3 {
        let page = code_page(&app, "guess@example.com").await;
        // Let the next password check write a fresh code.
        sqlx::query("UPDATE signin_codes SET created_at = now() - interval '2 minutes'")
            .execute(&app.db.pool)
            .await
            .unwrap();
        let code = email_code_in_last_letter(&app, "guess@example.com");
        for _ in 0..4 {
            second_step(&app, &page, "emailcode", &wrong(&code)).await;
            failures += 1;
        }
        app.state.limits.clear();
    }
    assert!(failures >= 10);
    let page = code_page(&app, "guess@example.com").await;
    let code = email_code_in_last_letter(&app, "guess@example.com");
    let (s, _, _) = second_step(&app, &page, "emailcode", &code).await;
    assert_ne!(s, StatusCode::SEE_OTHER, "the step is closed for the hour, even with the right code");
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_proof_does_not_outlive_the_password_check() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "old@example.com", "Bureau").await;
    let page = code_page(&app, "old@example.com").await;
    let (_, _, again) = second_step(&app, &page, "emailcode", "000000").await;
    assert_eq!(hidden(&again, "ts"), hidden(&page, "ts"), "a retry keeps the time of the password check");
    app.db.drop_db().await;
}
