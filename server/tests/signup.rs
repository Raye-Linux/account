//! Creating an account: nothing exists until the address is confirmed, and
//! the sign-up page never says whether an address is already used.

#[allow(dead_code)]
mod common;

use axum::http::StatusCode;
use common::*;
use raye_account_common::pkce;

async fn accounts(app: &App, email: &str) -> i64 {
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM accounts WHERE email = $1")
        .bind(email)
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    n
}

async fn try_sign_in(app: &App, email: &str, password: &str) -> StatusCode {
    let v = pkce::new_verifier();
    match browser_code(app, "signin", email, password, &pkce::challenge(&v)).await {
        Ok(_) => StatusCode::SEE_OTHER,
        Err((s, _)) => s,
    }
}

#[tokio::test]
async fn no_account_until_the_link_is_opened() {
    let Some(app) = app().await else { return };
    let (s, page) = sign_up_form(&app, "ana@example.com", PASSWORD).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Check your email"), "{page}");
    assert_eq!(accounts(&app, "ana@example.com").await, 0);
    assert_eq!(try_sign_in(&app, "ana@example.com", PASSWORD).await, StatusCode::UNAUTHORIZED);

    let link = link_in_last_letter(&app, "ana@example.com");
    assert!(link.starts_with("http://127.0.0.1:8787/verify-email?token="), "{link}");
    // A mail scanner fetching the link must not create the account.
    let (s, page) = app.page(link.strip_prefix("http://127.0.0.1:8787").unwrap()).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("<form"), "{page}");
    assert_eq!(accounts(&app, "ana@example.com").await, 0);

    let token = token_of(&link);
    let (s, _, page) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("is ready"), "{page}");
    assert_eq!(accounts(&app, "ana@example.com").await, 1);
    assert_eq!(try_sign_in(&app, "ana@example.com", PASSWORD).await, StatusCode::SEE_OTHER);

    let (s, _, _) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "single use");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_taken_address_gets_the_same_page_and_a_letter() {
    let Some(app) = app().await else { return };
    let (_, fresh) = sign_up_form(&app, "new@example.com", PASSWORD).await;
    let _ = sign_up(&app, "own@example.com", "Bureau").await;
    let before = app.state.outbox.all().len();

    let (s, again) = sign_up_form(&app, "own@example.com", "a different password").await;
    assert_eq!(s, StatusCode::OK);
    let strip = |p: &str| p.split("<form").next().unwrap().split("<a href").next().unwrap().to_owned();
    assert_eq!(strip(&again), strip(&fresh), "the page must not tell the two apart");
    assert_eq!(app.state.outbox.all().len(), before + 1, "the owner is written to");
    let letter = app.state.outbox.last_to("own@example.com").unwrap();
    assert!(letter.body.contains("/reset-password"), "{}", letter.body);
    assert!(!letter.body.contains("token="), "no link that could make a second account");

    assert_eq!(try_sign_in(&app, "own@example.com", PASSWORD).await, StatusCode::SEE_OTHER);
    assert_eq!(try_sign_in(&app, "own@example.com", "a different password").await, StatusCode::UNAUTHORIZED);
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_pending_sign_up_does_not_hold_the_address() {
    let Some(app) = app().await else { return };
    // Someone signs up with an address that is not theirs and never confirms.
    sign_up_form(&app, "real@example.com", "the squatter's password").await;
    let squat = token_of(&link_in_last_letter(&app, "real@example.com"));

    // The real owner signs up too and opens their own letter first.
    sign_up_form(&app, "real@example.com", PASSWORD).await;
    let mine = token_of(&link_in_last_letter(&app, "real@example.com"));
    assert_ne!(squat, mine);
    let (s, _, _) = app.form("/verify-email", &[("token", &mine)]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(try_sign_in(&app, "real@example.com", PASSWORD).await, StatusCode::SEE_OTHER);

    let (s, _, _) = app.form("/verify-email", &[("token", &squat)]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "the other sign-up died with the confirmation");
    assert_eq!(try_sign_in(&app, "real@example.com", "the squatter's password").await, StatusCode::UNAUTHORIZED);
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_sign_up_link_expires() {
    let Some(app) = app().await else { return };
    sign_up_form(&app, "late@example.com", PASSWORD).await;
    let token = token_of(&link_in_last_letter(&app, "late@example.com"));
    sqlx::query("UPDATE pending_signups SET expires_at = now() - interval '1 second'")
        .execute(&app.db.pool)
        .await
        .unwrap();
    let (s, _, _) = app.form("/verify-email", &[("token", &token)]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert_eq!(accounts(&app, "late@example.com").await, 0);
    app.db.drop_db().await;
}

#[tokio::test]
async fn sign_up_letters_are_rate_limited_per_address() {
    let Some(app) = app().await else { return };
    for _ in 0..3 {
        sign_up_form(&app, "flood@example.com", PASSWORD).await;
    }
    let sent = app.state.outbox.all().len();
    let (s, page) = sign_up_form(&app, "flood@example.com", PASSWORD).await;
    assert_eq!(s, StatusCode::OK, "same page, so the limit says nothing either");
    assert!(page.contains("Check your email"));
    assert_eq!(app.state.outbox.all().len(), sent, "but no fourth letter");
    app.db.drop_db().await;
}

#[tokio::test]
async fn an_old_unconfirmed_account_does_not_hold_the_address() {
    let Some(app) = app().await else { return };
    let hash = raye_account_server_hash("someone else's password");
    sqlx::query("INSERT INTO accounts (id, email, password_hash, display_name) VALUES ($1, 'old@example.com', $2, 'X')")
        .bind(uuid::Uuid::new_v4())
        .bind(hash)
        .execute(&app.db.pool)
        .await
        .unwrap();
    sign_up_form(&app, "old@example.com", PASSWORD).await;
    let link = link_in_last_letter(&app, "old@example.com");
    assert!(link.contains("token="), "a real confirmation, not the already-registered letter");
    let (s, _, _) = app.form("/verify-email", &[("token", &token_of(&link))]).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(accounts(&app, "old@example.com").await, 1);
    assert_eq!(try_sign_in(&app, "old@example.com", PASSWORD).await, StatusCode::SEE_OTHER);
    app.db.drop_db().await;
}

fn raye_account_server_hash(p: &str) -> String {
    use argon2::password_hash::{PasswordHasher, SaltString};
    let salt = SaltString::generate(&mut rand::rngs::OsRng);
    argon2::Argon2::default().hash_password(p.as_bytes(), &salt).unwrap().to_string()
}
