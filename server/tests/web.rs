//! The account website: a session in a cookie, and the pages behind it.

#[allow(dead_code)]
mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;

async fn get(app: &App, uri: &str, cookie: &str) -> (StatusCode, axum::http::HeaderMap, String) {
    let req = Request::get(uri).header(header::COOKIE, cookie).body(Body::empty()).unwrap();
    let (s, h, b) = app.call(req).await;
    (s, h, String::from_utf8_lossy(&b).into_owned())
}

async fn post(app: &App, uri: &str, cookie: &str, fields: &[(&str, &str)]) -> (StatusCode, axum::http::HeaderMap, String) {
    let body = fields.iter().map(|(k, v)| format!("{}={}", enc(k), enc(v))).collect::<Vec<_>>().join("&");
    let req = Request::post(uri)
        .header(header::COOKIE, cookie)
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from(body))
        .unwrap();
    let (s, h, b) = app.call(req).await;
    (s, h, String::from_utf8_lossy(&b).into_owned())
}

fn session_cookie(h: &axum::http::HeaderMap) -> String {
    let set = h.get(header::SET_COOKIE).expect("a session cookie").to_str().unwrap();
    assert!(set.contains("HttpOnly") && set.contains("SameSite=Lax"), "{set}");
    set.split(';').next().unwrap().to_owned()
}

/// Signs in on the website (password, then the code by email).
async fn web_sign_in(app: &App, email: &str) -> String {
    let (s, _, page) = get(app, "/signin", "").await;
    assert_eq!(s, StatusCode::OK);
    let fields = |page: &str, action: &str, extra: Vec<(&str, String)>| {
        let mut v: Vec<(String, String)> = vec![("action".into(), action.into())];
        for k in ["next", "ts", "mac", "account"] {
            if page.contains(&format!("name=\"{k}\" value=\"")) {
                v.push((k.into(), hidden(page, k)));
            }
        }
        for (k, val) in extra {
            v.push((k.into(), val));
        }
        v
    };
    let f = fields(&page, "password", vec![("email", email.into()), ("password", PASSWORD.into())]);
    let refs: Vec<(&str, &str)> = f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (s, _, page) = post(app, "/signin", "", &refs).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let code = email_code_in_last_letter(app, email);
    let f = fields(&page, "emailcode", vec![("code", code)]);
    let refs: Vec<(&str, &str)> = f.iter().map(|(a, b)| (a.as_str(), b.as_str())).collect();
    let (s, h, page) = post(app, "/signin", "", &refs).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "{page}");
    session_cookie(&h)
}

async fn csrf(app: &App, cookie: &str) -> String {
    let (_, _, page) = get(app, "/account/info", cookie).await;
    hidden(&page, "csrf")
}

#[tokio::test]
async fn account_pages_need_a_session() {
    let Some(app) = app().await else { return };
    for uri in ["/account", "/account/info", "/account/security", "/account/devices", "/account/privacy"] {
        let (s, h, _) = get(&app, uri, "").await;
        assert_eq!(s, StatusCode::SEE_OTHER, "{uri}");
        assert!(h[header::LOCATION].to_str().unwrap().starts_with("/signin?next="), "{uri}");
    }
    let (_, _, page) = get(&app, "/signin", "").await;
    assert!(page.contains("class=\"bar\"") && page.contains("href=\"/signin\""), "the bar offers Sign in");
    let (s, _, _) = get(&app, "/account/photo", "").await;
    assert_eq!(s, StatusCode::NOT_FOUND);
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_website_signs_in_with_the_email_code_and_shows_the_account() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "ana@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "ana@example.com").await;
    let (s, h, page) = get(&app, "/account", &cookie).await;
    assert_eq!(s, StatusCode::OK);
    assert!(page.contains("Ana Tremblay") && page.contains("ana@example.com"));
    assert!(page.contains("My Raye account") && page.contains("action=\"/signout\""), "the account flyout");
    assert!(page.contains(">AT<"), "initials when there is no photo");
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"), "{csp}");
    app.db.drop_db().await;
}

#[tokio::test]
async fn signing_out_ends_the_session_on_the_server() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "out@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "out@example.com").await;
    let token = csrf(&app, &cookie).await;
    let (s, h, _) = post(&app, "/signout", &cookie, &[("csrf", &token)]).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h[header::SET_COOKIE].to_str().unwrap().contains("Max-Age=0"));
    // The same cookie, kept by someone, opens nothing any more.
    let (s, _, _) = get(&app, "/account", &cookie).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM web_sessions").fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(n, 0);
    app.db.drop_db().await;
}

#[tokio::test]
async fn every_change_needs_the_csrf_token() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "csrf@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "csrf@example.com").await;
    let (s, _, _) = post(&app, "/account/info/name", &cookie, &[("csrf", "nope"), ("display_name", "Mallory")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (s, _, _) = post(&app, "/signout", &cookie, &[("csrf", "nope")]).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let (_, _, page) = get(&app, "/account", &cookie).await;
    assert!(page.contains("Ana Tremblay"), "nothing changed, still signed in");
    app.db.drop_db().await;
}

fn png() -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(300, 200, image::Rgba([123, 60, 255, 255]));
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png).unwrap();
    out
}

#[tokio::test]
async fn name_and_photo_change_from_the_website() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "info@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "info@example.com").await;
    let token = csrf(&app, &cookie).await;
    let (s, h, _) = post(&app, "/account/info/name", &cookie, &[("csrf", &token), ("display_name", "Ana T.")]).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/account/info?done=name");

    let boundary = "XyZ0123";
    let mut body = format!("--{boundary}\r\nContent-Disposition: form-data; name=\"csrf\"\r\n\r\n{token}\r\n--{boundary}\r\nContent-Disposition: form-data; name=\"photo\"; filename=\"me.png\"\r\nContent-Type: image/png\r\n\r\n").into_bytes();
    body.extend(png());
    body.extend(format!("\r\n--{boundary}--\r\n").into_bytes());
    let req = Request::post("/account/info/photo")
        .header(header::COOKIE, &cookie)
        .header(header::CONTENT_TYPE, format!("multipart/form-data; boundary={boundary}"))
        .body(Body::from(body))
        .unwrap();
    let (s, h, _) = app.call(req).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/account/info?done=photo");
    let (s, h, _) = get(&app, "/account/photo", &cookie).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "image/png");

    // The PC sees both through the API.
    let (_, me) = app.json(Method::GET, "/v1/me", &d.tokens.access_token, None).await;
    assert_eq!(me["display_name"], "Ana T.");
    assert!(me["avatar_etag"].is_string());
    app.db.drop_db().await;
}

#[tokio::test]
async fn taking_a_protection_off_needs_a_recent_sign_in() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "recent@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "recent@example.com").await;
    let token = csrf(&app, &cookie).await;
    sqlx::query("UPDATE web_sessions SET auth_at = now() - interval '1 hour'").execute(&app.db.pool).await.unwrap();
    let (s, h, _) = post(&app, "/account/security/email-code", &cookie, &[("csrf", &token), ("to", "off")]).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert!(h[header::LOCATION].to_str().unwrap().starts_with("/signin"));
    let (on,): (bool,) = sqlx::query_as("SELECT email_code_signin FROM accounts").fetch_one(&app.db.pool).await.unwrap();
    assert!(on);

    sqlx::query("UPDATE web_sessions SET auth_at = now()").execute(&app.db.pool).await.unwrap();
    let (s, h, _) = post(&app, "/account/security/email-code", &cookie, &[("csrf", &token), ("to", "off")]).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/account/security?done=email-code");
    let (on,): (bool,) = sqlx::query_as("SELECT email_code_signin FROM accounts").fetch_one(&app.db.pool).await.unwrap();
    assert!(!on);
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_pc_signed_out_from_the_website_is_signed_out() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "dev@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "dev@example.com").await;
    let (_, _, page) = get(&app, "/account/devices", &cookie).await;
    assert!(page.contains("Bureau"));
    let token = csrf(&app, &cookie).await;
    let id = d.tokens.device_id.to_string();
    let (s, _, _) = post(&app, &format!("/account/devices/{id}/remove"), &cookie, &[("csrf", &token)]).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    let (s, _) = app.json(Method::GET, "/v1/me", &d.tokens.access_token, None).await;
    assert_eq!(s, StatusCode::UNAUTHORIZED);
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_account_can_be_closed_from_the_website() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "bye@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "bye@example.com").await;
    let (s, h, _) = get(&app, "/account/privacy/export", &cookie).await;
    assert_eq!(s, StatusCode::OK);
    assert!(h[header::CONTENT_DISPOSITION].to_str().unwrap().contains("attachment"));
    let token = csrf(&app, &cookie).await;
    let (s, _, _) = post(&app, "/account/privacy/delete", &cookie, &[("csrf", &token), ("password", "wrong password!"), ("sure", "yes")]).await;
    assert_eq!(s, StatusCode::SEE_OTHER, "a wrong password goes back with an error");
    let (s, _, page) = post(&app, "/account/privacy/delete", &cookie, &[("csrf", &token), ("password", PASSWORD), ("sure", "yes")]).await;
    assert_eq!(s, StatusCode::OK, "{page}");
    let (n,): (i64,) = sqlx::query_as("SELECT count(*) FROM accounts").fetch_one(&app.db.pool).await.unwrap();
    assert_eq!(n, 0);
    app.db.drop_db().await;
}

#[tokio::test]
async fn the_language_switch_sticks() {
    let Some(app) = app().await else { return };
    let (s, h, _) = get(&app, "/lang/fr?back=/signin", "").await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    assert_eq!(h[header::LOCATION], "/signin");
    let lang = h[header::SET_COOKIE].to_str().unwrap().split(';').next().unwrap().to_owned();
    let (_, _, page) = get(&app, "/signin", &lang).await;
    assert!(page.contains("lang=\"fr\"") && page.contains("Se connecter"), "{page}");
    let (_, h, _) = get(&app, "/lang/fr?back=//evil.example", "").await;
    assert_eq!(h[header::LOCATION], "/account", "never sent off the site");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_signin_form_cannot_be_reused_or_forged() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "forge@example.com", "Bureau").await;
    let (s, _, _) = post(&app, "/signin", "", &[("action", "password"), ("email", "forge@example.com"), ("password", PASSWORD), ("ts", "1"), ("mac", "AAAA"), ("next", "/account")]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _, _) = post(&app, "/signin", "", &[("action", "emailcode"), ("account", &uuid::Uuid::new_v4().to_string()), ("code", "000000"), ("ts", "1"), ("mac", "AAAA"), ("next", "/account")]).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    app.db.drop_db().await;
}

#[tokio::test]
async fn own_forms_keep_their_origin() {
    // With no-referrer, browsers post the site's own forms with "Origin: null",
    // which the same-origin check has to refuse.
    let Some(app) = app().await else { return };
    let (_, h, _) = get(&app, "/signin", "").await;
    assert_eq!(h.get(header::REFERRER_POLICY).unwrap(), "same-origin");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_form_posted_from_another_site_is_refused() {
    let Some(app) = app().await else { return };
    let req = Request::post("/signin")
        .header(header::ORIGIN, "https://evil.example")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("action=password"))
        .unwrap();
    let (s, _, _) = app.call(req).await;
    assert_eq!(s, StatusCode::FORBIDDEN);
    let req = Request::post("/signin")
        .header(header::ORIGIN, "http://127.0.0.1:8787")
        .header(header::CONTENT_TYPE, "application/x-www-form-urlencoded")
        .body(Body::from("action=password&ts=1&mac=x"))
        .unwrap();
    let (s, _, _) = app.call(req).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "same origin goes through to the form check");
    app.db.drop_db().await;
}

#[tokio::test]
async fn a_password_reset_signs_the_browsers_out_too() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "reset@example.com", "Bureau").await;
    let cookie = web_sign_in(&app, "reset@example.com").await;
    app.form("/reset-password", &[("action", "request"), ("email", "reset@example.com")]).await;
    let token = token_of(&link_in_last_letter(&app, "reset@example.com"));
    let (s, _, _) = app
        .form("/reset-password", &[("action", "set"), ("token", &token), ("password", "another long password"), ("password2", "another long password")])
        .await;
    assert_eq!(s, StatusCode::OK);
    let (s, _, _) = get(&app, "/account", &cookie).await;
    assert_eq!(s, StatusCode::SEE_OTHER);
    app.db.drop_db().await;
}
