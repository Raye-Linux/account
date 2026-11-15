//! End-to-end tests of the account API against a real PostgreSQL: signing
//! in, devices, settings sync, the profile, the Store library, privacy.
//! The harness is in tests/common.

mod common;

use axum::body::Body;
use axum::http::{header, Method, Request, StatusCode};
use common::*;
use ed25519_dalek::SigningKey;
use raye_account_common::api::{LibraryApp, TokenResponse};
use raye_account_common::pkce;
use serde_json::{json, Value};

#[tokio::test]
async fn sign_up_then_sign_in_on_a_second_pc() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "Ana@Example.com", "Bureau").await;
    let (s, me) = app.json(Method::GET, "/v1/me", &a.tokens.access_token, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["email"], "ana@example.com");
    assert_eq!(me["display_name"], "Ana Tremblay");
    assert_eq!(me["email_verified"], true);

    let b = sign_in(&app, "ana@example.com", "Portable").await;
    let (_, devices) = app.json(Method::GET, "/v1/devices", &b.tokens.access_token, None).await;
    let names: Vec<_> = devices.as_array().unwrap().iter().map(|d| d["name"].as_str().unwrap()).collect();
    assert_eq!(names.len(), 2);
    assert!(names.contains(&"Bureau") && names.contains(&"Portable"));
    let this: Vec<_> = devices.as_array().unwrap().iter().filter(|d| d["this_device"] == true).collect();
    assert_eq!(this[0]["name"], "Portable");
    assert_eq!(this[0]["model"], "Dell Latitude 5420");
    app.db.drop_db().await;
}

#[tokio::test]
async fn codes_are_single_use_and_need_the_verifier() {
    let Some(app) = app().await else { return };
    let _ = sign_up(&app, "b@example.com", "first").await;
    let v = pkce::new_verifier();
    let code = browser_code(&app, "signin", "b@example.com", "a long enough password", &pkce::challenge(&v)).await.unwrap();
    assert_eq!(exchange(&app, &code, &pkce::new_verifier(), "x").await.0, StatusCode::BAD_REQUEST, "wrong verifier");
    // The failed try used the code up.
    assert_eq!(exchange(&app, &code, &v, "x").await.0, StatusCode::BAD_REQUEST);

    let v = pkce::new_verifier();
    let code = browser_code(&app, "signin", "b@example.com", "a long enough password", &pkce::challenge(&v)).await.unwrap();
    assert_eq!(exchange(&app, &code, &v, "x").await.0, StatusCode::OK);
    assert_eq!(exchange(&app, &code, &v, "x").await.0, StatusCode::BAD_REQUEST, "replay");
    app.db.drop_db().await;
}

#[tokio::test]
async fn authorize_refuses_foreign_redirects_and_forged_forms() {
    let Some(app) = app().await else { return };
    for redirect in ["https://evil.example/callback", "http://localhost:5000/callback", "http://127.0.0.1:5000/other"] {
        let uri = format!(
            "/oauth/authorize?response_type=code&client_id=raye-desktop&redirect_uri={}&state=state-0123456789abcdef&code_challenge={}&code_challenge_method=S256",
            enc(redirect),
            pkce::challenge("x")
        );
        let (s, h, _) = app.call(Request::get(&uri).body(Body::empty()).unwrap()).await;
        assert_eq!(s, StatusCode::BAD_REQUEST, "{redirect}");
        assert!(h.get(header::LOCATION).is_none());
    }
    // A form whose redirect was changed after the page was served.
    let (s, _, body) = app
        .form(
            "/oauth/authorize",
            &[
                ("action", "signin"),
                ("email", "x@example.com"),
                ("password", "whatever whatever"),
                ("redirect_uri", "http://127.0.0.1:6000/callback"),
                ("state", "state-0123456789abcdef"),
                ("code_challenge", &pkce::challenge(&pkce::new_verifier())),
                ("ts", &time::OffsetDateTime::now_utc().unix_timestamp().to_string()),
                ("csrf", "AAAA"),
            ],
        )
        .await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    assert!(body.contains("Start again"));
    app.db.drop_db().await;
}

#[tokio::test]
async fn wrong_passwords_lock_the_account_for_a_while() {
    let Some(app) = app().await else { return };
    sign_up(&app, "c@example.com", "pc").await;
    let ch = pkce::challenge(&pkce::new_verifier());
    for _ in 0..5 {
        let e = browser_code(&app, "signin", "c@example.com", "wrong password!!", &ch).await.unwrap_err();
        assert_eq!(e.0, StatusCode::UNAUTHORIZED);
        assert!(e.1.contains("isn't right"));
        assert!(!e.1.contains("wrong password!!"), "the password is never echoed");
    }
    let e = browser_code(&app, "signin", "c@example.com", "a long enough password", &ch).await.unwrap_err();
    assert_eq!(e.0, StatusCode::TOO_MANY_REQUESTS);
    // An unknown email gets the same answer as a wrong password.
    let e = browser_code(&app, "signin", "nobody@example.com", "a long enough password", &ch).await.unwrap_err();
    assert_eq!(e.0, StatusCode::UNAUTHORIZED);
    app.db.drop_db().await;
}

#[tokio::test]
async fn refresh_rotates_and_a_reused_token_ends_the_device() {
    let Some(app) = app().await else { return };
    let d = sign_up(&app, "d@example.com", "pc").await;
    let first = d.tokens.refresh_token.clone();

    let (s, _) = refresh(&app, &d, &first, -10 * 60).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "stale proof");
    let other = Device { key: SigningKey::generate(&mut rand::rngs::OsRng), tokens: d.tokens.clone() };
    let (s, _) = refresh(&app, &other, &first, 0).await;
    assert_eq!(s, StatusCode::BAD_REQUEST, "proof from another key");

    let (s, body) = refresh(&app, &d, &first, 0).await;
    assert_eq!(s, StatusCode::OK, "{body}");
    let next: TokenResponse = serde_json::from_str(&body).unwrap();
    assert_ne!(next.refresh_token, first);
    assert_eq!(app.json(Method::GET, "/v1/me", &next.access_token, None).await.0, StatusCode::OK);

    // The first token comes back: treated as stolen, the device is signed out.
    assert_eq!(refresh(&app, &d, &first, 0).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(app.json(Method::GET, "/v1/me", &next.access_token, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(refresh(&app, &d, &next.refresh_token, 0).await.0, StatusCode::BAD_REQUEST);
    app.db.drop_db().await;
}

#[tokio::test]
async fn removing_a_device_signs_it_out_and_stays_in_the_account() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "e@example.com", "Bureau").await;
    let b = sign_in(&app, "e@example.com", "Portable").await;
    let stranger = sign_up(&app, "f@example.com", "Autre").await;

    let uri = format!("/v1/devices/{}", b.tokens.device_id);
    assert_eq!(app.json(Method::DELETE, &uri, &stranger.tokens.access_token, None).await.0, StatusCode::NOT_FOUND);
    assert_eq!(app.json(Method::DELETE, &uri, &a.tokens.access_token, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(app.json(Method::GET, "/v1/me", &b.tokens.access_token, None).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(refresh(&app, &b, &b.tokens.refresh_token, 0).await.0, StatusCode::BAD_REQUEST);

    let (s, _) = app
        .json(Method::PATCH, "/v1/devices/current", &a.tokens.access_token, Some(json!({"name": "Salon", "raye_version": "0.2"})))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (_, list) = app.json(Method::GET, "/v1/devices", &a.tokens.access_token, None).await;
    assert_eq!(list[0]["name"], "Salon");
    assert_eq!(list[0]["raye_version"], "0.2");

    assert_eq!(app.json(Method::POST, "/v1/oauth/revoke", &a.tokens.access_token, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(app.json(Method::GET, "/v1/devices", &a.tokens.access_token, None).await.0, StatusCode::UNAUTHORIZED);
    app.db.drop_db().await;
}

#[tokio::test]
async fn settings_sync_between_two_pcs_with_conflicts() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "g@example.com", "A").await;
    let b = sign_in(&app, "g@example.com", "B").await;
    let (ta, tb) = (&a.tokens.access_token, &b.tokens.access_token);

    let push = |key: &str, value: Value, base: i64, at: &str| {
        json!({"changes": [{"key": key, "value": value, "base_rev": base, "modified_at": at}]})
    };
    let (s, r) = app
        .json(Method::PUT, "/v1/settings", ta, Some(push("appearance.accentColor", json!("#7b3cff"), 0, "2026-11-01T10:00:00Z")))
        .await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(r["rev"], 1);
    assert_eq!(r["results"][0]["outcome"], "accepted");

    // B never saw rev 1 and its change is older: A's value stays and B is told.
    let (_, r) = app
        .json(Method::PUT, "/v1/settings", tb, Some(push("appearance.accentColor", json!("#ff0000"), 0, "2026-11-01T09:00:00Z")))
        .await;
    assert_eq!(r["results"][0]["outcome"], "superseded");
    assert_eq!(r["results"][0]["item"]["value"], "#7b3cff");
    assert_eq!(r["rev"], 1);

    // Newer change from B wins even without having seen rev 1.
    let (_, r) = app
        .json(Method::PUT, "/v1/settings", tb, Some(push("appearance.accentColor", json!("#00aa88"), 0, "2026-11-01T11:00:00Z")))
        .await;
    assert_eq!(r["results"][0]["outcome"], "accepted");
    assert_eq!(r["rev"], 2);

    let (_, page) = app.json(Method::GET, "/v1/settings?since=1", ta, None).await;
    assert_eq!(page["rev"], 2);
    assert_eq!(page["items"].as_array().unwrap().len(), 1);
    assert_eq!(page["items"][0]["value"], "#00aa88");
    assert_eq!(page["items"][0]["device_id"], b.tokens.device_id.to_string());

    // Sending the same value again does not wake the other devices.
    let (_, r) = app
        .json(Method::PUT, "/v1/settings", ta, Some(push("appearance.accentColor", json!("#00aa88"), 2, "2026-11-01T12:00:00Z")))
        .await;
    assert_eq!(r["rev"], 2);

    // Removal travels too.
    let (_, r) = app
        .json(Method::PUT, "/v1/settings", ta, Some(push("appearance.accentColor", Value::Null, 2, "2026-11-01T12:30:00Z")))
        .await;
    assert_eq!(r["rev"], 3);
    let (_, page) = app.json(Method::GET, "/v1/settings?since=2", tb, None).await;
    assert!(page["items"][0]["value"].is_null());

    // A clock far in the future is pulled back to the server's time.
    let (_, r) = app
        .json(Method::PUT, "/v1/settings", ta, Some(push("region.formats", json!("fr_CA"), 0, "2099-01-01T00:00:00Z")))
        .await;
    assert!(r["results"][0]["item"]["modified_at"].as_str().unwrap() < "2099");
    app.db.drop_db().await;
}

#[tokio::test]
async fn settings_refuse_what_is_not_on_the_list() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "h@example.com", "A").await;
    let t = &a.tokens.access_token;
    let one = |key: &str, value: Value| json!({"changes": [{"key": key, "value": value, "base_rev": 0, "modified_at": "2026-11-01T10:00:00Z"}]});
    assert_eq!(app.json(Method::PUT, "/v1/settings", t, Some(one("my.secret.notes", json!("x")))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(app.json(Method::PUT, "/v1/settings", t, Some(one("appearance.accentColor", json!({"a": 1})))).await.0, StatusCode::BAD_REQUEST);
    let twice = json!({"changes": [
        {"key": "region.formats", "value": "fr_CA", "base_rev": 0, "modified_at": "2026-11-01T10:00:00Z"},
        {"key": "region.formats", "value": "en_US", "base_rev": 0, "modified_at": "2026-11-01T10:00:00Z"}]});
    assert_eq!(app.json(Method::PUT, "/v1/settings", t, Some(twice)).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(app.json(Method::GET, "/v1/settings", "not-a-token", None).await.0, StatusCode::UNAUTHORIZED);
    app.db.drop_db().await;
}

fn png(w: u32, h: u32) -> Vec<u8> {
    let img = image::RgbaImage::from_pixel(w, h, image::Rgba([192, 64, 255, 255]));
    let mut out = Vec::new();
    img.write_to(&mut std::io::Cursor::new(&mut out), image::ImageFormat::Png).unwrap();
    out
}

#[tokio::test]
async fn profile_picture_and_name() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "i@example.com", "A").await;
    let t = a.tokens.access_token.clone();
    let put = |body: Vec<u8>| {
        Request::put("/v1/me/avatar")
            .header(header::AUTHORIZATION, format!("Bearer {t}"))
            .header(header::CONTENT_TYPE, "image/png")
            .body(Body::from(body))
            .unwrap()
    };
    let (s, _, body) = app.call(put(png(800, 600))).await;
    assert_eq!(s, StatusCode::OK);
    let me: Value = serde_json::from_slice(&body).unwrap();
    let etag = me["avatar_etag"].as_str().unwrap().to_owned();

    let get = |inm: Option<&str>| {
        let mut b = Request::get("/v1/me/avatar").header(header::AUTHORIZATION, format!("Bearer {t}"));
        if let Some(v) = inm {
            b = b.header(header::IF_NONE_MATCH, v);
        }
        b.body(Body::empty()).unwrap()
    };
    let (s, h, pic) = app.call(get(None)).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(h[header::CONTENT_TYPE], "image/png");
    let img = image::load_from_memory(&pic).unwrap();
    assert_eq!((img.width(), img.height()), (256, 256));
    let (s, _, _) = app.call(get(Some(&format!("\"{etag}\"")))).await;
    assert_eq!(s, StatusCode::NOT_MODIFIED);

    let (s, _, _) = app.call(put(b"GIF89a\x01\x00\x01\x00".to_vec())).await;
    assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
    let (s, _, _) = app.call(put(vec![0u8; 3 * 1024 * 1024])).await;
    assert_eq!(s, StatusCode::PAYLOAD_TOO_LARGE);

    let (s, me) = app.json(Method::PATCH, "/v1/me", &t, Some(json!({"display_name": "  Ana T.  "}))).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(me["display_name"], "Ana T.");
    assert_eq!(app.json(Method::PATCH, "/v1/me", &t, Some(json!({"display_name": "x".repeat(65)}))).await.0, StatusCode::BAD_REQUEST);
    assert_eq!(app.json(Method::PATCH, "/v1/me", &t, Some(json!({"display_name": "a\u{0}b"}))).await.0, StatusCode::BAD_REQUEST);

    assert_eq!(app.json(Method::DELETE, "/v1/me/avatar", &t, None).await.0, StatusCode::NO_CONTENT);
    assert_eq!(app.call(get(None)).await.0, StatusCode::NOT_FOUND);
    app.db.drop_db().await;
}

#[tokio::test]
async fn store_library_follows_installs_on_each_pc() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "j@example.com", "A").await;
    let b = sign_in(&app, "j@example.com", "B").await;
    let installs = |ids: &[(&str, &str)]| {
        json!({"apps": ids.iter().map(|(a, s)| json!({"app_id": a, "source": s})).collect::<Vec<_>>()})
    };
    let (s, _) = app
        .json(Method::PUT, "/v1/devices/current/installs", &a.tokens.access_token,
              Some(installs(&[("org.mozilla.firefox", "flathub"), ("com.discordapp.Discord", "flathub")])))
        .await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    app.json(Method::PUT, "/v1/devices/current/installs", &b.tokens.access_token, Some(installs(&[("org.mozilla.firefox", "flathub")])))
        .await;

    let (_, lib) = app.json(Method::GET, "/v1/store/library", &b.tokens.access_token, None).await;
    let lib: Vec<LibraryApp> = serde_json::from_value(lib).unwrap();
    assert_eq!(lib.len(), 2);
    let ff = lib.iter().find(|l| l.app_id == "org.mozilla.firefox").unwrap();
    assert_eq!(ff.installed_on.len(), 2);
    let discord = lib.iter().find(|l| l.app_id == "com.discordapp.Discord").unwrap();
    assert_eq!(discord.installed_on, vec![a.tokens.device_id], "B can offer to install Discord from A");

    let (_, devs) = app.json(Method::GET, "/v1/devices", &b.tokens.access_token, None).await;
    let a_row = devs.as_array().unwrap().iter().find(|d| d["name"] == "A").unwrap();
    assert_eq!(a_row["app_count"], 2);
    let (_, list) = app.json(Method::GET, &format!("/v1/devices/{}/installs", a.tokens.device_id), &b.tokens.access_token, None).await;
    assert_eq!(list["apps"].as_array().unwrap().len(), 2);

    let (s, _) = app.json(Method::PUT, "/v1/devices/current/installs", &a.tokens.access_token, Some(installs(&[("../x", "flathub")]))).await;
    assert_eq!(s, StatusCode::BAD_REQUEST);
    let (s, _) = app.json(Method::PUT, "/v1/store/library/org.gimp.GIMP", &a.tokens.access_token, Some(json!({"source": "flathub"}))).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    let (s, _) = app.json(Method::DELETE, "/v1/store/library/org.gimp.GIMP", &a.tokens.access_token, None).await;
    assert_eq!(s, StatusCode::NO_CONTENT);
    app.db.drop_db().await;
}

#[tokio::test]
async fn export_then_delete_the_account() {
    let Some(app) = app().await else { return };
    let a = sign_up(&app, "k@example.com", "A").await;
    let t = &a.tokens.access_token;
    app.json(Method::PUT, "/v1/settings", t, Some(json!({"changes": [
        {"key": "region.language", "value": ["fr_CA"], "base_rev": 0, "modified_at": "2026-11-01T10:00:00Z"}]}))).await;
    let (s, export) = app.json(Method::GET, "/v1/me/export", t, None).await;
    assert_eq!(s, StatusCode::OK);
    assert_eq!(export["account"]["email"], "k@example.com");
    assert_eq!(export["settings"][0]["key"], "region.language");
    assert_eq!(export["devices"][0]["name"], "A");
    assert!(export.to_string().find("password").is_none(), "no password hash in the export");

    assert_eq!(app.json(Method::POST, "/v1/me/delete", t, Some(json!({"password": "nope nope nope"}))).await.0, StatusCode::UNAUTHORIZED);
    assert_eq!(app.json(Method::POST, "/v1/me/delete", t, Some(json!({"password": "a long enough password"}))).await.0, StatusCode::NO_CONTENT);
    assert_eq!(app.json(Method::GET, "/v1/me", t, None).await.0, StatusCode::UNAUTHORIZED);
    let left: (i64,) = sqlx::query_as("SELECT (SELECT count(*) FROM devices) + (SELECT count(*) FROM settings) + (SELECT count(*) FROM access_tokens)")
        .fetch_one(&app.db.pool)
        .await
        .unwrap();
    assert_eq!(left.0, 0, "nothing of the account is left behind");
    app.db.drop_db().await;
}

#[tokio::test]
async fn pages_carry_safe_headers_and_speak_french() {
    let Some(app) = app().await else { return };
    let uri = format!(
        "/oauth/authorize?response_type=code&client_id=raye-desktop&redirect_uri={}&state=state-0123456789abcdef&code_challenge={}&code_challenge_method=S256&screen=signup",
        enc(REDIRECT),
        pkce::challenge(&pkce::new_verifier())
    );
    let req = Request::get(&uri).header(header::ACCEPT_LANGUAGE, "fr-CA,fr;q=0.9").body(Body::empty()).unwrap();
    let (s, h, body) = app.call(req).await;
    assert_eq!(s, StatusCode::OK);
    let body = String::from_utf8(body).unwrap();
    assert!(body.contains("Créer votre compte Raye"));
    assert!(!body.contains("<script"));
    let csp = h[header::CONTENT_SECURITY_POLICY].to_str().unwrap();
    assert!(csp.contains("frame-ancestors 'none'") && csp.contains("default-src 'none'"));
    assert_eq!(h[header::X_FRAME_OPTIONS], "DENY");
    assert_eq!(h[header::CACHE_CONTROL], "no-store");
    app.db.drop_db().await;
}
