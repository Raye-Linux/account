use std::io::Cursor;

use axum::body::Bytes;
use axum::extract::State;
use axum::http::{header, HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use base64::engine::general_purpose::STANDARD;
use base64::Engine;
use image::{imageops::FilterType, ImageFormat, ImageReader, Limits};
use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::oauth::{check_password, display_name_ok};
use crate::time_fmt::rfc3339;
use crate::tokens::AuthDevice;
use crate::Shared;
use raye_account_common::api::Me;

/// Every picture is stored at this size, whatever was sent.
pub const AVATAR_SIZE: u32 = 256;
const MAX_SOURCE_SIDE: u32 = 4096;

pub async fn get_me(State(app): State<Shared>, auth: AuthDevice) -> Result<Json<Me>> {
    let (id, email, verified, totp, email_code, name, etag, created): (
        Uuid,
        String,
        bool,
        bool,
        bool,
        String,
        Option<String>,
        OffsetDateTime,
    ) = sqlx::query_as(
        "SELECT id, email, email_verified, totp_enabled, email_code_signin, display_name, avatar_etag, created_at
             FROM accounts WHERE id = $1",
    )
    .bind(auth.account_id)
    .fetch_optional(&app.db)
    .await?
    .ok_or(Error::Unauthorized)?;
    Ok(Json(Me {
        id,
        email,
        email_verified: verified,
        totp_enabled: totp,
        email_code_signin: email_code,
        display_name: name,
        avatar_etag: etag,
        created_at: rfc3339(created),
    }))
}

#[derive(Deserialize)]
pub struct PatchMe {
    display_name: String,
}

pub async fn patch_me(State(app): State<Shared>, auth: AuthDevice, Json(p): Json<PatchMe>) -> Result<Json<Me>> {
    if !display_name_ok(&p.display_name) {
        return Err(Error::BadRequest("display_name: 1 to 64 characters"));
    }
    sqlx::query("UPDATE accounts SET display_name = $2, updated_at = now() WHERE id = $1")
        .bind(auth.account_id)
        .bind(p.display_name.trim())
        .execute(&app.db)
        .await?;
    get_me(State(app), auth).await
}

/// Decodes PNG, JPEG or WebP, crops to the centre square and writes a new
/// 256 px PNG. Re-encoding drops whatever else the file carried (EXIF with a
/// location, comments, extra chunks) and anything crafted for a decoder
/// stays on the server.
pub fn reencode(bytes: &[u8]) -> std::result::Result<Vec<u8>, Error> {
    let format = match image::guess_format(bytes) {
        Ok(f @ (ImageFormat::Png | ImageFormat::Jpeg | ImageFormat::WebP)) => f,
        _ => return Err(Error::Unsupported("use a PNG, JPEG or WebP picture")),
    };
    let mut reader = ImageReader::with_format(Cursor::new(bytes), format);
    let mut limits = Limits::default();
    limits.max_image_width = Some(MAX_SOURCE_SIDE);
    limits.max_image_height = Some(MAX_SOURCE_SIDE);
    limits.max_alloc = Some(96 * 1024 * 1024);
    reader.limits(limits);
    let img = reader.decode().map_err(|_| Error::BadRequest("this picture can't be read"))?;
    let side = img.width().min(img.height());
    if side < 32 {
        return Err(Error::BadRequest("this picture is too small"));
    }
    let square = img.crop_imm((img.width() - side) / 2, (img.height() - side) / 2, side, side);
    let out = square.resize_exact(AVATAR_SIZE, AVATAR_SIZE, FilterType::Lanczos3).to_rgba8();
    let mut png = Vec::new();
    out.write_to(&mut Cursor::new(&mut png), ImageFormat::Png)
        .map_err(|e| Error::Internal(e.to_string()))?;
    Ok(png)
}

pub async fn put_avatar(State(app): State<Shared>, auth: AuthDevice, body: Bytes) -> Result<Json<Me>> {
    if body.len() > crate::AVATAR_UPLOAD_LIMIT {
        return Err(Error::TooLarge);
    }
    let png = {
        let _permit = app.heavy.acquire().await.map_err(|e| Error::Internal(e.to_string()))?;
        tokio::task::spawn_blocking(move || reencode(&body))
            .await
            .map_err(|e| Error::Internal(e.to_string()))??
    };
    let etag = raye_account_common::hex(&Sha256::digest(&png)[..12]);
    sqlx::query("UPDATE accounts SET avatar_png = $2, avatar_etag = $3, updated_at = now() WHERE id = $1")
        .bind(auth.account_id)
        .bind(png)
        .bind(etag)
        .execute(&app.db)
        .await?;
    get_me(State(app), auth).await
}

pub async fn get_avatar(State(app): State<Shared>, auth: AuthDevice, headers: HeaderMap) -> Result<Response> {
    let row: Option<(Option<Vec<u8>>, Option<String>)> =
        sqlx::query_as("SELECT avatar_png, avatar_etag FROM accounts WHERE id = $1")
            .bind(auth.account_id)
            .fetch_optional(&app.db)
            .await?;
    let Some((Some(png), Some(etag))) = row else {
        return Err(Error::NotFound);
    };
    let quoted = format!("\"{etag}\"");
    if headers.get(header::IF_NONE_MATCH).and_then(|v| v.to_str().ok()) == Some(quoted.as_str()) {
        return Ok((StatusCode::NOT_MODIFIED, [(header::ETAG, quoted)]).into_response());
    }
    Ok(([(header::CONTENT_TYPE, "image/png".to_owned()), (header::ETAG, quoted)], png).into_response())
}

pub async fn delete_avatar(State(app): State<Shared>, auth: AuthDevice) -> Result<StatusCode> {
    sqlx::query("UPDATE accounts SET avatar_png = NULL, avatar_etag = NULL, updated_at = now() WHERE id = $1")
        .bind(auth.account_id)
        .execute(&app.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Everything the account holds, in one JSON file.
pub async fn export(State(app): State<Shared>, auth: AuthDevice) -> Result<Response> {
    let me = get_me(State(app.clone()), auth).await?.0;
    let avatar: Option<(Option<Vec<u8>>,)> = sqlx::query_as("SELECT avatar_png FROM accounts WHERE id = $1")
        .bind(auth.account_id)
        .fetch_optional(&app.db)
        .await?;
    let devices: Vec<(Uuid, String, String, String, OffsetDateTime, OffsetDateTime)> = sqlx::query_as(
        "SELECT id, name, model, raye_version, created_at, last_seen_at FROM devices WHERE account_id = $1 ORDER BY created_at",
    )
    .bind(auth.account_id)
    .fetch_all(&app.db)
    .await?;
    let settings: Vec<(String, Option<serde_json::Value>, OffsetDateTime)> = sqlx::query_as(
        "SELECT key, value, modified_at FROM settings WHERE account_id = $1 AND value IS NOT NULL ORDER BY key",
    )
    .bind(auth.account_id)
    .fetch_all(&app.db)
    .await?;
    let library: Vec<(String, String, OffsetDateTime)> = sqlx::query_as(
        "SELECT app_id, source, added_at FROM store_library WHERE account_id = $1 ORDER BY app_id",
    )
    .bind(auth.account_id)
    .fetch_all(&app.db)
    .await?;
    let body = json!({
        "exported_at": rfc3339(OffsetDateTime::now_utc()),
        "account": me,
        "picture_png_base64": avatar.and_then(|a| a.0).map(|p| STANDARD.encode(p)),
        "devices": devices.into_iter().map(|d| json!({
            "id": d.0, "name": d.1, "model": d.2, "raye_version": d.3,
            "created_at": rfc3339(d.4), "last_seen_at": rfc3339(d.5),
        })).collect::<Vec<_>>(),
        "settings": settings.into_iter().map(|s| json!({
            "key": s.0, "value": s.1, "modified_at": rfc3339(s.2),
        })).collect::<Vec<_>>(),
        "store_library": library.into_iter().map(|l| json!({
            "app_id": l.0, "source": l.1, "added_at": rfc3339(l.2),
        })).collect::<Vec<_>>(),
    });
    Ok((
        [(header::CONTENT_DISPOSITION, "attachment; filename=\"raye-account.json\"")],
        Json(body),
    )
        .into_response())
}

#[derive(Deserialize)]
pub struct DeleteAccount {
    password: String,
}

/// Deletes the account and everything under it (the foreign keys cascade).
/// Asks for the password again: an access token alone, stolen from a PC,
/// must not be enough to wipe someone's account.
pub async fn delete_account(
    State(app): State<Shared>,
    auth: AuthDevice,
    Json(d): Json<DeleteAccount>,
) -> Result<StatusCode> {
    let (stored,): (String,) = sqlx::query_as("SELECT password_hash FROM accounts WHERE id = $1")
        .bind(auth.account_id)
        .fetch_optional(&app.db)
        .await?
        .ok_or(Error::Unauthorized)?;
    if !app.limits.take("delete-account", &auth.account_id.to_string(), crate::ratelimit::SIGN_IN_ACCOUNT) {
        return Err(Error::TooMany);
    }
    if !check_password(&app, d.password, stored).await? {
        return Err(Error::Unauthorized);
    }
    sqlx::query("DELETE FROM accounts WHERE id = $1").bind(auth.account_id).execute(&app.db).await?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{Rgba, RgbaImage};

    fn png(w: u32, h: u32) -> Vec<u8> {
        let img = RgbaImage::from_pixel(w, h, Rgba([123, 60, 255, 255]));
        let mut out = Vec::new();
        img.write_to(&mut Cursor::new(&mut out), ImageFormat::Png).unwrap();
        out
    }

    #[test]
    fn crops_and_resizes() {
        let out = reencode(&png(640, 480)).unwrap();
        let back = image::load_from_memory(&out).unwrap();
        assert_eq!((back.width(), back.height()), (AVATAR_SIZE, AVATAR_SIZE));
    }

    #[test]
    fn refuses_other_formats_and_junk() {
        assert!(matches!(reencode(b"GIF89a....."), Err(Error::Unsupported(_))));
        assert!(matches!(reencode(b"<svg xmlns=\"http://www.w3.org/2000/svg\"/>"), Err(Error::Unsupported(_))));
        let mut broken = png(64, 64);
        broken.truncate(40);
        assert!(matches!(reencode(&broken), Err(Error::BadRequest(_))));
        assert!(matches!(reencode(&png(8, 8)), Err(Error::BadRequest(_))));
    }

    #[test]
    fn refuses_huge_dimensions() {
        assert!(reencode(&png(MAX_SOURCE_SIDE + 1, 40)).is_err());
    }
}
