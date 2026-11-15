//! The Store library: apps tied to the account, and which device has which
//! installed, so the Store can show "Your devices" and offer to install an
//! app from another PC.

use std::collections::HashSet;

use axum::extract::{Path, State};
use axum::http::StatusCode;
use axum::Json;
use serde::Deserialize;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::time_fmt::rfc3339;
use crate::tokens::AuthDevice;
use crate::Shared;
use raye_account_common::api::{InstalledApp, InstalledApps, LibraryApp};

const MAX_INSTALLS: usize = 2000;
const SOURCES: &[&str] = &["flathub", "raye", "deb"];

/// Flatpak ids and package names: letters, digits, dots, dashes, underscores, plus.
pub fn app_id_ok(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 255
        && id.bytes().all(|b| b.is_ascii_alphanumeric() || b".-_+".contains(&b))
        && !id.starts_with('.')
}

fn check(app: &InstalledApp) -> Result<()> {
    if !app_id_ok(&app.app_id) {
        return Err(Error::BadRequest("app_id"));
    }
    if !SOURCES.contains(&app.source.as_str()) {
        return Err(Error::BadRequest("source: flathub, raye or deb"));
    }
    Ok(())
}

pub async fn library(State(app): State<Shared>, auth: AuthDevice) -> Result<Json<Vec<LibraryApp>>> {
    let rows: Vec<(String, String, OffsetDateTime, Vec<Uuid>)> = sqlx::query_as(
        "SELECT l.app_id, l.source, l.added_at,
                coalesce(array_agg(i.device_id) FILTER (WHERE i.device_id IS NOT NULL), '{}')
         FROM store_library l
         LEFT JOIN devices d ON d.account_id = l.account_id
         LEFT JOIN device_installs i ON i.device_id = d.id AND i.app_id = l.app_id
         WHERE l.account_id = $1
         GROUP BY l.app_id, l.source, l.added_at
         ORDER BY l.added_at DESC",
    )
    .bind(auth.account_id)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| LibraryApp { app_id: r.0, source: r.1, added_at: rfc3339(r.2), installed_on: r.3 })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct AddBody {
    source: String,
}

pub async fn add_to_library(
    State(app): State<Shared>,
    auth: AuthDevice,
    Path(app_id): Path<String>,
    Json(b): Json<AddBody>,
) -> Result<StatusCode> {
    check(&InstalledApp { app_id: app_id.clone(), source: b.source.clone() })?;
    sqlx::query(
        "INSERT INTO store_library (account_id, app_id, source) VALUES ($1, $2, $3)
         ON CONFLICT (account_id, app_id) DO NOTHING",
    )
    .bind(auth.account_id)
    .bind(app_id)
    .bind(b.source)
    .execute(&app.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn remove_from_library(
    State(app): State<Shared>,
    auth: AuthDevice,
    Path(app_id): Path<String>,
) -> Result<StatusCode> {
    sqlx::query("DELETE FROM store_library WHERE account_id = $1 AND app_id = $2")
        .bind(auth.account_id)
        .bind(app_id)
        .execute(&app.db)
        .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// This device's whole list of installed apps, sent when it changes. Every
/// installed app also joins the library, the way installing from a store
/// adds it to "your apps".
pub async fn put_installs(
    State(app): State<Shared>,
    auth: AuthDevice,
    Json(body): Json<InstalledApps>,
) -> Result<StatusCode> {
    if body.apps.len() > MAX_INSTALLS {
        return Err(Error::BadRequest("too many apps"));
    }
    let mut seen = HashSet::new();
    for a in &body.apps {
        check(a)?;
        if !seen.insert(a.app_id.as_str()) {
            return Err(Error::BadRequest("an app appears twice"));
        }
    }
    let ids: Vec<&str> = body.apps.iter().map(|a| a.app_id.as_str()).collect();
    let sources: Vec<&str> = body.apps.iter().map(|a| a.source.as_str()).collect();
    let mut tx = app.db.begin().await?;
    sqlx::query("DELETE FROM device_installs WHERE device_id = $1")
        .bind(auth.device_id)
        .execute(&mut *tx)
        .await?;
    sqlx::query("INSERT INTO device_installs (device_id, app_id) SELECT $1, unnest($2::text[])")
        .bind(auth.device_id)
        .bind(&ids)
        .execute(&mut *tx)
        .await?;
    sqlx::query(
        "INSERT INTO store_library (account_id, app_id, source)
         SELECT $1, a, s FROM unnest($2::text[], $3::text[]) AS t(a, s)
         ON CONFLICT (account_id, app_id) DO NOTHING",
    )
    .bind(auth.account_id)
    .bind(&ids)
    .bind(&sources)
    .execute(&mut *tx)
    .await?;
    sqlx::query("UPDATE devices SET last_seen_at = now() WHERE id = $1")
        .bind(auth.device_id)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(StatusCode::NO_CONTENT)
}

pub async fn device_installs(
    State(app): State<Shared>,
    auth: AuthDevice,
    Path(id): Path<Uuid>,
) -> Result<Json<InstalledApps>> {
    let owned: Option<(Uuid,)> = sqlx::query_as("SELECT id FROM devices WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(auth.account_id)
        .fetch_optional(&app.db)
        .await?;
    if owned.is_none() {
        return Err(Error::NotFound);
    }
    let rows: Vec<(String, String)> = sqlx::query_as(
        "SELECT i.app_id, coalesce(l.source, 'flathub') FROM device_installs i
         LEFT JOIN store_library l ON l.account_id = $2 AND l.app_id = i.app_id
         WHERE i.device_id = $1 ORDER BY i.app_id",
    )
    .bind(id)
    .bind(auth.account_id)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(InstalledApps {
        apps: rows.into_iter().map(|(app_id, source)| InstalledApp { app_id, source }).collect(),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn app_ids() {
        assert!(app_id_ok("org.mozilla.firefox"));
        assert!(app_id_ok("libreoffice-writer"));
        assert!(!app_id_ok("../etc/passwd"));
        assert!(!app_id_ok(".hidden"));
        assert!(!app_id_ok("a b"));
        assert!(!app_id_ok(""));
    }
}
