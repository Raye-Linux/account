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
use raye_account_common::api::Device;

type Row = (Uuid, String, String, String, OffsetDateTime, OffsetDateTime, i64);

pub async fn list(State(app): State<Shared>, auth: AuthDevice) -> Result<Json<Vec<Device>>> {
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT d.id, d.name, d.model, d.raye_version, d.created_at, d.last_seen_at,
                (SELECT count(*) FROM device_installs i WHERE i.device_id = d.id)
         FROM devices d WHERE d.account_id = $1 ORDER BY d.last_seen_at DESC",
    )
    .bind(auth.account_id)
    .fetch_all(&app.db)
    .await?;
    Ok(Json(
        rows.into_iter()
            .map(|r| Device {
                id: r.0,
                name: r.1,
                model: r.2,
                raye_version: r.3,
                created_at: rfc3339(r.4),
                last_seen_at: rfc3339(r.5),
                this_device: r.0 == auth.device_id,
                app_count: r.6,
            })
            .collect(),
    ))
}

#[derive(Deserialize)]
pub struct PatchDevice {
    name: Option<String>,
    raye_version: Option<String>,
}

fn clean(s: Option<String>, max: usize) -> Result<Option<String>> {
    match s.map(|s| s.trim().to_owned()) {
        None => Ok(None),
        Some(s) if !s.is_empty() && s.chars().count() <= max && !s.chars().any(char::is_control) => Ok(Some(s)),
        Some(_) => Err(Error::BadRequest("text too long or empty")),
    }
}

/// The PC renames itself or reports a new Raye version.
pub async fn patch_current(
    State(app): State<Shared>,
    auth: AuthDevice,
    Json(p): Json<PatchDevice>,
) -> Result<StatusCode> {
    let name = clean(p.name, 64)?;
    let version = clean(p.raye_version, 32)?;
    sqlx::query(
        "UPDATE devices SET name = coalesce($2, name), raye_version = coalesce($3, raye_version),
                last_seen_at = now() WHERE id = $1",
    )
    .bind(auth.device_id)
    .bind(name)
    .bind(version)
    .execute(&app.db)
    .await?;
    Ok(StatusCode::NO_CONTENT)
}

/// Removing a device signs it out: its tokens go with it.
pub async fn remove(State(app): State<Shared>, auth: AuthDevice, Path(id): Path<Uuid>) -> Result<StatusCode> {
    let done = sqlx::query("DELETE FROM devices WHERE id = $1 AND account_id = $2")
        .bind(id)
        .bind(auth.account_id)
        .execute(&app.db)
        .await?;
    if done.rows_affected() == 0 {
        return Err(Error::NotFound);
    }
    Ok(StatusCode::NO_CONTENT)
}
