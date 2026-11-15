//! Settings sync. Each key has a revision handed out by the server and the
//! time the change was made on the device. A device sends the revision it
//! last saw with each change: if nobody wrote the key since, the change is
//! taken; if somebody did, the newer change (by device time) wins and the
//! loser is told which value to apply. One account row lock per push keeps
//! revisions in order.

use std::collections::HashSet;

use axum::extract::{Query, State};
use axum::Json;
use serde::Deserialize;
use serde_json::Value;
use time::OffsetDateTime;
use uuid::Uuid;

use crate::error::{Error, Result};
use crate::time_fmt::{parse, rfc3339};
use crate::tokens::AuthDevice;
use crate::Shared;
use raye_account_common::api::{PushOutcome, PushResponse, PushResult, SettingItem, SettingsPage, SettingsPush};
use raye_account_common::keys;

const MAX_CHANGES: usize = 64;

#[derive(Deserialize)]
pub struct Since {
    #[serde(default)]
    since: i64,
}

type Row = (String, Option<Value>, i64, OffsetDateTime, Option<Uuid>);

fn item(r: Row) -> SettingItem {
    SettingItem { key: r.0, value: r.1, rev: r.2, modified_at: rfc3339(r.3), device_id: r.4 }
}

pub async fn pull(State(app): State<Shared>, auth: AuthDevice, Query(q): Query<Since>) -> Result<Json<SettingsPage>> {
    let mut tx = app.db.begin().await?;
    let (rev,): (i64,) = sqlx::query_as("SELECT settings_rev FROM accounts WHERE id = $1")
        .bind(auth.account_id)
        .fetch_one(&mut *tx)
        .await?;
    let rows: Vec<Row> = sqlx::query_as(
        "SELECT key, value, rev, modified_at, device_id FROM settings
         WHERE account_id = $1 AND rev > $2 ORDER BY rev",
    )
    .bind(auth.account_id)
    .bind(q.since)
    .fetch_all(&mut *tx)
    .await?;
    tx.commit().await?;
    Ok(Json(SettingsPage { rev, items: rows.into_iter().map(item).collect() }))
}

/// Decides one change against what is stored. Returns true when the change wins.
pub fn change_wins(stored: Option<(i64, OffsetDateTime)>, base_rev: i64, modified_at: OffsetDateTime) -> bool {
    match stored {
        None => true,
        Some((rev, _)) if rev <= base_rev => true,
        // Someone else wrote since this device last looked: newer wins,
        // and on a tie the value already stored stays.
        Some((_, stored_at)) => modified_at > stored_at,
    }
}

pub async fn push(State(app): State<Shared>, auth: AuthDevice, Json(p): Json<SettingsPush>) -> Result<Json<PushResponse>> {
    if p.changes.len() > MAX_CHANGES {
        return Err(Error::BadRequest("too many changes at once"));
    }
    let mut seen = HashSet::new();
    let now = OffsetDateTime::now_utc();
    let mut checked = Vec::with_capacity(p.changes.len());
    for c in p.changes {
        if !seen.insert(c.key.clone()) {
            return Err(Error::BadRequest("a key appears twice"));
        }
        keys::validate(&c.key, c.value.as_ref()).map_err(Error::BadRequest)?;
        let at = parse(&c.modified_at).ok_or(Error::BadRequest("modified_at is not RFC 3339"))?;
        // A clock running ahead must not let a device win every conflict forever.
        checked.push((c.key, c.value, c.base_rev, at.min(now)));
    }

    let mut tx = app.db.begin().await?;
    let (mut rev,): (i64,) = sqlx::query_as("SELECT settings_rev FROM accounts WHERE id = $1 FOR UPDATE")
        .bind(auth.account_id)
        .fetch_one(&mut *tx)
        .await?;
    let mut results = Vec::with_capacity(checked.len());
    for (key, value, base_rev, at) in checked {
        let stored: Option<Row> = sqlx::query_as(
            "SELECT key, value, rev, modified_at, device_id FROM settings WHERE account_id = $1 AND key = $2",
        )
        .bind(auth.account_id)
        .bind(&key)
        .fetch_optional(&mut *tx)
        .await?;
        let wins = change_wins(stored.as_ref().map(|s| (s.2, s.3)), base_rev, at);
        if !wins {
            results.push(PushResult { key, outcome: PushOutcome::Superseded, item: item(stored.unwrap()) });
            continue;
        }
        if let Some(s) = stored.as_ref().filter(|s| s.1 == value) {
            // Same value: nothing to tell the other devices.
            results.push(PushResult { key, outcome: PushOutcome::Accepted, item: item(s.clone()) });
            continue;
        }
        rev += 1;
        sqlx::query(
            "INSERT INTO settings (account_id, key, value, rev, modified_at, device_id)
             VALUES ($1, $2, $3, $4, $5, $6)
             ON CONFLICT (account_id, key) DO UPDATE
             SET value = EXCLUDED.value, rev = EXCLUDED.rev, modified_at = EXCLUDED.modified_at,
                 device_id = EXCLUDED.device_id",
        )
        .bind(auth.account_id)
        .bind(&key)
        .bind(&value)
        .bind(rev)
        .bind(at)
        .bind(auth.device_id)
        .execute(&mut *tx)
        .await?;
        results.push(PushResult {
            key: key.clone(),
            outcome: PushOutcome::Accepted,
            item: item((key, value, rev, at, Some(auth.device_id))),
        });
    }
    sqlx::query("UPDATE accounts SET settings_rev = $2 WHERE id = $1")
        .bind(auth.account_id)
        .bind(rev)
        .execute(&mut *tx)
        .await?;
    tx.commit().await?;
    Ok(Json(PushResponse { rev, results }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use time::macros::datetime;

    #[test]
    fn conflict_rules() {
        let t1 = datetime!(2026-11-01 10:00 UTC);
        let t2 = datetime!(2026-11-01 10:05 UTC);
        assert!(change_wins(None, 0, t1), "new key");
        assert!(change_wins(Some((4, t2)), 4, t1), "nobody wrote since: taken even if older");
        assert!(change_wins(Some((5, t1)), 4, t2), "concurrent, newer wins");
        assert!(!change_wins(Some((5, t2)), 4, t1), "concurrent, older loses");
        assert!(!change_wins(Some((5, t1)), 4, t1), "tie keeps the stored value");
    }
}
