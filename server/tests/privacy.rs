//! The privacy page, checked against the code it describes.
//!
//! `docs/privacy.md` tells people what a Raye account keeps. A page the code
//! contradicts is worse than no page at all, because it is believed and
//! nobody re-reads it. So every claim here that CAN be mechanically tied to
//! the schema or to the list of synced settings, is.
//!
//! None of this needs a database or a network: it reads the migrations, the
//! key table and the page itself.

use raye_account_common::keys::KEYS;

const PAGE: &str = include_str!("../../docs/privacy.md");
const M1: &str = include_str!("../migrations/0001_init.sql");
const M2: &str = include_str!("../migrations/0002_email_and_totp.sql");

fn tables() -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for sql in [M1, M2] {
        for line in sql.lines() {
            if let Some(rest) = line.trim().strip_prefix("CREATE TABLE ") {
                out.push(rest.trim_end_matches(" (").trim().to_owned());
            }
        }
    }
    out.sort();
    out
}

/// Column names of every CREATE TABLE and ADD COLUMN, across the migrations.
fn columns() -> Vec<String> {
    let mut out = Vec::new();
    for sql in [M1, M2] {
        let mut inside = false;
        for line in sql.lines() {
            let t = line.trim();
            if t.starts_with("CREATE TABLE ") {
                inside = true;
                continue;
            }
            if inside && t.starts_with(");") {
                inside = false;
                continue;
            }
            if let Some(rest) = t.strip_prefix("ADD COLUMN ") {
                if let Some(name) = rest.split_whitespace().next() {
                    out.push(name.to_owned());
                }
                continue;
            }
            if inside {
                let first = t.split_whitespace().next().unwrap_or("");
                if first.chars().all(|c| c.is_ascii_lowercase() || c == '_') && !first.is_empty() {
                    out.push(first.to_owned());
                }
            }
        }
    }
    out
}

fn number_word(n: usize) -> &'static str {
    ["zero", "one", "two", "three", "four", "five", "six", "seven", "eight", "nine", "ten", "eleven",
     "twelve", "thirteen", "fourteen", "fifteen", "sixteen", "seventeen", "eighteen", "nineteen", "twenty"][n]
}

#[test]
fn the_page_names_every_table_and_counts_them_right() {
    let tables = tables();
    for t in &tables {
        assert!(
            PAGE.contains(&format!("`{t}`")),
            "docs/privacy.md does not mention the `{t}` table. A table people are \
             not told about is the whole failure mode this test exists for."
        );
    }
    let said = format!("The {} tables", number_word(tables.len()));
    assert!(
        PAGE.contains(&said),
        "the page should say {said:?} (there are {} now: {})",
        tables.len(),
        tables.join(", ")
    );
}

#[test]
fn the_page_lists_exactly_the_settings_that_sync() {
    for spec in KEYS {
        assert!(
            PAGE.contains(&format!("`{}`", spec.key)),
            "docs/privacy.md does not list the synced setting `{}`. The page claims to \
             be an exact description of what is kept, so a missing key makes it a lie.",
            spec.key
        );
    }
    let entries = &raye_account_common::table::TABLE.synced;
    for e in entries {
        let row = format!("| `{}` | `{}` | `{}` |", e.file, e.group, e.key);
        assert!(PAGE.contains(&row), "docs/privacy.md does not list the synced entry {row}");
    }
    for x in &raye_account_common::table::TABLE.excluded {
        let row = format!("| `{}` | `{}` | `{}` |", x.file, x.group, x.key);
        assert!(PAGE.contains(&row), "docs/privacy.md does not list the entry kept on the PC {row}");
    }
    let said = format!("The {} settings that sync", KEYS.len() + entries.len());
    assert!(PAGE.contains(&said), "the page should say {said:?}");
}

/// The page says: "Not stored. ... no table has a column for an address."
#[test]
fn no_column_anywhere_holds_an_ip_address() {
    for c in columns() {
        let looks_like_an_address = c.contains("ip_")
            || c.ends_with("_ip")
            || c == "ip"
            || c.contains("addr")
            || c.contains("remote_");
        assert!(
            !looks_like_an_address,
            "column {c:?} looks like it holds a network address. \
             docs/privacy.md promises none exists; either the column or the page is wrong."
        );
    }
}

/// The page says the password is only ever an Argon2id hash.
#[test]
fn the_password_is_only_ever_a_hash() {
    let cols = columns();
    assert!(cols.iter().any(|c| c == "password_hash"), "no password_hash column");
    assert!(
        !cols.iter().any(|c| c == "password" || c == "passphrase"),
        "a column holds a password, not a hash of one: {cols:?}"
    );
    assert!(M1.contains("never as sent"), "the migration should say why these are hashes");
}

/// The page says every token, code and recovery code is stored as a SHA-256.
/// Each of those tables is therefore keyed by a hash, not by the secret.
#[test]
fn every_token_table_is_keyed_by_a_hash() {
    for table in ["access_tokens", "refresh_tokens", "oauth_codes", "email_tokens", "password_resets", "totp_recovery_codes"] {
        let sql = [M1, M2]
            .iter()
            .find_map(|s| {
                let at = s.find(&format!("CREATE TABLE {table} ("))?;
                let end = s[at..].find(");")? + at;
                Some(&s[at..end])
            })
            .unwrap_or_else(|| panic!("{table} is not in the migrations"));
        let keyed_by_hash = sql
            .lines()
            .any(|l| l.contains("PRIMARY KEY") && (l.contains("token_hash") || l.contains("code_hash")));
        assert!(keyed_by_hash, "{table} is not keyed by a hash of the secret:\n{sql}");
        assert!(
            !sql.contains(" token text") && !sql.contains(" code text"),
            "{table} appears to keep the secret itself:\n{sql}"
        );
    }
}

/// The page says the TOTP secret is sealed, never readable in the row.
#[test]
fn the_two_step_secret_is_a_sealed_blob() {
    assert!(M2.contains("totp_secret bytea"), "totp_secret should be bytes, not text");
    assert!(M2.contains("XChaCha20-Poly1305"), "the migration should name what seals it");
    assert!(PAGE.contains("XChaCha20-Poly1305"), "the page should name it too");
    // And the key must not live next to the data it protects.
    assert!(
        PAGE.contains("RAYE_ACCOUNT_TOTP_KEY"),
        "the page should say where the key is, since that is what makes a dump safe"
    );
}

/// Deleting the account has to actually empty everything: the page says every
/// row cascades away, and that is a property of the schema.
#[test]
fn every_table_cascades_from_the_account() {
    for table in tables() {
        if table == "accounts" {
            continue;
        }
        let sql = [M1, M2]
            .iter()
            .find_map(|s| {
                let at = s.find(&format!("CREATE TABLE {table} ("))?;
                let end = s[at..].find(");")? + at;
                Some(&s[at..end])
            })
            .unwrap();
        assert!(
            sql.contains("ON DELETE CASCADE"),
            "{table} does not cascade, so deleting an account would leave rows behind \
             while docs/privacy.md says every row goes at once:\n{sql}"
        );
    }
}
