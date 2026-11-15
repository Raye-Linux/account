//! Plain config entries that sync as they are: one KDE config key each,
//! copied from PC to PC. The list lives in `sync-table.json` next to this
//! crate, which also says what Raye Settings writes and is kept off the
//! account, and why. `tests/test_sync_table.py` fails when Settings starts
//! writing a key that is in neither list.
//!
//! The id of an entry is `cfg:<file>:<group>:<key>`, with nested groups
//! joined by '/'.

use std::collections::BTreeMap;
use std::sync::LazyLock;

use serde::Deserialize;
use serde_json::Value;

use crate::keys::Category;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum EntryKind {
    Bool,
    Int,
    Text,
}

#[derive(Debug, Deserialize)]
pub struct Entry {
    pub file: String,
    pub group: String,
    pub key: String,
    pub category: Category,
    #[serde(rename = "type")]
    pub kind: EntryKind,
    #[serde(default)]
    pub min: Option<i64>,
    #[serde(default)]
    pub max: Option<i64>,
    pub page: String,
}

#[derive(Debug, Deserialize)]
pub struct Excluded {
    pub file: String,
    pub group: String,
    pub key: String,
    pub why: String,
}

#[derive(Debug, Deserialize)]
pub struct Table {
    pub synced: Vec<Entry>,
    pub excluded: Vec<Excluded>,
    /// A write site in Settings ("backends/x.cpp:\"Key\"") and the entries
    /// ("file|group|key") it can write.
    pub sites: BTreeMap<String, Vec<String>>,
}

pub const PREFIX: &str = "cfg:";
const TEXT_MAX: usize = 200;

pub static TABLE: LazyLock<Table> =
    LazyLock::new(|| serde_json::from_str(include_str!("../sync-table.json")).expect("sync-table.json"));

impl Entry {
    pub fn id(&self) -> String {
        format!("{PREFIX}{}:{}:{}", self.file, self.group, self.key)
    }

    pub fn groups(&self) -> Vec<&str> {
        self.group.split('/').collect()
    }

    pub fn check(&self, v: &Value) -> bool {
        match self.kind {
            EntryKind::Bool => v.is_boolean(),
            EntryKind::Int => v.as_i64().is_some_and(|n| {
                self.min.is_none_or(|m| n >= m) && self.max.is_none_or(|m| n <= m)
            }),
            EntryKind::Text => v.as_str().is_some_and(text_ok),
        }
    }

    /// The JSON value for what the config file holds, or None when it does
    /// not fit (a hand edit, a newer format).
    pub fn from_config(&self, raw: &str) -> Option<Value> {
        let v = match self.kind {
            EntryKind::Bool => match raw {
                "true" => Value::Bool(true),
                "false" => Value::Bool(false),
                _ => return None,
            },
            EntryKind::Int => Value::from(raw.trim().parse::<i64>().ok()?),
            EntryKind::Text => Value::from(raw),
        };
        self.check(&v).then_some(v)
    }

    /// The text kwriteconfig6 is given, and its --type.
    pub fn to_config(&self, v: &Value) -> Option<(String, Option<&'static str>)> {
        if !self.check(v) {
            return None;
        }
        Some(match self.kind {
            EntryKind::Bool => (v.as_bool()?.to_string(), Some("bool")),
            EntryKind::Int => (v.as_i64()?.to_string(), None),
            EntryKind::Text => (v.as_str()?.to_owned(), None),
        })
    }
}

/// Theme names, font descriptions, ids and short lists. Nothing that KDE
/// could read as a command (leading '!'), an option, a path or a shell word.
fn text_ok(s: &str) -> bool {
    s.len() <= TEXT_MAX
        && !s.starts_with(['!', '-'])
        && !s.contains("..")
        && !s.chars().any(|c| c.is_control() || matches!(c, '/' | '\\' | '$' | '`'))
}

pub fn entry(id: &str) -> Option<&'static Entry> {
    let rest = id.strip_prefix(PREFIX)?;
    TABLE.synced.iter().find(|e| {
        let (f, g, k) = (&e.file, &e.group, &e.key);
        rest.len() == f.len() + g.len() + k.len() + 2 && rest == format!("{f}:{g}:{k}")
    })
}

/// The config files the entries live in, sorted, each once.
pub fn files() -> Vec<&'static str> {
    let mut v: Vec<&str> = TABLE.synced.iter().map(|e| e.file.as_str()).collect();
    v.sort();
    v.dedup();
    v
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::collections::HashSet;

    fn triple(file: &str, group: &str, key: &str) -> String {
        format!("{file}|{group}|{key}")
    }

    #[test]
    fn the_table_loads_and_has_no_duplicates() {
        let mut seen = HashSet::new();
        for e in &TABLE.synced {
            assert!(seen.insert(triple(&e.file, &e.group, &e.key)), "{} twice", e.id());
            assert!(!e.page.is_empty(), "{} names no page", e.id());
        }
        for x in &TABLE.excluded {
            assert!(seen.insert(triple(&x.file, &x.group, &x.key)), "{}|{}|{} synced and excluded, or excluded twice", x.file, x.group, x.key);
            assert!(x.why.len() > 10, "{}: say why it stays on this PC", x.key);
        }
    }

    #[test]
    fn every_site_writes_only_known_entries() {
        let known: HashSet<String> = TABLE
            .synced
            .iter()
            .map(|e| triple(&e.file, &e.group, &e.key))
            .chain(TABLE.excluded.iter().map(|x| triple(&x.file, &x.group, &x.key)))
            .collect();
        for (site, writes) in &TABLE.sites {
            assert!(!writes.is_empty(), "{site} writes nothing?");
            for w in writes {
                assert!(known.contains(w), "{site} writes {w}, which is neither synced nor excluded");
            }
        }
    }

    #[test]
    fn ids_find_their_entry() {
        for e in &TABLE.synced {
            assert!(std::ptr::eq(entry(&e.id()).unwrap(), e));
            assert!(!e.file.contains(':') && !e.group.contains(':') && !e.key.contains(':'), "{}", e.id());
        }
        assert!(entry("cfg:nothing:here:at all").is_none());
        assert!(entry("appearance.wallpaper").is_none());
    }

    #[test]
    fn values_are_checked_both_ways() {
        let b = Entry { file: "f".into(), group: "G".into(), key: "K".into(), category: Category::System, kind: EntryKind::Bool, min: None, max: None, page: "p".into() };
        assert_eq!(b.from_config("true"), Some(json!(true)));
        assert_eq!(b.from_config("yes"), None);
        assert_eq!(b.to_config(&json!(false)), Some(("false".into(), Some("bool"))));
        assert_eq!(b.to_config(&json!("false")), None);
        let i = Entry { kind: EntryKind::Int, min: Some(0), max: Some(3600), ..b };
        assert_eq!(i.from_config("300"), Some(json!(300)));
        assert_eq!(i.from_config("9999"), None);
        assert!(!i.check(&json!(1.5)));
        let t = Entry { kind: EntryKind::Text, min: None, max: None, ..i };
        assert!(t.check(&json!("org.kde.konsole.desktop")));
        assert!(!t.check(&json!("a\nb")));
        assert!(!t.check(&json!("x".repeat(201))));
        // a text never reads as a command, an option or a path
        for bad in ["!curl x|sh", "-rf", "../../themes/x", "a/b", "a\\b", "$(id)", "`id`"] {
            assert!(!t.check(&json!(bad)), "{bad}");
        }
        assert!(t.check(&json!("Inter,10,-1,5,400,0,0,0,0,0,0,0,0,0,0,1")));
    }
}
