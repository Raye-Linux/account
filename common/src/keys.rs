//! The settings that may sync. The server stores nothing outside this list,
//! so an old or modified client cannot use the account as free storage, and
//! the privacy section of the design can say exactly what is kept.
//!
//! Adding a key: add it here (the server and the client both read this
//! table), give the client an adapter that reads and writes it locally,
//! and add the key to the design doc.

use serde_json::Value;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Category {
    /// Theme, colours, accent, wallpaper.
    Personalization,
    /// Taskbar pins and layout, Start pins.
    Taskbar,
    /// Language, formats, keyboard layouts.
    Language,
    Accessibility,
    /// Sound, notifications, power, privacy, default apps, multitasking,
    /// mouse and keyboard, and the rest of what Settings remembers.
    System,
}

impl Category {
    pub const ALL: [Category; 5] = [
        Category::Personalization,
        Category::Taskbar,
        Category::Language,
        Category::Accessibility,
        Category::System,
    ];

    pub fn id(self) -> &'static str {
        match self {
            Category::Personalization => "personalization",
            Category::Taskbar => "taskbar",
            Category::Language => "language",
            Category::Accessibility => "accessibility",
            Category::System => "system",
        }
    }

    pub fn from_id(id: &str) -> Option<Category> {
        Category::ALL.into_iter().find(|c| c.id() == id)
    }
}

#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Kind {
    /// A short string from a fixed alphabet (ids, locale names).
    Ident,
    /// "#rrggbb" or "auto".
    Color,
    /// A list of identifiers, at most `max` long.
    IdentList { max: usize },
    /// A number between `min` and `max`.
    Number { min: f64, max: f64 },
    Bool,
}

pub struct KeySpec {
    pub key: &'static str,
    pub category: Category,
    pub kind: Kind,
}

pub const KEYS: &[KeySpec] = &[
    KeySpec { key: "appearance.colorScheme", category: Category::Personalization, kind: Kind::Ident },
    KeySpec { key: "appearance.accentColor", category: Category::Personalization, kind: Kind::Color },
    KeySpec { key: "appearance.wallpaper", category: Category::Personalization, kind: Kind::Ident },
    KeySpec { key: "taskbar.pins", category: Category::Taskbar, kind: Kind::IdentList { max: 40 } },
    KeySpec { key: "taskbar.alignment", category: Category::Taskbar, kind: Kind::Ident },
    KeySpec { key: "start.pins", category: Category::Taskbar, kind: Kind::IdentList { max: 60 } },
    KeySpec { key: "region.language", category: Category::Language, kind: Kind::IdentList { max: 8 } },
    KeySpec { key: "region.formats", category: Category::Language, kind: Kind::Ident },
    KeySpec { key: "input.keyboardLayouts", category: Category::Language, kind: Kind::IdentList { max: 8 } },
    KeySpec { key: "accessibility.animationSpeed", category: Category::Accessibility, kind: Kind::Number { min: 0.0, max: 4.0 } },
    KeySpec { key: "accessibility.cursorSize", category: Category::Accessibility, kind: Kind::Number { min: 16.0, max: 96.0 } },
    KeySpec { key: "accessibility.stickyKeys", category: Category::Accessibility, kind: Kind::Bool },
];

pub fn spec(key: &str) -> Option<&'static KeySpec> {
    KEYS.iter().find(|s| s.key == key)
}

const IDENT_MAX: usize = 96;

fn ident_ok(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= IDENT_MAX
        && !s.starts_with('.')
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || b"-_.@:+ ".contains(&b))
}

fn color_ok(s: &str) -> bool {
    s == "auto" || (s.len() == 7 && s.starts_with('#') && s[1..].bytes().all(|b| b.is_ascii_hexdigit()))
}

/// The category a key belongs to, whether it has its own adapter or is a
/// plain config entry from the table.
pub fn category_of(key: &str) -> Option<Category> {
    spec(key).map(|s| s.category).or_else(|| crate::table::entry(key).map(|e| e.category))
}

/// Every key that may sync: the ones with their own adapter, then the table.
pub fn all_keys() -> Vec<String> {
    KEYS.iter()
        .map(|k| k.key.to_owned())
        .chain(crate::table::TABLE.synced.iter().map(|e| e.id()))
        .collect()
}

/// Checks a value against the table. `None` (a deleted value) is always fine.
pub fn validate(key: &str, value: Option<&Value>) -> Result<(), &'static str> {
    if let Some(e) = crate::table::entry(key) {
        return match value {
            None => Ok(()),
            Some(v) if e.check(v) => Ok(()),
            Some(_) => Err("value does not fit this setting"),
        };
    }
    let spec = spec(key).ok_or("unknown setting")?;
    let Some(value) = value else { return Ok(()) };
    let ok = match spec.kind {
        Kind::Ident => value.as_str().is_some_and(ident_ok),
        Kind::Color => value.as_str().is_some_and(color_ok),
        Kind::IdentList { max } => value
            .as_array()
            .is_some_and(|a| a.len() <= max && a.iter().all(|v| v.as_str().is_some_and(ident_ok))),
        Kind::Number { min, max } => value.as_f64().is_some_and(|n| n.is_finite() && n >= min && n <= max),
        Kind::Bool => value.is_boolean(),
    };
    if ok {
        Ok(())
    } else {
        Err("value does not fit this setting")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn keys_are_unique() {
        for (i, a) in KEYS.iter().enumerate() {
            assert!(KEYS[i + 1..].iter().all(|b| b.key != a.key), "{} twice", a.key);
        }
    }

    #[test]
    fn checks_values() {
        assert!(validate("appearance.accentColor", Some(&json!("#7b3cff"))).is_ok());
        assert!(validate("appearance.accentColor", Some(&json!("auto"))).is_ok());
        assert!(validate("appearance.accentColor", Some(&json!("red"))).is_err());
        assert!(validate("appearance.colorScheme", Some(&json!("RayeNight"))).is_ok());
        assert!(validate("appearance.colorScheme", Some(&json!("x\n[General]"))).is_err());
        assert!(validate("appearance.wallpaper", Some(&json!(".."))).is_err());
        assert!(validate("region.language", Some(&json!(["fr_CA", "en_US"]))).is_ok());
        assert!(validate("region.language", Some(&json!(vec!["a"; 9]))).is_err());
        assert!(validate("accessibility.cursorSize", Some(&json!(24))).is_ok());
        assert!(validate("accessibility.cursorSize", Some(&json!(1000))).is_err());
        assert!(validate("accessibility.stickyKeys", Some(&json!("yes"))).is_err());
        assert!(validate("nope", Some(&json!(1))).is_err());
        assert!(validate("taskbar.pins", None).is_ok());
    }

    #[test]
    fn categories_round_trip() {
        for c in Category::ALL {
            assert_eq!(Category::from_id(c.id()), Some(c));
        }
    }
}
