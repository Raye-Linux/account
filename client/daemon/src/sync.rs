//! One sync: pull what other devices changed, apply it unless this PC
//! changed the same thing since the last sync, then push this PC's
//! changes. The server settles real conflicts (newer change wins).
//!
//! The first sync after signing in looks at what the account already has
//! (first_sync): an empty account gets this PC's settings, and when both
//! sides differ the person picks which to keep before anything changes.

use std::path::{Path, PathBuf};
use std::time::SystemTime;

use raye_account_common::api::{InstalledApp, PushOutcome, PushResponse, SettingChange, SettingItem, SettingsPage};
use raye_account_common::keys;
use raye_account_common::table;
use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::api::{ApiError, Client};
use crate::local::Local;
use crate::state::{State, Synced};

pub fn hash(v: Option<&Value>) -> String {
    match v {
        None => "-".into(),
        Some(v) => raye_account_common::hex(&Sha256::digest(v.to_string().as_bytes())[..16]),
    }
}

fn enabled(state: &State, key: &str) -> bool {
    keys::category_of(key).is_some_and(|c| state.category_on(c.id())) && Local::supports(key)
}

#[derive(Debug, Default, PartialEq)]
pub struct Report {
    pub applied: Vec<String>,
    pub pushed: Vec<String>,
    pub superseded: Vec<String>,
    pub failed: Vec<(String, String)>,
}

/// Applies what the server sent. Pure apart from `local`: easy to test.
pub fn take_pulled(state: &mut State, local: &Local, page: &SettingsPage, report: &mut Report) {
    for item in &page.items {
        if !enabled(state, &item.key) {
            continue;
        }
        let local_hash = hash(local.read(&item.key).as_ref());
        let changed_here = state.keys.get(&item.key).is_some_and(|s| s.hash != local_hash);
        if changed_here {
            // Both sides changed: the push below lets the server decide.
            continue;
        }
        settle(state, local, item, local_hash, report);
    }
    state.settings_rev = state.settings_rev.max(page.rev);
}

fn settle(state: &mut State, local: &Local, item: &SettingItem, local_hash: String, report: &mut Report) {
    // The server checks values too; checking again here means a broken or
    // hostile server still cannot hand the config tools something odd.
    if let Err(e) = keys::validate(&item.key, item.value.as_ref()) {
        report.failed.push((item.key.clone(), e.to_owned()));
        return;
    }
    let server_hash = hash(item.value.as_ref());
    if server_hash != local_hash {
        if let Err(e) = local.apply(&item.key, item.value.as_ref()) {
            report.failed.push((item.key.clone(), e));
            return;
        }
        report.applied.push(item.key.clone());
    }
    state.keys.insert(item.key.clone(), Synced { rev: item.rev, hash: server_hash });
}

/// What the first sync after signing in has to do.
#[derive(Debug, PartialEq, Eq)]
pub enum FirstSync {
    /// The account has none of the settings this PC syncs: send this PC's.
    Empty,
    /// Everything the account has already matches this PC.
    Same,
    /// This many settings differ: ask which side to keep.
    Differs(usize),
}

pub fn first_sync(state: &State, local: &Local, page: &SettingsPage) -> FirstSync {
    let held: Vec<&SettingItem> =
        page.items.iter().filter(|i| i.value.is_some() && enabled(state, &i.key)).collect();
    if held.is_empty() {
        return FirstSync::Empty;
    }
    let differ = held
        .iter()
        .filter(|i| hash(i.value.as_ref()) != hash(local.read(&i.key).as_ref()))
        .count();
    if differ == 0 { FirstSync::Same } else { FirstSync::Differs(differ) }
}

/// "Keep this PC's settings": the account's values become the last agreed
/// ones, so the next push replaces every value this PC has differently
/// and removes the ones it doesn't have.
pub fn adopt_account_revs(state: &mut State, page: &SettingsPage) {
    for item in &page.items {
        if enabled(state, &item.key) {
            state.keys.insert(item.key.clone(), Synced { rev: item.rev, hash: hash(item.value.as_ref()) });
        }
    }
    state.settings_rev = state.settings_rev.max(page.rev);
}

pub fn changes_to_push(state: &State, local: &Local, modified: &dyn Fn(&str) -> String) -> Vec<SettingChange> {
    keys::all_keys()
        .into_iter()
        .filter(|k| enabled(state, k))
        .filter_map(|k| {
            let value = local.read(&k);
            let h = hash(value.as_ref());
            let synced = state.keys.get(&k);
            match synced {
                Some(s) if s.hash == h => None,
                None if value.is_none() => None,
                _ => Some(SettingChange {
                    base_rev: synced.map(|s| s.rev).unwrap_or(0),
                    modified_at: modified(&k),
                    key: k,
                    value,
                }),
            }
        })
        .collect()
}

pub fn take_push_result(state: &mut State, local: &Local, resp: &PushResponse, report: &mut Report) {
    for r in &resp.results {
        match r.outcome {
            PushOutcome::Accepted => {
                state.keys.insert(r.key.clone(), Synced { rev: r.item.rev, hash: hash(r.item.value.as_ref()) });
                report.pushed.push(r.key.clone());
            }
            PushOutcome::Superseded => {
                report.superseded.push(r.key.clone());
                settle(state, local, &r.item, String::new(), report);
            }
        }
    }
}

/// The config file a key lives in, for the time of the local change.
fn file_of(key: &str) -> &'static str {
    if let Some(e) = table::entry(key) {
        return e.file.as_str();
    }
    match key.split('.').next() {
        Some("region") => "plasma-localerc",
        Some("input") => "kxkbrc",
        Some("taskbar") | Some("start") => "plasma-org.kde.plasma.desktop-appletsrc",
        _ if key == "appearance.wallpaper" => "plasma-org.kde.plasma.desktop-appletsrc",
        _ if key == "accessibility.cursorSize" => "kcminputrc",
        _ if key == "accessibility.stickyKeys" => "kaccessrc",
        _ => "kdeglobals",
    }
}

fn rfc3339(t: SystemTime) -> String {
    use time::format_description::well_known::Rfc3339;
    time::OffsetDateTime::from(t).format(&Rfc3339).unwrap_or_default()
}

pub fn modified_at(config: &Path, key: &str) -> String {
    let t = std::fs::metadata(config.join(file_of(key)))
        .and_then(|m| m.modified())
        .unwrap_or_else(|_| SystemTime::now());
    rfc3339(t)
}

/// Flatpak apps installed for everyone and for this user. Reading the
/// directories is enough; no flatpak process is started.
pub fn installed_apps(dirs: &[PathBuf]) -> Vec<InstalledApp> {
    let mut ids: Vec<String> = dirs
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .filter_map(|e| e.ok())
        .filter(|e| e.path().join("current").exists())
        .filter_map(|e| e.file_name().into_string().ok())
        .collect();
    ids.sort();
    ids.dedup();
    ids.into_iter().map(|app_id| InstalledApp { app_id, source: "flathub".into() }).collect()
}

pub fn flatpak_dirs() -> Vec<PathBuf> {
    vec![PathBuf::from("/var/lib/flatpak/app"), crate::state::home().join(".local/share/flatpak/app")]
}

/// Settings and apps. Blocking: run it on a blocking thread.
pub fn settings_and_apps(state: &mut State, local: &Local, client: &mut Client) -> Result<Report, ApiError> {
    let mut report = Report::default();
    let page: SettingsPage = client.json("GET", &format!("/v1/settings?since={}", state.settings_rev), None)?;
    take_pulled(state, local, &page, &mut report);

    let config = local.config.clone();
    let changes = changes_to_push(state, local, &|k| modified_at(&config, k));
    for chunk in changes.chunks(32) {
        let resp: PushResponse = client.json("PUT", "/v1/settings", Some(&json!({ "changes": chunk })))?;
        take_push_result(state, local, &resp, &mut report);
    }

    if state.apps_sync {
        let apps = installed_apps(&flatpak_dirs());
        let h = hash(Some(&serde_json::to_value(&apps).unwrap_or_default()));
        if h != state.installs_hash {
            client.no_content("PUT", "/v1/devices/current/installs", Some(&json!({ "apps": apps })))?;
            state.installs_hash = h;
        }
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local::Exec;
    use std::cell::RefCell;

    /// Applies by writing the value into a fake kdeglobals, so reads follow.
    struct FakeKde {
        dir: PathBuf,
        calls: RefCell<Vec<String>>,
    }

    impl Exec for FakeKde {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.calls.borrow_mut().push(argv.join(" "));
            if argv[0] == "kwriteconfig6" && argv.contains(&"AccentColor".to_owned()) {
                let v = argv.last().unwrap();
                std::fs::write(self.dir.join("kdeglobals"), format!("[General]\nAccentColor={v}\n")).unwrap();
            }
            Ok(())
        }
    }

    fn fake(accent: Option<&str>) -> FakeKde {
        let dir = std::env::temp_dir().join(format!("raye-sync-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(&dir).unwrap();
        if let Some(a) = accent {
            std::fs::write(dir.join("kdeglobals"), format!("[General]\nAccentColor={a}\n")).unwrap();
        }
        FakeKde { dir, calls: RefCell::new(vec![]) }
    }

    fn item(key: &str, v: Value, rev: i64) -> SettingItem {
        SettingItem { key: key.into(), value: Some(v), rev, modified_at: "2026-11-01T10:00:00Z".into(), device_id: None }
    }

    #[test]
    fn first_sync_takes_the_account_values() {
        let kde = fake(Some("255,0,0"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        let page = SettingsPage { rev: 3, items: vec![item("appearance.accentColor", json!("#7b3cff"), 3)] };
        let mut r = Report::default();
        take_pulled(&mut state, &local, &page, &mut r);
        assert_eq!(r.applied, vec!["appearance.accentColor"]);
        assert_eq!(local.read("appearance.accentColor"), Some(json!("#7b3cff")));
        assert_eq!(state.settings_rev, 3);
        assert!(changes_to_push(&state, &local, &|_| "t".into()).is_empty(), "nothing left to push");
    }

    #[test]
    fn local_change_is_pushed_and_not_overwritten_by_pull() {
        let kde = fake(Some("123,60,255"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        state.keys.insert("appearance.accentColor".into(), Synced { rev: 3, hash: hash(Some(&json!("#ff0000"))) });
        // Another device changed it too (rev 4).
        let page = SettingsPage { rev: 4, items: vec![item("appearance.accentColor", json!("#00ff00"), 4)] };
        let mut r = Report::default();
        take_pulled(&mut state, &local, &page, &mut r);
        assert!(r.applied.is_empty(), "local change kept for the server to judge");
        let changes = changes_to_push(&state, &local, &|_| "2026-11-01T11:00:00Z".into());
        assert_eq!(changes.len(), 1);
        assert_eq!(changes[0].base_rev, 3);
        assert_eq!(changes[0].value, Some(json!("#7b3cff")));

        // The server says the other device's change was newer.
        let resp = PushResponse {
            rev: 4,
            results: vec![raye_account_common::api::PushResult {
                key: "appearance.accentColor".into(),
                outcome: PushOutcome::Superseded,
                item: item("appearance.accentColor", json!("#00ff00"), 4),
            }],
        };
        take_push_result(&mut state, &local, &resp, &mut r);
        assert_eq!(local.read("appearance.accentColor"), Some(json!("#00ff00")));
        assert_eq!(state.keys["appearance.accentColor"].rev, 4);
    }

    #[test]
    fn switched_off_categories_are_left_alone() {
        let kde = fake(Some("255,0,0"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        state.set_category("personalization", false);
        let page = SettingsPage { rev: 1, items: vec![item("appearance.accentColor", json!("#7b3cff"), 1)] };
        let mut r = Report::default();
        take_pulled(&mut state, &local, &page, &mut r);
        assert!(r.applied.is_empty());
        assert!(changes_to_push(&state, &local, &|_| "t".into()).is_empty());
        assert!(kde.calls.borrow().is_empty());
    }

    #[test]
    fn plain_entries_are_pushed_and_follow_their_category() {
        let kde = fake(None);
        std::fs::write(kde.dir.join("rayeshellrc"), "[Taskbar]\nAlignment=left\n[Sound]\nVolumeChime=false\n").unwrap();
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        let keys: Vec<String> = changes_to_push(&state, &local, &|_| "t".into()).into_iter().map(|c| c.key).collect();
        assert!(keys.contains(&"cfg:rayeshellrc:Taskbar:Alignment".to_owned()), "{keys:?}");
        assert!(keys.contains(&"cfg:rayeshellrc:Sound:VolumeChime".to_owned()), "{keys:?}");
        state.set_category("system", false);
        let keys: Vec<String> = changes_to_push(&state, &local, &|_| "t".into()).into_iter().map(|c| c.key).collect();
        assert!(!keys.iter().any(|k| k.contains("VolumeChime")), "system is off");
        assert!(keys.iter().any(|k| k.contains("Alignment")), "taskbar is still on");
    }

    #[test]
    fn values_from_the_server_are_checked_before_applying() {
        let kde = fake(Some("255,0,0"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        let page = SettingsPage {
            rev: 2,
            items: vec![
                item("appearance.wallpaper", json!("../../../etc"), 1),
                item("appearance.accentColor", json!("red; rm -rf"), 2),
            ],
        };
        let mut r = Report::default();
        take_pulled(&mut state, &local, &page, &mut r);
        assert_eq!(r.failed.len(), 2);
        assert!(kde.calls.borrow().is_empty());
    }

    #[test]
    fn going_back_to_default_is_sent_as_removal() {
        let kde = fake(None);
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        state.keys.insert("appearance.accentColor".into(), Synced { rev: 2, hash: hash(Some(&json!("#7b3cff"))) });
        let c = changes_to_push(&state, &local, &|_| "t".into());
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].value, None);
    }

    #[test]
    fn empty_account_takes_this_pc() {
        let kde = fake(Some("255,0,0"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let state = State::default();
        let page = SettingsPage { rev: 0, items: vec![] };
        assert_eq!(first_sync(&state, &local, &page), FirstSync::Empty);
        let removed = SettingItem { value: None, ..item("appearance.accentColor", json!(""), 2) };
        assert_eq!(first_sync(&state, &local, &SettingsPage { rev: 2, items: vec![removed] }), FirstSync::Empty);
    }

    #[test]
    fn account_with_other_values_asks() {
        let kde = fake(Some("255,0,0"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let state = State::default();
        let page = SettingsPage { rev: 3, items: vec![item("appearance.accentColor", json!("#7b3cff"), 3)] };
        assert_eq!(first_sync(&state, &local, &page), FirstSync::Differs(1));
        let same = SettingsPage { rev: 3, items: vec![item("appearance.accentColor", json!("#ff0000"), 3)] };
        assert_eq!(first_sync(&state, &local, &same), FirstSync::Same);
    }

    #[test]
    fn keeping_this_pc_overwrites_the_account() {
        let kde = fake(Some("255,0,0"));
        let local = Local { config: kde.dir.clone(), system_config: vec![], data_dirs: vec![], exec: &kde };
        let mut state = State::default();
        let page = SettingsPage {
            rev: 7,
            items: vec![
                item("appearance.accentColor", json!("#7b3cff"), 5),
                item("cfg:rayeshellrc:Taskbar:Alignment", json!("left"), 7),
            ],
        };
        adopt_account_revs(&mut state, &page);
        let mut r = Report::default();
        take_pulled(&mut state, &local, &SettingsPage { rev: 7, items: vec![] }, &mut r);
        assert!(r.applied.is_empty(), "nothing taken from the account");
        let mut changes = changes_to_push(&state, &local, &|_| "t".into());
        changes.sort_by(|a, b| a.key.cmp(&b.key));
        assert_eq!(changes.len(), 2, "{changes:?}");
        assert_eq!(changes[0].key, "appearance.accentColor");
        assert_eq!(changes[0].value, Some(json!("#ff0000")));
        assert_eq!(changes[0].base_rev, 5);
        assert_eq!(changes[1].value, None, "the PC has no taskbar alignment: removed from the account");
        assert_eq!(changes[1].base_rev, 7);
        assert!(kde.calls.borrow().is_empty());
    }

    #[test]
    fn lists_flatpak_apps_from_their_folders() {
        let d = std::env::temp_dir().join(format!("raye-flatpak-test-{}", uuid::Uuid::new_v4()));
        for id in ["org.mozilla.firefox", "com.discordapp.Discord"] {
            std::fs::create_dir_all(d.join("sys").join(id).join("current")).unwrap();
        }
        std::fs::create_dir_all(d.join("user/org.mozilla.firefox/current")).unwrap();
        std::fs::create_dir_all(d.join("user/half.installed")).unwrap();
        let apps = installed_apps(&[d.join("sys"), d.join("user"), d.join("missing")]);
        let ids: Vec<_> = apps.iter().map(|a| a.app_id.as_str()).collect();
        assert_eq!(ids, vec!["com.discordapp.Discord", "org.mozilla.firefox"]);
        let _ = std::fs::remove_dir_all(d);
    }
}
