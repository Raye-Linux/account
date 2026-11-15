//! Reading and applying the synced settings on this PC. Reads parse the KDE
//! config files directly (no process per key); applying goes through the
//! Plasma tools so running apps hear about the change.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;

use raye_account_common::table;
use serde_json::{json, Value};

/// A parsed KDE config file: (groups joined by '/', key) -> raw value.
#[derive(Default, Debug)]
pub struct KConfig {
    entries: HashMap<(String, String), String>,
}

impl KConfig {
    pub fn parse(text: &str) -> KConfig {
        let mut entries = HashMap::new();
        let mut group = String::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line.starts_with('[') && line.ends_with(']') {
                group = line[1..line.len() - 1].split("][").collect::<Vec<_>>().join("/");
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            // "Key[$e]" and localized "Key[fr]" variants: only the plain key matters here.
            let k = k.trim();
            if k.contains('[') {
                continue;
            }
            entries.insert((group.clone(), k.to_owned()), unescape(v.trim()));
        }
        KConfig { entries }
    }

    pub fn load(path: &Path) -> KConfig {
        std::fs::read_to_string(path).map(|t| KConfig::parse(&t)).unwrap_or_default()
    }

    pub fn get(&self, group: &str, key: &str) -> Option<&str> {
        self.entries.get(&(group.to_owned(), key.to_owned())).map(String::as_str)
    }

    pub fn groups_with(&self, key: &str) -> Vec<(&str, &str)> {
        let mut v: Vec<_> = self
            .entries
            .iter()
            .filter(|((_, k), _)| k == key)
            .map(|((g, _), val)| (g.as_str(), val.as_str()))
            .collect();
        v.sort();
        v
    }
}

fn unescape(v: &str) -> String {
    let mut out = String::with_capacity(v.len());
    let mut it = v.chars();
    while let Some(c) = it.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match it.next() {
            Some('s') => out.push(' '),
            Some('t') => out.push('\t'),
            Some('n') => out.push('\n'),
            Some('\\') => out.push('\\'),
            Some(o) => out.push(o),
            None => {}
        }
    }
    out
}

pub trait Exec {
    fn run(&self, argv: &[String]) -> Result<(), String>;
}

pub struct RealExec;

impl Exec for RealExec {
    fn run(&self, argv: &[String]) -> Result<(), String> {
        let out = Command::new(&argv[0])
            .args(&argv[1..])
            .output()
            .map_err(|e| format!("{}: {e}", argv[0]))?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!("{} failed: {}", argv[0], String::from_utf8_lossy(&out.stderr).trim()))
        }
    }
}

pub struct Local<'a> {
    /// The user's config folder; written to.
    pub config: PathBuf,
    /// System config folders (XDG_CONFIG_DIRS, /etc/xdg): read under the
    /// user's files the way KConfig does, so a distribution default counts.
    pub system_config: Vec<PathBuf>,
    pub data_dirs: Vec<PathBuf>,
    pub exec: &'a dyn Exec,
}

fn s(v: &str) -> String {
    v.to_owned()
}

fn write_args(file: &str, groups: &[&str], key: &str, value: Option<&str>, kind: Option<&str>) -> Vec<String> {
    let mut a = vec![s("kwriteconfig6"), s("--file"), s(file)];
    for g in groups {
        a.push(s("--group"));
        a.push(s(g));
    }
    a.push(s("--key"));
    a.push(s(key));
    if let Some(t) = kind {
        a.push(s("--type"));
        a.push(s(t));
    }
    a.push(s("--notify"));
    match value {
        // "--": a value such as -1 is not an option
        Some(v) => {
            a.push(s("--"));
            a.push(s(v));
        }
        None => a.push(s("--delete")),
    }
    a
}

impl Local<'_> {
    fn file(&self, name: &str) -> KConfig {
        let mut merged = KConfig::default();
        for dir in self.system_config.iter().rev() {
            merged.entries.extend(KConfig::load(&dir.join(name)).entries);
        }
        merged.entries.extend(KConfig::load(&self.config.join(name)).entries);
        merged
    }

    /// Files whose change means a synced setting may have changed. The
    /// systemd path unit watches the same list.
    #[cfg(test)]
    pub fn watched_files() -> &'static [&'static str] {
        static FILES: std::sync::LazyLock<Vec<&'static str>> = std::sync::LazyLock::new(|| {
            let mut v = vec!["kdeglobals", "kcminputrc", "kxkbrc", "plasma-localerc", "kaccessrc", "plasma-org.kde.plasma.desktop-appletsrc"];
            v.extend(table::files());
            v.sort();
            v.dedup();
            v
        });
        &FILES
    }

    fn find_data(&self, rel: &str) -> Option<PathBuf> {
        self.data_dirs.iter().map(|d| d.join(rel)).find(|p| p.exists())
    }

    /// The local value, or None when the setting is at its default or this
    /// PC has no way to express it.
    pub fn read(&self, key: &str) -> Option<Value> {
        if let Some(e) = table::entry(key) {
            return self.file(&e.file).get(&e.group, &e.key).and_then(|raw| e.from_config(raw));
        }
        match key {
            "appearance.colorScheme" => self.file("kdeglobals").get("General", "ColorScheme").map(|v| json!(v)),
            "appearance.accentColor" => {
                let g = self.file("kdeglobals");
                if g.get("General", "accentColorFromWallpaper") == Some("true") {
                    return Some(json!("auto"));
                }
                let rgb: Vec<u8> = g.get("General", "AccentColor")?.split(',').filter_map(|p| p.trim().parse().ok()).collect();
                (rgb.len() == 3).then(|| json!(format!("#{:02x}{:02x}{:02x}", rgb[0], rgb[1], rgb[2])))
            }
            "appearance.wallpaper" => {
                let f = self.file("plasma-org.kde.plasma.desktop-appletsrc");
                f.groups_with("Image")
                    .into_iter()
                    .find(|(g, _)| g.ends_with("Wallpaper/org.kde.image/General"))
                    .and_then(|(_, v)| wallpaper_name(v))
                    .map(|n| json!(n))
            }
            "taskbar.pins" => {
                let f = self.file("plasma-org.kde.plasma.desktop-appletsrc");
                let applet = f.groups_with("plugin").into_iter().find(|(_, p)| {
                    matches!(*p, "org.kde.plasma.icontasks" | "org.kde.plasma.taskmanager")
                })?;
                let launchers = f.get(&format!("{}/Configuration/General", applet.0), "launchers")?;
                let ids: Vec<Value> = launchers
                    .split(',')
                    .filter_map(|l| l.trim().strip_prefix("applications:"))
                    .map(|id| json!(id))
                    .collect();
                Some(Value::Array(ids))
            }
            "region.language" => {
                let v = self.file("plasma-localerc").get("Translations", "LANGUAGE")?.to_owned();
                Some(json!(v.split(':').filter(|l| !l.is_empty()).collect::<Vec<_>>()))
            }
            "region.formats" => self.file("plasma-localerc").get("Formats", "LANG").map(|v| json!(v)),
            "input.keyboardLayouts" => {
                let v = self.file("kxkbrc").get("Layout", "LayoutList")?.to_owned();
                Some(json!(v.split(',').filter(|l| !l.is_empty()).collect::<Vec<_>>()))
            }
            "accessibility.animationSpeed" => self
                .file("kdeglobals")
                .get("KDE", "AnimationDurationFactor")
                .and_then(|v| v.parse::<f64>().ok())
                .map(|v| json!(v)),
            "accessibility.cursorSize" => self
                .file("kcminputrc")
                .get("Mouse", "cursorSize")
                .and_then(|v| v.parse::<u32>().ok())
                .map(|v| json!(v)),
            "accessibility.stickyKeys" => self.file("kaccessrc").get("Keyboard", "StickyKeys").map(|v| json!(v == "true")),
            // Raye's own Start menu keeps its pins elsewhere; not wired yet.
            _ => None,
        }
    }

    /// Whether this PC can apply the key at all.
    pub fn supports(key: &str) -> bool {
        !matches!(key, "start.pins" | "taskbar.alignment")
    }

    fn apply_entry(&self, e: &table::Entry, value: Option<&Value>) -> Result<(), String> {
        let groups = e.groups();
        let argv = match value {
            None => write_args(&e.file, &groups, &e.key, None, None),
            Some(v) => {
                let (text, kind) = e.to_config(v).ok_or_else(|| format!("{} does not fit {}", v, e.id()))?;
                write_args(&e.file, &groups, &e.key, Some(&text), kind)
            }
        };
        self.exec.run(&argv)?;
        // KWin reads its file again only when asked.
        if e.file == "kwinrc" {
            let _ = self.exec.run(&[s("qdbus6"), s("org.kde.KWin"), s("/KWin"), s("reconfigure")]);
        }
        Ok(())
    }

    pub fn apply(&self, key: &str, value: Option<&Value>) -> Result<(), String> {
        if let Some(e) = table::entry(key) {
            return self.apply_entry(e, value);
        }
        let text = value.and_then(Value::as_str);
        let run = |argv: Vec<String>| self.exec.run(&argv);
        match key {
            "appearance.colorScheme" => {
                let Some(name) = text else { return Ok(()) };
                if self.find_data(&format!("color-schemes/{name}.colors")).is_none() {
                    return Err(format!("colour scheme {name} is not installed here"));
                }
                run(vec![s("plasma-apply-colorscheme"), s(name)])
            }
            "appearance.accentColor" => match text {
                Some("auto") => run(write_args("kdeglobals", &["General"], "accentColorFromWallpaper", Some("true"), Some("bool"))),
                Some(c) => {
                    // The tool tints the scheme's colours; the key is what the
                    // Colours page and this client read back.
                    run(vec![s("plasma-apply-colorscheme"), s("--accent-color"), s(c)])?;
                    run(write_args("kdeglobals", &["General"], "accentColorFromWallpaper", Some("false"), Some("bool")))?;
                    run(write_args("kdeglobals", &["General"], "AccentColor", Some(&rgb_of(c)), None))
                }
                None => run(write_args("kdeglobals", &["General"], "AccentColor", None, None)),
            },
            "appearance.wallpaper" => {
                let Some(name) = text else { return Ok(()) };
                let dir = self
                    .find_data(&format!("wallpapers/{name}"))
                    .ok_or_else(|| format!("wallpaper {name} is not installed here"))?;
                run(vec![s("plasma-apply-wallpaperimage"), dir.to_string_lossy().into_owned()])
            }
            "taskbar.pins" => {
                let ids: Vec<String> = value
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(|v| v.as_str()).map(|id| format!("applications:{id}")).collect())
                    .unwrap_or_default();
                run(vec![
                    s("qdbus6"),
                    s("org.kde.plasmashell"),
                    s("/PlasmaShell"),
                    s("org.kde.PlasmaShell.evaluateScript"),
                    pins_script(&ids),
                ])
            }
            "region.language" => {
                let joined = value
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(":"));
                run(write_args("plasma-localerc", &["Translations"], "LANGUAGE", joined.as_deref(), None))
            }
            "region.formats" => run(write_args("plasma-localerc", &["Formats"], "LANG", text, None)),
            "input.keyboardLayouts" => {
                let joined = value
                    .and_then(Value::as_array)
                    .map(|a| a.iter().filter_map(Value::as_str).collect::<Vec<_>>().join(","));
                run(write_args("kxkbrc", &["Layout"], "LayoutList", joined.as_deref(), None))?;
                if joined.is_some() {
                    run(write_args("kxkbrc", &["Layout"], "Use", Some("true"), Some("bool")))?;
                }
                run(vec![s("dbus-send"), s("--session"), s("--type=signal"), s("/Layouts"), s("org.kde.keyboard.reloadConfig")])
            }
            "accessibility.animationSpeed" => {
                let v = value.and_then(Value::as_f64).map(|f| f.to_string());
                run(write_args("kdeglobals", &["KDE"], "AnimationDurationFactor", v.as_deref(), None))
            }
            "accessibility.cursorSize" => {
                let v = value.and_then(Value::as_f64).map(|f| (f as u32).to_string());
                run(write_args("kcminputrc", &["Mouse"], "cursorSize", v.as_deref(), None))
            }
            "accessibility.stickyKeys" => {
                let v = value.and_then(Value::as_bool).map(|b| b.to_string());
                run(write_args("kaccessrc", &["Keyboard"], "StickyKeys", v.as_deref(), Some("bool")))
            }
            _ => Ok(()),
        }
    }
}

/// "#7b3cff" -> "123,60,255", the way kdeglobals keeps colours.
fn rgb_of(hex: &str) -> String {
    (0..3)
        .map(|i| u8::from_str_radix(hex.get(1 + 2 * i..3 + 2 * i).unwrap_or("0"), 16).unwrap_or(0).to_string())
        .collect::<Vec<_>>()
        .join(",")
}

/// "file:///usr/share/wallpapers/Raye Dusk/contents/images/1920x1080.png" -> "Raye Dusk".
/// Pictures of the user's own are not synced (yet): they are files, not names.
pub fn wallpaper_name(image: &str) -> Option<String> {
    let path = image.strip_prefix("file://").unwrap_or(image);
    let rest = path.strip_prefix("/usr/share/wallpapers/")?;
    let name = rest.split('/').next()?;
    (!name.is_empty() && raye_account_common::keys::validate("appearance.wallpaper", Some(&json!(name))).is_ok())
        .then(|| name.to_owned())
}

/// Plasma script that sets the pinned apps of every task manager on the panels.
pub fn pins_script(launchers: &[String]) -> String {
    let list = serde_json::to_string(launchers).unwrap_or_else(|_| "[]".into());
    format!(
        "var l = {list}; panels().forEach(function (p) {{ p.widgets().forEach(function (w) {{ \
         if (w.type === 'org.kde.plasma.icontasks' || w.type === 'org.kde.plasma.taskmanager') {{ \
         w.currentConfigGroup = ['General']; w.writeConfig('launchers', l); }} }}); }});"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::RefCell;

    #[derive(Default)]
    struct Record(RefCell<Vec<Vec<String>>>);

    impl Exec for Record {
        fn run(&self, argv: &[String]) -> Result<(), String> {
            self.0.borrow_mut().push(argv.to_vec());
            Ok(())
        }
    }

    fn setup(files: &[(&str, &str)]) -> tempdir::Dir {
        let d = tempdir::Dir::new();
        for (name, text) in files {
            std::fs::write(d.path.join(name), text).unwrap();
        }
        d
    }

    mod tempdir {
        pub struct Dir {
            pub path: std::path::PathBuf,
        }
        impl Dir {
            pub fn new() -> Dir {
                let path = std::env::temp_dir().join(format!("raye-account-test-{}", uuid::Uuid::new_v4()));
                std::fs::create_dir_all(&path).unwrap();
                Dir { path }
            }
        }
        impl Drop for Dir {
            fn drop(&mut self) {
                let _ = std::fs::remove_dir_all(&self.path);
            }
        }
    }

    const APPLETSRC: &str = "\
[Containments][1]
plugin=org.kde.plasma.folder

[Containments][1][Wallpaper][org.kde.image][General]
Image=file:///usr/share/wallpapers/Raye Dusk/contents/images/1920x1080.png

[Containments][2][Applets][5]
plugin=org.kde.plasma.icontasks

[Containments][2][Applets][5][Configuration][General]
launchers=applications:org.kde.dolphin.desktop,preferred://browser,applications:firefox.desktop
";

    #[test]
    fn reads_kde_files() {
        let d = setup(&[
            ("kdeglobals", "[General]\nColorScheme=RayeNight\nAccentColor=123,60,255\n\n[KDE]\nAnimationDurationFactor=0.5\n"),
            ("plasma-localerc", "[Formats]\nLANG=fr_CA.UTF-8\n\n[Translations]\nLANGUAGE=fr_CA:fr:en_US\n"),
            ("kxkbrc", "[Layout]\nLayoutList=ca,us\nUse=true\n"),
            ("kcminputrc", "[Mouse]\ncursorSize=32\n"),
            ("kaccessrc", "[Keyboard]\nStickyKeys=true\n"),
            ("plasma-org.kde.plasma.desktop-appletsrc", APPLETSRC),
        ]);
        let r = Record::default();
        let l = Local { config: d.path.clone(), system_config: vec![], data_dirs: vec![], exec: &r };
        assert_eq!(l.read("appearance.colorScheme"), Some(json!("RayeNight")));
        assert_eq!(l.read("appearance.accentColor"), Some(json!("#7b3cff")));
        assert_eq!(l.read("appearance.wallpaper"), Some(json!("Raye Dusk")));
        assert_eq!(l.read("taskbar.pins"), Some(json!(["org.kde.dolphin.desktop", "firefox.desktop"])));
        assert_eq!(l.read("region.language"), Some(json!(["fr_CA", "fr", "en_US"])));
        assert_eq!(l.read("region.formats"), Some(json!("fr_CA.UTF-8")));
        assert_eq!(l.read("input.keyboardLayouts"), Some(json!(["ca", "us"])));
        assert_eq!(l.read("accessibility.animationSpeed"), Some(json!(0.5)));
        assert_eq!(l.read("accessibility.cursorSize"), Some(json!(32)));
        assert_eq!(l.read("accessibility.stickyKeys"), Some(json!(true)));
        assert_eq!(l.read("start.pins"), None);
        for k in raye_account_common::keys::KEYS {
            if let Some(v) = l.read(k.key) {
                assert!(raye_account_common::keys::validate(k.key, Some(&v)).is_ok(), "{} reads {v}", k.key);
            }
        }
    }

    #[test]
    fn system_defaults_sit_under_the_user_file() {
        let d = setup(&[("kdeglobals", "[General]\nAccentColor=0,170,136\n")]);
        std::fs::create_dir_all(d.path.join("xdg")).unwrap();
        std::fs::write(d.path.join("xdg/kdeglobals"), "[General]\nColorScheme=RayeNight\nAccentColor=1,2,3\n").unwrap();
        let r = Record::default();
        let l = Local { config: d.path.clone(), system_config: vec![d.path.join("xdg")], data_dirs: vec![], exec: &r };
        assert_eq!(l.read("appearance.colorScheme"), Some(json!("RayeNight")));
        assert_eq!(l.read("appearance.accentColor"), Some(json!("#00aa88")));
    }

    #[test]
    fn defaults_read_as_absent() {
        let d = setup(&[("kdeglobals", "[General]\nColorScheme=RayeNight\n")]);
        let r = Record::default();
        let l = Local { config: d.path.clone(), system_config: vec![], data_dirs: vec![], exec: &r };
        assert_eq!(l.read("appearance.accentColor"), None);
        assert_eq!(l.read("accessibility.cursorSize"), None);
    }

    #[test]
    fn applies_through_plasma_tools() {
        let d = setup(&[]);
        std::fs::create_dir_all(d.path.join("data/color-schemes")).unwrap();
        std::fs::write(d.path.join("data/color-schemes/RayeNight.colors"), "").unwrap();
        let r = Record::default();
        let l = Local { config: d.path.clone(), system_config: vec![], data_dirs: vec![d.path.join("data")], exec: &r };
        l.apply("appearance.colorScheme", Some(&json!("RayeNight"))).unwrap();
        assert!(l.apply("appearance.colorScheme", Some(&json!("Missing"))).is_err());
        l.apply("appearance.accentColor", Some(&json!("#00aa88"))).unwrap();
        l.apply("accessibility.cursorSize", None).unwrap();
        let calls = r.0.borrow();
        assert_eq!(calls[0], vec!["plasma-apply-colorscheme", "RayeNight"]);
        assert_eq!(calls[1], vec!["plasma-apply-colorscheme", "--accent-color", "#00aa88"]);
        assert_eq!(calls[3].last().unwrap(), "0,170,136");
        assert_eq!(calls[4].last().unwrap(), "--delete");
        assert!(calls[4].contains(&"cursorSize".to_owned()));
    }

    #[test]
    fn plain_entries_read_and_apply_through_kwriteconfig() {
        let d = setup(&[
            ("powerdevilrc", "[AC][Display]\nTurnOffDisplayIdleTimeoutSec=600\nTurnOffDisplayWhenIdle=true\n"),
            ("rayeshellrc", "[Taskbar]\nAlignment=left\n"),
        ]);
        let r = Record::default();
        let l = Local { config: d.path.clone(), system_config: vec![], data_dirs: vec![], exec: &r };
        let secs = "cfg:powerdevilrc:AC/Display:TurnOffDisplayIdleTimeoutSec";
        assert_eq!(l.read(secs), Some(json!(600)));
        assert_eq!(l.read("cfg:powerdevilrc:AC/Display:TurnOffDisplayWhenIdle"), Some(json!(true)));
        assert_eq!(l.read("cfg:rayeshellrc:Taskbar:Alignment"), Some(json!("left")));
        assert_eq!(l.read("cfg:kwinrc:Plugins:blurEnabled"), None, "absent is the default");

        l.apply(secs, Some(&json!(300))).unwrap();
        l.apply("cfg:kwinrc:Plugins:blurEnabled", Some(&json!(false))).unwrap();
        l.apply("cfg:rayeshellrc:Taskbar:Alignment", None).unwrap();
        assert!(l.apply(secs, Some(&json!("300"))).is_err(), "a value of the wrong type is not written");
        let calls = r.0.borrow();
        let want: Vec<String> = ["kwriteconfig6", "--file", "powerdevilrc", "--group", "AC", "--group", "Display", "--key", "TurnOffDisplayIdleTimeoutSec", "--notify", "--", "300"]
            .map(String::from)
            .to_vec();
        assert_eq!(calls[0], want);
        assert!(calls[1].windows(2).any(|w| w == ["--type", "bool"]) && calls[1].last().unwrap() == "false");
        assert_eq!(calls[2], vec!["qdbus6", "org.kde.KWin", "/KWin", "reconfigure"], "KWin is told to read its file");
        assert_eq!(calls[3].last().unwrap(), "--delete");
        assert_eq!(calls.len(), 4);
    }

    #[test]
    fn wallpapers_and_pins() {
        assert_eq!(wallpaper_name("/usr/share/wallpapers/Next"), Some("Next".into()));
        assert_eq!(wallpaper_name("file:///home/ana/Pictures/cat.jpg"), None);
        let script = pins_script(&["applications:a\".desktop".into()]);
        assert!(script.contains(r#"["applications:a\".desktop"]"#), "{script}");
    }

    #[test]
    fn the_path_unit_watches_every_file_we_read() {
        let unit = include_str!("../../data/systemd/raye-account-watch.path");
        for f in Local::watched_files() {
            assert!(unit.contains(&format!("PathChanged=%h/.config/{f}\n")), "{f} is not watched");
        }
    }

    #[test]
    fn parses_escapes_and_skips_localized_keys() {
        let c = KConfig::parse("[A][B]\nName=x\\sy\nName[fr]=z\n# c\nPath[$e]=$HOME\n");
        assert_eq!(c.get("A/B", "Name"), Some("x y"));
        assert_eq!(c.get("A/B", "Path"), None);
    }
}
