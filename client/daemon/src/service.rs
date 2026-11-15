//! org.raye.Account1 on the session bus. Started by D-Bus when Settings,
//! the Store or the sync unit call it, and gone again after a short idle
//! time: nothing of the account runs while nobody uses it.

use std::sync::{Arc, Mutex};
use std::time::Duration;

use serde_json::{json, Value};
use tokio::time::Instant;
use zbus::object_server::SignalEmitter;
use zbus::{fdo, interface, Connection};

use crate::api::{ApiError, Client};
use crate::keyring;
use crate::local::{Local, RealExec};
use crate::profile;
use crate::signin::{self, Canceller, SignInError};
use crate::state::{cache_dir, config_dir, state_dir, OriginalProfile, ProfileMode, State};
use crate::sync;
use raye_account_common::api::{Me, SettingsPage};

pub const NAME: &str = "org.raye.Account1";
pub const PATH: &str = "/org/raye/Account1";
const IDLE: Duration = Duration::from_secs(20);
const PICTURE_MAX: u64 = 2 * 1024 * 1024;

pub struct Shared {
    state: Mutex<State>,
    busy: Mutex<Option<Canceller>>,
    signing_in: Mutex<bool>,
    /// What the sign-in is doing, for the pages: "browser", "syncing" or "".
    stage: Mutex<&'static str>,
    first_sync_lock: tokio::sync::Mutex<()>,
    last_use: Mutex<Instant>,
    sync_lock: tokio::sync::Mutex<()>,
    system: tokio::sync::OnceCell<Option<Connection>>,
}

impl Shared {
    pub fn new() -> Arc<Shared> {
        Arc::new(Shared {
            state: Mutex::new(State::load()),
            busy: Mutex::new(None),
            signing_in: Mutex::new(false),
            stage: Mutex::new(""),
            first_sync_lock: tokio::sync::Mutex::new(()),
            last_use: Mutex::new(Instant::now()),
            sync_lock: tokio::sync::Mutex::new(()),
            system: tokio::sync::OnceCell::new(),
        })
    }

    fn touch(&self) {
        *self.last_use.lock().unwrap() = Instant::now();
    }

    fn set_stage(&self, stage: &'static str) {
        *self.stage.lock().unwrap() = stage;
    }

    fn snapshot(&self) -> State {
        self.state.lock().unwrap().clone()
    }

    fn update(&self, f: impl FnOnce(&mut State)) {
        let mut s = self.state.lock().unwrap();
        f(&mut s);
        if let Err(e) = s.save() {
            eprintln!("raye-accountd: can't save state: {e}");
        }
    }

    async fn system_bus(&self) -> Option<&Connection> {
        self.system.get_or_init(|| async { Connection::system().await.ok() }).await.as_ref()
    }

    /// Exits once nobody has called for IDLE and no sign-in is waiting on the browser.
    pub async fn exit_when_idle(self: Arc<Self>) {
        loop {
            let deadline = *self.last_use.lock().unwrap() + IDLE;
            tokio::time::sleep_until(deadline).await;
            let idle = self.last_use.lock().unwrap().elapsed() >= IDLE;
            if idle && !*self.signing_in.lock().unwrap() && self.sync_lock.try_lock().is_ok() {
                return;
            }
            if !idle {
                continue;
            }
            self.touch();
        }
    }
}

fn code(e: &ApiError) -> &'static str {
    match e {
        ApiError::SignedOut => "signed_out",
        ApiError::Offline(_) => "offline",
        ApiError::Server(_, _) => "server",
    }
}

fn failed(e: impl std::fmt::Display) -> fdo::Error {
    fdo::Error::Failed(e.to_string())
}

/// The account picture as last downloaded. The name carries the ETag so a
/// new picture is a new URL and image caches in the pages never show the old one.
fn picture_path(etag: &str) -> std::path::PathBuf {
    cache_dir().join(format!("picture-{etag}.png"))
}

fn remove_pictures() {
    if let Ok(dir) = std::fs::read_dir(cache_dir()) {
        for e in dir.flatten() {
            if e.file_name().to_string_lossy().starts_with("picture-") {
                let _ = std::fs::remove_file(e.path());
            }
        }
    }
}

async fn load_client(state: &State) -> Result<Client, String> {
    match keyring::load(&state.server).await? {
        Some(s) => Ok(Client::new(state.server.clone(), s)),
        None => Err("signed_out".into()),
    }
}

/// Runs a blocking API call with the client, writing refreshed tokens back.
async fn with_client<T: Send + 'static>(
    state: &State,
    f: impl FnOnce(&mut Client) -> Result<T, ApiError> + Send + 'static,
) -> Result<T, String> {
    let mut client = load_client(state).await?;
    let server = state.server.clone();
    let (client, out) = tokio::task::spawn_blocking(move || {
        let out = f(&mut client);
        (client, out)
    })
    .await
    .map_err(|e| e.to_string())?;
    if client.refreshed {
        keyring::store(&server, &client.secrets).await?;
    }
    out.map_err(|e| code(&e).to_owned())
}

fn system_config_dirs() -> Vec<std::path::PathBuf> {
    let dirs = std::env::var("XDG_CONFIG_DIRS").unwrap_or_else(|_| "/etc/xdg".into());
    dirs.split(':').filter(|d| !d.is_empty()).map(Into::into).collect()
}

fn local_paths() -> (std::path::PathBuf, Vec<std::path::PathBuf>) {
    let mut data = vec![crate::state::home().join(".local/share")];
    let dirs = std::env::var("XDG_DATA_DIRS").unwrap_or_else(|_| "/usr/local/share:/usr/share".into());
    data.extend(dirs.split(':').filter(|d| !d.is_empty()).map(Into::into));
    (config_dir(), data)
}

fn systemctl(args: &[&str]) {
    let _ = std::process::Command::new("systemctl").arg("--user").args(args).status();
}

pub struct Account {
    pub shared: Arc<Shared>,
}

impl Account {
    /// Every sync goes through here: the first one after a sign-in looks
    /// at the account before anything is taken from it.
    async fn sync_all(&self) -> Result<sync::Report, String> {
        if self.shared.snapshot().first_sync_pending {
            return self.first_sync().await;
        }
        self.sync_settled().await
    }

    /// Settings, apps, then picture and name. One at a time.
    async fn sync_settled(&self) -> Result<sync::Report, String> {
        let _guard = self.shared.sync_lock.lock().await;
        let mut state = self.shared.snapshot();
        if !state.signed_in {
            return Err("signed_out".into());
        }
        if state.choose_pending || state.first_sync_pending {
            return Err("choose".into());
        }
        let mut client = load_client(&state).await?;
        let server = state.server.clone();
        let (client, state_after, result, me_pic) = tokio::task::spawn_blocking(move || {
            let (config, data) = local_paths();
            let exec = RealExec;
            let local = Local { config, system_config: system_config_dirs(), data_dirs: data, exec: &exec };
            let result = sync::settings_and_apps(&mut state, &local, &mut client);
            let me_pic = result.as_ref().ok().map(|_| fetch_profile(&mut state, &mut client));
            (client, state, result, me_pic)
        })
        .await
        .map_err(|e| e.to_string())?;
        if client.refreshed {
            keyring::store(&server, &client.secrets).await?;
        }
        let mut state = state_after;
        let now = time::OffsetDateTime::now_utc();
        match &result {
            Ok(_) => {
                state.last_sync = now.format(&time::format_description::well_known::Rfc3339).unwrap_or_default();
                state.last_error.clear();
            }
            Err(e) => state.last_error = code(e).to_owned(),
        }
        if let Some(Ok(new_picture)) = me_pic {
            self.apply_profile(&mut state, new_picture).await;
        }
        let signed_out = matches!(result, Err(ApiError::SignedOut));
        self.shared.update(|s| *s = state);
        if signed_out {
            self.forget_this_pc(false).await;
        }
        result.map_err(|e| code(&e).to_owned())
    }

    async fn apply_profile(&self, state: &mut State, new_picture: bool) {
        let mode = state.profile_mode;
        if mode == ProfileMode::None {
            return;
        }
        let Some(bus) = self.shared.system_bus().await else { return };
        if state.original_profile.is_none() {
            if let Ok(orig) = profile::current(bus).await {
                state.original_profile = Some(keep_original_picture(orig));
            }
        }
        let mut errors = Vec::new();
        if mode.name() && !state.display_name.is_empty() {
            if let Err(e) = profile::set_name(bus, &state.display_name).await {
                errors.push(e.to_string());
            }
        }
        let picture = picture_path(&state.avatar_etag);
        if mode.picture() && (new_picture || state.avatar_applied_etag() != state.avatar_etag) && picture.exists() {
            match profile::set_picture(bus, &picture).await {
                Ok(()) => state.mark_avatar_applied(),
                Err(e) => errors.push(e.to_string()),
            }
        }
        if !errors.is_empty() {
            eprintln!("raye-accountd: profile: {}", errors.join("; "));
            state.last_error = "profile".into();
        }
    }

    /// Signs this PC out locally: keyring, watchers, state.
    async fn forget_this_pc(&self, restore: bool) {
        let state = self.shared.snapshot();
        let _ = keyring::delete(&state.server).await;
        systemctl(&["disable", "--now", "raye-account-watch.path", "raye-account-sync.timer"]);
        if restore {
            if let (Some(orig), Some(bus)) = (state.original_profile.clone(), self.shared.system_bus().await) {
                if let Err(e) = profile::restore(bus, &orig).await {
                    eprintln!("raye-accountd: restore profile: {e}");
                }
            }
        }
        remove_pictures();
        self.shared.update(State::sign_out);
    }

    async fn sign_in_flow(&self, signup: bool, emitter: &SignalEmitter<'_>) -> Result<(), String> {
        let server = self.shared.snapshot().server;
        let (pending, url) = signin::begin(&server, signup).map_err(|e| e.to_string())?;
        *self.shared.busy.lock().unwrap() = Some(pending.canceller());
        open_browser(&url)?;
        let device = crate::device::current();
        let device_name = device.name.clone();
        let server_b = server.clone();
        let secrets = tokio::task::spawn_blocking(move || {
            let code = pending.wait_for_code()?;
            pending.exchange(&server_b, &code, &device)
        })
        .await
        .map_err(|e| e.to_string())?
        .map_err(|e| match e {
            SignInError::Cancelled => "cancelled".to_owned(),
            SignInError::TimedOut => "timeout".to_owned(),
            SignInError::Api(a) => code(&a).to_owned(),
            SignInError::Io(_) => "offline".to_owned(),
        })?;
        keyring::store(&server, &secrets).await.map_err(|_| "keyring".to_owned())?;
        self.shared.update(|s| {
            let keep = (s.sync_off.clone(), s.apps_sync, s.profile_mode, s.server.clone());
            *s = State::default();
            (s.sync_off, s.apps_sync, s.profile_mode, s.server) = keep;
            s.signed_in = true;
            s.first_sync_pending = true;
            s.device_name = device_name;
        });
        systemctl(&["enable", "--now", "raye-account-watch.path", "raye-account-sync.timer"]);
        self.shared.set_stage("syncing");
        let _ = Account::changed(emitter).await;
        match self.first_sync().await {
            Ok(_) => Ok(()),
            // the pages ask which settings to keep
            Err(e) if e == "choose" => Ok(()),
            Err(e) => Err(e),
        }
    }

    /// Right after signing in: an empty account gets this PC's settings and
    /// picture; an account that already has other settings waits for the
    /// person to choose (KeepSettings).
    async fn first_sync(&self) -> Result<sync::Report, String> {
        let _guard = self.shared.first_sync_lock.lock().await;
        let state = self.shared.snapshot();
        if !state.first_sync_pending {
            return self.sync_settled().await;
        }
        let page: SettingsPage = with_client(&state, |c| c.json("GET", "/v1/settings?since=0", None)).await?;
        let me: Me = with_client(&state, |c| c.json("GET", "/v1/me", None)).await?;
        let decision = tokio::task::spawn_blocking(move || {
            let (config, data) = local_paths();
            let exec = RealExec;
            let local = Local { config, system_config: system_config_dirs(), data_dirs: data, exec: &exec };
            sync::first_sync(&state, &local, &page)
        })
        .await
        .map_err(|e| e.to_string())?;
        // the header shows who signed in while the person decides
        self.shared.update(|s| {
            s.email = me.email.clone();
            s.display_name = me.display_name.clone();
        });
        if let sync::FirstSync::Differs(n) = decision {
            self.shared.update(|s| {
                s.first_sync_pending = false;
                s.choose_pending = true;
                s.choose_differ = n;
            });
            return Err("choose".into());
        }
        if me.avatar_etag.is_none() {
            self.send_pc_picture().await;
        }
        self.shared.update(|s| s.first_sync_pending = false);
        self.sync_settled().await
    }

    /// Sends this PC's picture to the account, unless it is one of the
    /// pictures Raye ships: those are nobody's photo.
    async fn send_pc_picture(&self) {
        let Some(bus) = self.shared.system_bus().await else { return };
        let Ok(current) = profile::current(bus).await else { return };
        let Some(bytes) = own_picture(std::path::Path::new(&current.icon_file), &stock_picture_dirs()) else { return };
        let state = self.shared.snapshot();
        let sent = with_client(&state, move |c| {
            c.request("PUT", "/v1/me/avatar", crate::api::Body::Png(&bytes), None).map(|_| ())
        })
        .await;
        if let Err(e) = sent {
            eprintln!("raye-accountd: picture not sent: {e}");
        }
    }
}

fn stock_picture_dirs() -> Vec<std::path::PathBuf> {
    let (_, data) = local_paths();
    data.iter()
        .flat_map(|d| [d.join("raye-settings/avatars"), d.join("plasma/avatars")])
        .collect()
}

/// The bytes of the local account's picture when it is the person's own:
/// present, not too big, and not a copy of a stock picture.
pub fn own_picture(file: &std::path::Path, stock_dirs: &[std::path::PathBuf]) -> Option<Vec<u8>> {
    let meta = std::fs::metadata(file).ok()?;
    if !meta.is_file() || meta.len() == 0 || meta.len() > PICTURE_MAX {
        return None;
    }
    let bytes = std::fs::read(file).ok()?;
    let is_stock = stock_dirs
        .iter()
        .filter_map(|d| std::fs::read_dir(d).ok())
        .flatten()
        .flatten()
        .filter(|e| e.metadata().map(|m| m.len() == meta.len()).unwrap_or(false))
        .any(|e| std::fs::read(e.path()).map(|b| b == bytes).unwrap_or(false));
    (!is_stock).then_some(bytes)
}

/// Copies the picture the login screen shows now, before ours replaces
/// it: AccountsService keeps one file per user and overwrites it.
fn keep_original_picture(orig: OriginalProfile) -> OriginalProfile {
    let src = std::path::Path::new(&orig.icon_file);
    let dst = state_dir().join("picture-before-raye-account");
    let copied = src.is_file() && std::fs::create_dir_all(state_dir()).is_ok() && std::fs::copy(src, &dst).is_ok();
    OriginalProfile {
        real_name: orig.real_name,
        icon_file: if copied { dst.to_string_lossy().into_owned() } else { String::new() },
    }
}

/// Name and picture from the account. Returns whether a new picture came.
fn fetch_profile(state: &mut State, client: &mut Client) -> Result<bool, ApiError> {
    let me: raye_account_common::api::Me = client.json("GET", "/v1/me", None)?;
    state.email = me.email;
    state.display_name = me.display_name;
    let etag = me.avatar_etag.unwrap_or_default();
    if etag.is_empty() {
        state.avatar_etag.clear();
        return Ok(false);
    }
    let cached = if picture_path(&state.avatar_etag).exists() { state.avatar_etag.as_str() } else { "" };
    match client.avatar(cached)? {
        Some(png) => {
            std::fs::create_dir_all(cache_dir()).map_err(|e| ApiError::Offline(e.to_string()))?;
            let tmp = cache_dir().join(".picture.png.tmp");
            remove_pictures();
            std::fs::write(&tmp, &png)
                .and_then(|_| std::fs::rename(&tmp, picture_path(&etag)))
                .map_err(|e| ApiError::Offline(e.to_string()))?;
            state.avatar_etag = etag;
            Ok(true)
        }
        None => {
            state.avatar_etag = etag;
            Ok(false)
        }
    }
}

/// RAYE_ACCOUNT_BROWSER replaces xdg-open, for tests and the demo.
fn open_browser(url: &str) -> Result<(), String> {
    let opener = std::env::var("RAYE_ACCOUNT_BROWSER").unwrap_or_else(|_| "xdg-open".into());
    std::process::Command::new(opener)
        .arg(url)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .spawn()
        .map(|_| ())
        .map_err(|_| "no_browser".to_owned())
}

fn public_state(s: &State, busy: bool) -> Value {
    let picture = picture_path(&s.avatar_etag);
    json!({
        "preview": crate::state::preview_enabled(),
        "signedIn": s.signed_in,
        "busy": busy,
        "email": s.email,
        "displayName": s.display_name,
        "picture": if s.signed_in && !s.avatar_etag.is_empty() && picture.exists() { format!("file://{}", picture.display()) } else { String::new() },
        "deviceName": s.device_name,
        "server": s.server,
        "profileMode": s.profile_mode.id(),
        "sync": {
            "personalization": s.category_on("personalization"),
            "taskbar": s.category_on("taskbar"),
            "language": s.category_on("language"),
            "accessibility": s.category_on("accessibility"),
            "system": s.category_on("system"),
            "apps": s.apps_sync,
        },
        "lastSync": s.last_sync,
        "error": s.last_error,
        "choose": s.signed_in && s.choose_pending,
        "chooseDiffer": s.choose_differ,
    })
}

#[interface(name = "org.raye.Account1")]
impl Account {
    /// Everything the pages show, as JSON.
    async fn state(&self) -> String {
        self.shared.touch();
        let busy = *self.shared.signing_in.lock().unwrap();
        let stage = *self.shared.stage.lock().unwrap();
        let mut v = public_state(&self.shared.snapshot(), busy);
        v["stage"] = json!(stage);
        v.to_string()
    }

    /// Opens the browser on the sign-in page and returns at once; Changed
    /// fires when the sign-in ends one way or the other.
    async fn sign_in(&self, create_account: bool, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        {
            let mut busy = self.shared.signing_in.lock().unwrap();
            if *busy {
                return Err(failed("busy"));
            }
            *busy = true;
        }
        let me = Account { shared: self.shared.clone() };
        let emitter = emitter.into_owned();
        tokio::spawn(async move {
            me.shared.set_stage("browser");
            let _ = Account::changed(&emitter).await;
            let result = me.sign_in_flow(create_account, &emitter).await;
            me.shared.set_stage("");
            *me.shared.signing_in.lock().unwrap() = false;
            *me.shared.busy.lock().unwrap() = None;
            if let Err(e) = result {
                me.shared.update(|s| s.last_error = e);
            }
            me.shared.touch();
            let _ = Account::changed(&emitter).await;
        });
        Ok(())
    }

    async fn cancel_sign_in(&self) {
        self.shared.touch();
        if let Some(c) = self.shared.busy.lock().unwrap().take() {
            c.cancel();
        }
    }

    /// Signs this PC out of the account. With `restore_profile`, the local
    /// account gets back the name and picture it had before.
    async fn sign_out(&self, restore_profile: bool, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        let state = self.shared.snapshot();
        if state.signed_in {
            // Best effort: offline, the device still leaves this PC and the
            // owner can remove it from another one.
            let _ = with_client(&state, |c| c.no_content("POST", "/v1/oauth/revoke", None)).await;
        }
        self.forget_this_pc(restore_profile).await;
        let _ = Account::changed(&emitter).await;
        Ok(())
    }

    /// After a sign-in to an account that already had other settings:
    /// "pc" keeps this PC's settings and picture and sends them to the
    /// account, "account" takes the account's.
    async fn keep_settings(&self, from: String, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        let state = self.shared.snapshot();
        if !state.signed_in || !state.choose_pending {
            return Err(failed("nothing_to_choose"));
        }
        if from != "pc" && from != "account" {
            return Err(fdo::Error::InvalidArgs(from));
        }
        self.shared.set_stage("syncing");
        let _ = Account::changed(&emitter).await;
        let result = async {
            if from == "pc" {
                let page: SettingsPage =
                    with_client(&state, |c| c.json("GET", "/v1/settings?since=0", None)).await?;
                self.shared.update(|s| sync::adopt_account_revs(s, &page));
                self.send_pc_picture().await;
            }
            self.shared.update(|s| {
                s.choose_pending = false;
                s.choose_differ = 0;
            });
            self.sync_all().await.map(|_| ())
        }
        .await;
        self.shared.set_stage("");
        if let Err(e) = &result {
            self.shared.update(|s| s.last_error = e.clone());
        }
        let _ = Account::changed(&emitter).await;
        result.map_err(failed)
    }

    async fn sync_now(&self, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<String> {
        self.shared.touch();
        let r = self.sync_all().await;
        let _ = Account::changed(&emitter).await;
        let r = r.map_err(failed)?;
        Ok(json!({"applied": r.applied, "pushed": r.pushed, "superseded": r.superseded,
                  "failed": r.failed.iter().map(|(k, _)| k).collect::<Vec<_>>()})
            .to_string())
    }

    async fn devices(&self) -> fdo::Result<String> {
        self.shared.touch();
        let state = self.shared.snapshot();
        let list: Value = with_client(&state, |c| c.json("GET", "/v1/devices", None)).await.map_err(failed)?;
        Ok(list.to_string())
    }

    async fn remove_device(&self, id: String, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        let id = uuid::Uuid::parse_str(&id).map_err(|_| fdo::Error::InvalidArgs("id".into()))?;
        let state = self.shared.snapshot();
        let this = keyring::load(&state.server).await.ok().flatten().map(|s| s.device_id);
        with_client(&state, move |c| c.no_content("DELETE", &format!("/v1/devices/{id}"), None))
            .await
            .map_err(failed)?;
        if this == Some(id) {
            self.forget_this_pc(false).await;
        }
        let _ = Account::changed(&emitter).await;
        Ok(())
    }

    /// "Raye backup" switches: personalization, taskbar, language,
    /// accessibility, apps.
    async fn set_sync(&self, category: String, on: bool, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        if category == "apps" {
            self.shared.update(|s| {
                s.apps_sync = on;
                s.installs_hash.clear();
            });
        } else if raye_account_common::keys::Category::from_id(&category).is_some() {
            self.shared.update(|s| s.set_category(&category, on));
        } else {
            return Err(fdo::Error::InvalidArgs(category));
        }
        let _ = Account::changed(&emitter).await;
        if on && self.shared.snapshot().signed_in {
            let _ = self.sync_all().await;
            let _ = Account::changed(&emitter).await;
        }
        Ok(())
    }

    /// both, picture, name or none.
    async fn set_profile_mode(&self, mode: String, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        let mode = ProfileMode::parse(&mode).ok_or_else(|| fdo::Error::InvalidArgs(mode))?;
        self.shared.update(|s| s.profile_mode = mode);
        let mut state = self.shared.snapshot();
        if state.signed_in {
            self.apply_profile(&mut state, true).await;
            self.shared.update(|s| *s = state);
        }
        let _ = Account::changed(&emitter).await;
        Ok(())
    }

    async fn set_display_name(&self, name: String, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        let state = self.shared.snapshot();
        let body = json!({ "display_name": name });
        let me: raye_account_common::api::Me =
            with_client(&state, move |c| c.json("PATCH", "/v1/me", Some(&body))).await.map_err(failed)?;
        let mut state = self.shared.snapshot();
        state.display_name = me.display_name;
        self.apply_profile(&mut state, false).await;
        self.shared.update(|s| *s = state);
        let _ = Account::changed(&emitter).await;
        Ok(())
    }

    /// Sends a picture to the account. The server crops and re-encodes it.
    async fn upload_picture(&self, path: String, #[zbus(signal_emitter)] emitter: SignalEmitter<'_>) -> fdo::Result<()> {
        self.shared.touch();
        let path = path.strip_prefix("file://").unwrap_or(&path).to_owned();
        let meta = std::fs::metadata(&path).map_err(|_| fdo::Error::FileNotFound(path.clone()))?;
        if !meta.is_file() || meta.len() > PICTURE_MAX {
            return Err(failed("too_large"));
        }
        let bytes = std::fs::read(&path).map_err(failed)?;
        let state = self.shared.snapshot();
        with_client(&state, move |c| c.request("PUT", "/v1/me/avatar", crate::api::Body::Png(&bytes), None).map(|_| ()))
            .await
            .map_err(failed)?;
        let _ = self.sync_all().await;
        let _ = Account::changed(&emitter).await;
        Ok(())
    }

    /// The Store library with the devices each app is on, as JSON.
    async fn library(&self) -> fdo::Result<String> {
        self.shared.touch();
        let state = self.shared.snapshot();
        let list: Value = with_client(&state, |c| c.json("GET", "/v1/store/library", None)).await.map_err(failed)?;
        Ok(list.to_string())
    }

    #[zbus(signal)]
    async fn changed(emitter: &SignalEmitter<'_>) -> zbus::Result<()>;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn stock_pictures_are_not_sent() {
        let d = std::env::temp_dir().join(format!("raye-picture-test-{}", uuid::Uuid::new_v4()));
        std::fs::create_dir_all(d.join("stock")).unwrap();
        std::fs::write(d.join("stock/eye.png"), b"stock eye").unwrap();
        std::fs::write(d.join("copy-of-eye"), b"stock eye").unwrap();
        std::fs::write(d.join("me.png"), b"a real photo").unwrap();
        std::fs::write(d.join("empty"), b"").unwrap();
        let stock = [d.join("stock"), d.join("missing")];
        assert_eq!(own_picture(&d.join("me.png"), &stock), Some(b"a real photo".to_vec()));
        assert_eq!(own_picture(&d.join("copy-of-eye"), &stock), None);
        assert_eq!(own_picture(&d.join("empty"), &stock), None);
        assert_eq!(own_picture(&d.join("nothing-here"), &stock), None);
        let _ = std::fs::remove_dir_all(d);
    }

    #[test]
    fn state_tells_the_pages_to_ask() {
        let mut s = State { signed_in: true, choose_pending: true, choose_differ: 12, first_sync_pending: true, ..State::default() };
        let v = public_state(&s, false);
        assert_eq!(v["choose"], json!(true));
        assert_eq!(v["chooseDiffer"], json!(12));
        s.sign_out();
        assert_eq!(public_state(&s, false)["choose"], json!(false));
        assert!(!s.first_sync_pending, "a new sign-in starts the comparison again");
    }
}
