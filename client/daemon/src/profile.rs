//! The account's picture and name on the local account, through
//! AccountsService: the same place Settings > Your info, the lock screen
//! and the login screen read them. Only the display name and the picture
//! change; the Unix login name is never touched.

use std::path::Path;

use zbus::{proxy, zvariant::OwnedObjectPath, Connection};

use crate::state::OriginalProfile;

#[proxy(
    interface = "org.freedesktop.Accounts",
    default_service = "org.freedesktop.Accounts",
    default_path = "/org/freedesktop/Accounts"
)]
trait Accounts {
    fn find_user_by_id(&self, id: i64) -> zbus::Result<OwnedObjectPath>;
}

#[proxy(interface = "org.freedesktop.Accounts.User", default_service = "org.freedesktop.Accounts")]
trait User {
    fn set_real_name(&self, name: &str) -> zbus::Result<()>;
    fn set_icon_file(&self, filename: &str) -> zbus::Result<()>;
    #[zbus(property)]
    fn real_name(&self) -> zbus::Result<String>;
    #[zbus(property)]
    fn icon_file(&self) -> zbus::Result<String>;
}

fn uid() -> u32 {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata("/proc/self").map(|m| m.uid()).unwrap_or(u32::MAX)
}

async fn me(conn: &Connection) -> zbus::Result<UserProxy<'static>> {
    let path = AccountsProxy::new(conn).await?.find_user_by_id(uid() as i64).await?;
    UserProxy::builder(conn).path(path)?.build().await
}

pub async fn current(conn: &Connection) -> zbus::Result<OriginalProfile> {
    let u = me(conn).await?;
    Ok(OriginalProfile { real_name: u.real_name().await?, icon_file: u.icon_file().await? })
}

pub async fn set_name(conn: &Connection, name: &str) -> zbus::Result<()> {
    let u = me(conn).await?;
    if u.real_name().await? != name {
        u.set_real_name(name).await?;
    }
    Ok(())
}

/// AccountsService copies the file into its own folder, so the cached
/// copy can change later without touching what the login screen shows.
pub async fn set_picture(conn: &Connection, file: &Path) -> zbus::Result<()> {
    me(conn).await?.set_icon_file(&file.to_string_lossy()).await
}

/// Puts back the name and picture the account had before the Raye account.
pub async fn restore(conn: &Connection, original: &OriginalProfile) -> zbus::Result<()> {
    let u = me(conn).await?;
    u.set_real_name(&original.real_name).await?;
    // An empty path is AccountsService's way of saying "no picture".
    let icon = if Path::new(&original.icon_file).exists() { original.icon_file.as_str() } else { "" };
    u.set_icon_file(icon).await
}
