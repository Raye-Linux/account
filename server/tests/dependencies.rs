//! What this crate is allowed to depend on.
//!
//! `.cargo/audit.toml` silences four advisories, and each ignore rests on a
//! measurement. An ignore whose premise nobody re-checks is how a real
//! advisory gets silenced for years, so the premise that can be checked
//! cheaply is checked here, on every run, with no network and no database.

/// The premise of the `RUSTSEC-2023-0071` ignore in `.cargo/audit.toml`:
/// `rsa` reaches the lockfile only through `sqlx-mysql`, which this crate
/// never enables, so the vulnerable code is listed and never compiled.
/// Measured 2026-11-06: `cargo tree -i rsa -e normal` prints "nothing to
/// print", and the only sqlx backends with build artefacts are `sqlx_core`,
/// `sqlx_macros` and `sqlx_postgres`.
///
/// The ignore is only honest while that holds. Turning on `mysql` -- or
/// letting sqlx's default features back in -- would pull `rsa` into a
/// shipped binary and leave a real advisory silenced. This fails first.
#[test]
fn sqlx_pulls_in_no_other_backend() {
    let manifest = include_str!("../Cargo.toml");
    let line = manifest
        .lines()
        .find(|l| l.trim_start().starts_with("sqlx = "))
        .expect("a sqlx dependency line in server/Cargo.toml");
    assert!(line.contains("default-features = false"), "sqlx must not bring its defaults: {line}");
    assert!(line.contains("\"postgres\""), "postgres is the backend we use: {line}");
    for other in ["mysql", "sqlite", "mssql", "any"] {
        assert!(
            !line.contains(&format!("\"{other}\"")),
            "the sqlx feature {other:?} pulls in another backend. mysql brings rsa, and \
             .cargo/audit.toml ignores RUSTSEC-2023-0071 only because nothing builds it: {line}"
        );
    }
}

/// The desktop daemon reaches the keyring through `secret-service`, which is
/// what pins `zbus` to 5 and so keeps the three unmaintained crates
/// (RUSTSEC-2026-0370/0371/0372) in the tree. If that dependency ever goes,
/// the ignores go with it rather than quietly outliving their reason.
#[test]
fn the_keyring_crate_is_still_what_pins_zbus() {
    let manifest = include_str!("../../client/daemon/Cargo.toml");
    assert!(
        manifest.lines().any(|l| l.trim_start().starts_with("secret-service = ")),
        "secret-service is gone from the daemon: re-check whether zbus can move to 6, \
         and drop the RUSTSEC-2026-0370/0371/0372 ignores from .cargo/audit.toml"
    );
    assert!(
        manifest.lines().any(|l| l.trim_start().starts_with("zbus = ")),
        "zbus is gone from the daemon: the same three ignores no longer apply"
    );
}
