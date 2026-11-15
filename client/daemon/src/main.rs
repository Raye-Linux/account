mod api;
mod device;
mod keyring;
mod local;
mod profile;
mod service;
mod signin;
mod state;
mod sync;

use std::process::ExitCode;

const USAGE: &str = "usage: raye-accountd [serve | sync | status | --version]";

fn main() -> ExitCode {
    let cmd = std::env::args().nth(1).unwrap_or_else(|| "serve".into());
    let rt = match tokio::runtime::Builder::new_current_thread().enable_all().build() {
        Ok(rt) => rt,
        Err(e) => {
            eprintln!("raye-accountd: {e}");
            return ExitCode::FAILURE;
        }
    };
    match cmd.as_str() {
        "serve" => rt.block_on(serve()),
        "sync" => rt.block_on(call("SyncNow")),
        "status" => rt.block_on(call("State")),
        "--version" => {
            println!("raye-accountd {}", env!("CARGO_PKG_VERSION"));
            ExitCode::SUCCESS
        }
        _ => {
            eprintln!("{USAGE}");
            ExitCode::from(2)
        }
    }
}

async fn serve() -> ExitCode {
    let shared = service::Shared::new();
    let account = service::Account { shared: shared.clone() };
    let conn = zbus::connection::Builder::session()
        .and_then(|b| b.name(service::NAME))
        .and_then(|b| b.serve_at(service::PATH, account));
    let conn = match conn {
        Ok(b) => b.build().await,
        Err(e) => Err(e),
    };
    match conn {
        Ok(_conn) => {
            shared.exit_when_idle().await;
            ExitCode::SUCCESS
        }
        Err(zbus::Error::NameTaken) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("raye-accountd: {e}");
            ExitCode::FAILURE
        }
    }
}

/// The sync unit and scripts go through the running service (D-Bus starts
/// it if needed), so only one process ever writes the state.
async fn call(method: &str) -> ExitCode {
    let reply = async {
        let conn = zbus::Connection::session().await?;
        let msg = conn
            .call_method(Some(service::NAME), service::PATH, Some(service::NAME), method, &())
            .await?;
        msg.body().deserialize::<String>()
    }
    .await;
    match reply {
        Ok(s) => {
            println!("{s}");
            ExitCode::SUCCESS
        }
        Err(e) => {
            eprintln!("raye-accountd: {e}");
            ExitCode::FAILURE
        }
    }
}
