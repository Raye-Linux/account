# Raye account

One account across your Raye PCs: settings that follow you, your name and
picture, your devices and your Store apps. Raye works the same without it.
This is a prototype: nothing here is online yet.

- `server/` the account server (Rust, PostgreSQL)
- `common/` code shared by the server and the client
- `client/` the desktop side: a small daemon and the QML pages for Settings
- `docs/` privacy notes and the security review

## Build

    cargo build --release

The QML pages build with CMake:

    cmake -S client/qml -B build-qml && cmake --build build-qml

## Test

    tools/run-tests.sh            # everything that can run on this machine

The server tests need a database; `tools/dev-db.sh start` starts a
throwaway PostgreSQL and `tools/dev-db.sh url` prints its address:

    RAYE_ACCOUNT_TEST_DB=$(tools/dev-db.sh url) cargo test --workspace

## License

GPL-3.0-or-later, see `LICENSE`.

## Links

- Website: https://rayelinux.com
- Discord: https://discord.gg/TrxhUkabyB (questions, bug reports, news)
