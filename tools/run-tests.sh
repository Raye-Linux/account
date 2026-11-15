#!/bin/sh
# Every test of this repository, in one command.
#
# WHY THIS EXISTS. Until now nothing ran these tests, anywhere. The launcher
# of the tree (iso/tools/raye-tests) lists both suites of this repository as
# skipped, and its reason is exact: `cargo test` compiles the crates, and no
# package build covers them either -- account has no debian/ and
# iso/build.sh does not build it. So the knowledge of how to run them lived
# only in the README, and a suite nobody can start is a suite that rots.
#
# This script holds that knowledge instead: it makes the throwaway database
# the integration half needs, runs everything, and says what it skipped and
# why. It never touches a real database -- see dev-db.sh: a cluster of its
# own in a work folder, on a Unix socket, with no TCP port at all.
#
#   tools/run-tests.sh              everything that can run here
#   tools/run-tests.sh rust         the workspace suite only
#   tools/run-tests.sh qml          the QML module only
#   tools/run-tests.sh pages        the Settings pages and their search rows
#   tools/run-tests.sh audit        cargo audit only
#
# Work folders, all outside the repository so nothing lands in git status:
#   RAYE_ACCOUNT_PG     throwaway PostgreSQL   (default /var/tmp/raye-account-test/pg)
#   CARGO_TARGET_DIR    cargo artefacts        (default /var/tmp/raye-account-build)
#   RAYE_ACCOUNT_QML_BUILD  cmake build folder (default /var/tmp/raye-account-qml)
set -e
cd "$(dirname "$0")/.."
REPO=$(pwd)

: "${RAYE_ACCOUNT_PG:=/var/tmp/raye-account-test/pg}"
: "${CARGO_TARGET_DIR:=/var/tmp/raye-account-build}"
: "${RAYE_ACCOUNT_QML_BUILD:=/var/tmp/raye-account-qml}"
export RAYE_ACCOUNT_PG CARGO_TARGET_DIR

what=${1:-all}
rc=0
skipped=""

note() { printf '\n== %s\n' "$1"; }
skip() { printf '   SKIPPED: %s\n' "$2"; skipped="$skipped\n   $1: $2"; }

have() { command -v "$1" >/dev/null 2>&1; }

# ------------------------------------------------------------------ rust
if [ "$what" = all ] || [ "$what" = rust ]; then
    note "workspace suite (common, server, raye-accountd)"
    if ! have cargo; then
        skip "account/cargo" "no cargo on this machine (apt install cargo; the lockfile wants rustc 1.89 or newer, so trixie-backports)"
    else
        # The integration half makes a database per test and drops it after.
        # Without a database it is SKIPPED BY THE TESTS THEMSELVES, which is
        # the silence this tree refuses: so the database is made here.
        if have runuser && id postgres >/dev/null 2>&1 && ls -d /usr/lib/postgresql/*/bin >/dev/null 2>&1; then
            url=$(sh tools/dev-db.sh start)
            echo "   throwaway database: $url"
            RAYE_ACCOUNT_TEST_DB="$url" cargo test --workspace || rc=1
        else
            skip "account/cargo (integration half)" "no local PostgreSQL (apt install postgresql); the unit tests still run"
            cargo test --workspace || rc=1
        fi
    fi
fi

# ------------------------------------------------------------------- qml
if [ "$what" = all ] || [ "$what" = qml ]; then
    note "QML module org.raye.account"
    if ! have cmake; then
        skip "account/qml" "no cmake"
    elif ! have dbus-run-session; then
        skip "account/qml" "no dbus-run-session (apt install dbus): the test needs a private session bus"
    elif ! cmake -S client/qml -B "$RAYE_ACCOUNT_QML_BUILD" >/dev/null 2>&1; then
        skip "account/qml" "cmake could not configure it (apt install qt6-base-dev qt6-declarative-dev)"
    else
        cmake --build "$RAYE_ACCOUNT_QML_BUILD" -j "$(nproc)" >/dev/null || rc=1
        ctest --test-dir "$RAYE_ACCOUNT_QML_BUILD" --output-on-failure || rc=1
    fi
fi

# ----------------------------------------------------------------- pages
# The cheapest half of this repository to check, and the only one that
# compiles nothing: the Settings pages written here against the sibling
# settings checkout. It counts the search rows they still owe and catches
# a page copy that has drifted from the one settings ships.
if [ "$what" = all ] || [ "$what" = pages ]; then
    note "Settings pages and their search rows"
    if ! have python3; then
        skip "account/pages" "no python3"
    else
        python3 -I -B tests/test_search_anchors.py || rc=1
        python3 -I -B tests/test_sync_table.py || rc=1
    fi
fi

# ----------------------------------------------------------------- audit
if [ "$what" = all ] || [ "$what" = audit ]; then
    note "cargo audit"
    if ! have cargo-audit && ! cargo audit --version >/dev/null 2>&1; then
        skip "cargo audit" "not installed (cargo install cargo-audit --locked); it needs the network for the advisory database"
    else
        # Ignores and their measured reasons: .cargo/audit.toml
        (cd "$REPO" && cargo audit) || rc=1
    fi
fi

if [ -n "$skipped" ]; then
    printf '\n== what did not run, and why\n'
    printf '%b\n' "$skipped"
fi
printf '\n== %s\n' "$([ $rc -eq 0 ] && echo 'everything that ran, passed' || echo 'SOMETHING FAILED')"
exit $rc
