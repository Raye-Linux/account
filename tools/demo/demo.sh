#!/bin/sh
# End to end on one machine, inside the agents' chroot: a throwaway
# database, the server on 127.0.0.1, and two "PCs" (two homes, two session
# buses, two raye-accountd started by D-Bus activation). Nothing listens
# beyond the loopback and nothing touches a real account or database.
#   demo.sh up | down
set -eu
ROOT=${ROOT:-/build/account}
SRC=$ROOT/src
BIN=$ROOT/target/release
# built with --features insecure-test-keyring: the chroot has no keyring
DAEMON=${DAEMON:-$ROOT/target-demo/release/raye-accountd}
DEMO=$ROOT/demo
PORT=18787
SERVER=http://127.0.0.1:$PORT
EMAIL=ana.tremblay@example.com

pgdir=$ROOT/pg
psql_admin() { runuser -u postgres -- psql -h "$pgdir/sock" -p 55433 -U postgres -qtA "$@"; }

call() { # pc method [args...]
    pc=$1 m=$2
    shift 2
    DBUS_SESSION_BUS_ADDRESS=$(cat "$DEMO/$pc/bus") gdbus call --session -d org.raye.Account1 \
        -o /org/raye/Account1 -m "org.raye.Account1.$m" "$@"
}

state() { call "$1" State | sed "s/^('//; s/',)\$//"; }

wait_signed_in() {
    i=0
    until state "$1" | grep -q '"signedIn":true' && ! state "$1" | grep -q '"busy":true'; do
        i=$((i + 1))
        [ $i -lt 60 ] || { echo "$1: sign-in did not finish"; state "$1"; exit 1; }
        sleep 0.5
    done
}

make_pc() { # pc device-name action name
    pc=$1
    home=$DEMO/$pc/home
    mkdir -p "$home/.config" "$DEMO/$pc/share/dbus-1/services"
    cat >"$DEMO/$pc/share/dbus-1/services/org.raye.Account1.service" <<EOF
[D-BUS Service]
Name=org.raye.Account1
Exec=$DAEMON serve
EOF
    env -i PATH=/usr/bin:/bin HOME="$home" XDG_CONFIG_HOME="$home/.config" \
        XDG_STATE_HOME="$home/.local/state" XDG_CACHE_HOME="$home/.cache" \
        XDG_DATA_DIRS="$DEMO/$pc/share:/usr/local/share:/usr/share" LANG=en_US.UTF-8 \
        RAYE_ACCOUNT_SERVER="$SERVER" RAYE_ACCOUNT_PREVIEW=1 RAYE_ACCOUNT_DEVICE_NAME="$2" \
        RAYE_ACCOUNT_TEST_KEYRING_FILE="$DEMO/$pc/secrets.json" \
        RAYE_ACCOUNT_BROWSER="$SRC/tools/demo/stand-in-browser.sh" \
        DEMO_ACTION="$3" DEMO_EMAIL="$EMAIL" DEMO_NAME="$4" DEMO_PASSWORD_FILE="$DEMO/password" \
        DBUS_SYSTEM_BUS_ADDRESS=unix:path=/nonexistent QT_QPA_PLATFORM=offscreen \
        dbus-daemon --session --fork --print-address=3 --print-pid=4 \
        3>"$DEMO/$pc/bus" 4>"$DEMO/$pc/bus.pid"
}

# A Plasma PC's kdeglobals holds the whole colour scheme, not just its name.
scheme() { # pc scheme accent
    h=$DEMO/$1/home
    HOME=$h XDG_CONFIG_HOME=$h/.config QT_QPA_PLATFORM=offscreen plasma-apply-colorscheme "$2" >/dev/null 2>&1
    HOME=$h XDG_CONFIG_HOME=$h/.config QT_QPA_PLATFORM=offscreen plasma-apply-colorscheme --accent-color "$3" >/dev/null 2>&1
    rgb=$(printf '%d,%d,%d' "0x$(echo "$3" | cut -c2-3)" "0x$(echo "$3" | cut -c4-5)" "0x$(echo "$3" | cut -c6-7)")
    XDG_CONFIG_HOME=$h/.config kwriteconfig6 --file kdeglobals --group General --key ColorScheme "$2"
    XDG_CONFIG_HOME=$h/.config kwriteconfig6 --file kdeglobals --group General --key AccentColor "$rgb"
}

case "${1:-up}" in
up)
    rm -rf "$DEMO"
    mkdir -p "$DEMO"
    "$SRC/tools/dev-db.sh" start >/dev/null
    psql_admin -c "DROP DATABASE IF EXISTS account_demo" -c "CREATE DATABASE account_demo OWNER account"
    # a throwaway password for a throwaway account, never shown
    head -c 18 /dev/urandom | base64 | tr -d '\n' >"$DEMO/password"
    RAYE_ACCOUNT_DATABASE_URL="postgres://account@localhost/account_demo?host=$pgdir/sock&port=55433" \
        RAYE_ACCOUNT_LISTEN=127.0.0.1:$PORT RAYE_ACCOUNT_LOG=warn \
        "$BIN/raye-account-server" >"$DEMO/server.log" 2>&1 &
    echo $! >"$DEMO/server.pid"
    until curl -sf "$SERVER/healthz" >/dev/null; do sleep 0.2; done

    # PC A, "Bureau": Raye Night, violet accent, French formats, three apps.
    make_pc a Bureau signup "Ana Tremblay"
    cfg=$DEMO/a/home/.config
    scheme a BreezeDark "#7b3cff"
    printf '\n[KDE]\nAnimationDurationFactor=0.5\n\n[Icons]\nTheme=breeze-dark\n' >>"$cfg/kdeglobals"
    printf '[Formats]\nLANG=fr_CA.UTF-8\n\n[Translations]\nLANGUAGE=fr_CA:fr:en_US\n' >"$cfg/plasma-localerc"
    printf '[Layout]\nLayoutList=ca,us\nUse=true\n' >"$cfg/kxkbrc"
    for app in org.mozilla.firefox com.discordapp.Discord org.gimp.GIMP; do
        mkdir -p "$DEMO/a/home/.local/share/flatpak/app/$app/current"
    done

    # PC B, "Portable": light theme, blue accent, one app.
    make_pc b Portable signin ""
    cfg=$DEMO/b/home/.config
    scheme b BreezeLight "#3daee9"
    mkdir -p "$DEMO/b/home/.local/share/flatpak/app/org.mozilla.firefox/current"
    # the Raye eye for the pages, from the theme repo copy made by the caller
    mkdir -p "$DEMO/share/icons/hicolor/256x256/apps"
    [ -f "$ROOT/raye-eye.png" ] && cp "$ROOT/raye-eye.png" "$DEMO/share/icons/hicolor/256x256/apps/raye-eye.png"
    echo "== ready: $SERVER, buses in $DEMO/{a,b}/bus"
    ;;
signup-a)
    call a SignIn true >/dev/null
    wait_signed_in a
    state a
    ;;
signin-b)
    echo "B before: $(grep -E 'ColorScheme|AccentColor' "$DEMO/b/home/.config/kdeglobals" | tr '\n' ' ')"
    call b SignIn false >/dev/null
    wait_signed_in b
    echo "B after:  $(grep -E 'ColorScheme|AccentColor' "$DEMO/b/home/.config/kdeglobals" | tr '\n' ' ')"
    state b
    ;;
call)
    shift
    call "$@"
    ;;
state)
    state "$2"
    ;;
down)
    for pc in a b c; do
        [ -f "$DEMO/$pc/bus.pid" ] && kill "$(cat "$DEMO/$pc/bus.pid")" 2>/dev/null || true
    done
    pkill -x raye-accountd 2>/dev/null || true
    [ -f "$DEMO/server.pid" ] && kill "$(cat "$DEMO/server.pid")" 2>/dev/null || true
    psql_admin -c "DROP DATABASE IF EXISTS account_demo WITH (FORCE)" || true
    ;;
*)
    echo "usage: $0 up|signup-a|signin-b|call <pc> <method> [args]|state <pc>|down" >&2
    exit 2
    ;;
esac
