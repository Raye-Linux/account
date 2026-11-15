#!/bin/sh
# Renders one Settings page of the demo under Xvfb and saves a PNG.
#   shot.sh <pc> <page.qml> <out.png> [fr] [WxH]
set -eu
ROOT=${ROOT:-/build/account}
DEMO=$ROOT/demo
pc=$1 page=$2 out=$3 lang=${4:-en} size=${5:-1280x800}
display=${DISPLAY_NUMBER:-163}
Xvfb ":$display" -screen 0 "${size}x24" >/dev/null 2>&1 &
xvfb=$!
trap 'kill $xvfb $app 2>/dev/null || true' EXIT
sleep 1
if [ "$lang" = fr ]; then L=fr_CA.UTF-8 LG=fr; else L=en_US.UTF-8 LG=en; fi
home=$DEMO/$pc/home
DISPLAY=":$display" HOME="$home" XDG_CONFIG_HOME="$home/.config" XDG_RUNTIME_DIR="$DEMO/$pc/run" \
    DBUS_SESSION_BUS_ADDRESS=$(cat "$DEMO/$pc/bus") LANG=$L LANGUAGE=$LG \
    RAYE_ACCOUNT_PREVIEW=1 QT_QUICK_BACKEND=${QUICK_BACKEND:-software} QML_IMPORT_PATH=$ROOT/qml-build/qml \
    RAYE_SETTINGS_LAYOUT=$ROOT/settings/data/layout.json XDG_DATA_DIRS=$DEMO/share:$ROOT/settings/build:/usr/share \
    QT_QPA_PLATFORMTHEME=kde \
    "$ROOT/settings/build/bin/raye-settings" --preview "$page" >"$DEMO/$pc/settings.log" 2>&1 &
app=$!
sleep "${WAIT:-6}"
DISPLAY=":$display" import -window root "$out"
