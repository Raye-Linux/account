#!/bin/sh
# Stands in for the person at the browser in the headless demo: opens the
# sign-in page the PC asked for, fills it in like they would, and follows
# the redirect back to the PC. Never used outside tests.
#   DEMO_ACTION=signup|signin DEMO_EMAIL DEMO_NAME DEMO_PASSWORD_FILE
set -eu
url=$1
jar=$(mktemp)
page=$(curl -sf -c "$jar" "$url")
field() { printf '%s' "$page" | sed -n "s/.*name=\"$1\" value=\"\([^\"]*\)\".*/\1/p" | sed 's/&amp;/\&/g'; }
base=${url%%/oauth/*}
loc=$(curl -sf -o /dev/null -w '%{redirect_url}' -b "$jar" \
    --data-urlencode "action=${DEMO_ACTION}" \
    --data-urlencode "email=${DEMO_EMAIL}" \
    --data-urlencode "password@${DEMO_PASSWORD_FILE}" \
    --data-urlencode "display_name=${DEMO_NAME:-}" \
    --data-urlencode "redirect_uri=$(field redirect_uri)" \
    --data-urlencode "state=$(field state)" \
    --data-urlencode "code_challenge=$(field code_challenge)" \
    --data-urlencode "ts=$(field ts)" \
    --data-urlencode "csrf=$(field csrf)" \
    "$base/oauth/authorize")
rm -f "$jar"
case "$loc" in
http://127.0.0.1:*/callback\?*) curl -sf -o /dev/null "$loc" ;;
*) echo "stand-in browser: sign-in refused" >&2; exit 1 ;;
esac
