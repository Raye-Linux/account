#!/bin/sh
# Throwaway PostgreSQL for the tests and the local demo. Unix socket only,
# no TCP port, trust auth on that socket: never point this at real data.
#   dev-db.sh start | stop | wipe | url
set -e
BIN=$(ls -d /usr/lib/postgresql/*/bin | sort -V | tail -1)
DIR=${RAYE_ACCOUNT_PG:-/build/account/pg}
PORT=${RAYE_ACCOUNT_PG_PORT:-55433}
url="postgres://account@localhost/account?host=$DIR/sock&port=$PORT"

as_pg() { runuser -u postgres -- "$@"; }

case "$1" in
start)
    if [ ! -f "$DIR/data/PG_VERSION" ]; then
        mkdir -p "$DIR/data" "$DIR/sock"
        chown -R postgres:postgres "$DIR"
        as_pg "$BIN/initdb" -D "$DIR/data" -U postgres -A trust -E UTF8 --locale=C.UTF-8 >/dev/null
        cat >>"$DIR/data/postgresql.conf" <<CONF
listen_addresses = ''
unix_socket_directories = '$DIR/sock'
port = $PORT
shared_buffers = 32MB
fsync = off
synchronous_commit = off
full_page_writes = off
CONF
    fi
    as_pg "$BIN/pg_ctl" -D "$DIR/data" status >/dev/null 2>&1 ||
        as_pg "$BIN/pg_ctl" -D "$DIR/data" -l "$DIR/log" -w start >/dev/null
    as_pg "$BIN/psql" -h "$DIR/sock" -p "$PORT" -U postgres -qtAc \
        "SELECT 1 FROM pg_roles WHERE rolname='account'" | grep -q 1 ||
        as_pg "$BIN/psql" -h "$DIR/sock" -p "$PORT" -U postgres -q \
            -c "CREATE ROLE account LOGIN CREATEDB" -c "CREATE DATABASE account OWNER account"
    echo "$url"
    ;;
stop)
    as_pg "$BIN/pg_ctl" -D "$DIR/data" -w stop >/dev/null
    ;;
wipe)
    as_pg "$BIN/pg_ctl" -D "$DIR/data" -w stop >/dev/null 2>&1 || true
    rm -rf "$DIR"
    ;;
url)
    echo "$url"
    ;;
*)
    echo "usage: $0 start|stop|wipe|url" >&2
    exit 2
    ;;
esac
