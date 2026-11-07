#!/usr/bin/env bash
# Apply all migrations to a throwaway Postgres cluster and run the RLS/RPC tests.
# Usage: scripts/test-db.sh            (uses a temp cluster; needs initdb/pg_ctl on PATH or PG_BIN)
#        DATABASE_URL=postgres://... scripts/test-db.sh   (uses an existing EMPTY database)
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
PG_BIN="${PG_BIN:-$(ls -d /usr/lib/postgresql/*/bin 2>/dev/null | sort -V | tail -1)}"
export PATH="$PG_BIN:$PATH"

if [[ -z "${DATABASE_URL:-}" ]]; then
  TMP="$(mktemp -d)"
  RUN_AS=()
  if [[ "$(id -u)" == "0" ]]; then
    chown postgres "$TMP"
    RUN_AS=(sudo -u postgres)
    command -v sudo >/dev/null || RUN_AS=(su postgres -s /bin/bash -c)
  fi
  run() { if [[ ${#RUN_AS[@]} -eq 0 ]]; then "$@"; elif [[ "${RUN_AS[0]}" == "su" ]]; then "${RUN_AS[@]}" "$(printf '%q ' "$@")"; else "${RUN_AS[@]}" "$@"; fi; }
  run "$PG_BIN/initdb" -D "$TMP/data" -U postgres -A trust >/dev/null
  run "$PG_BIN/pg_ctl" -D "$TMP/data" -o "-p 54329 -k $TMP -c listen_addresses=''" -l "$TMP/log" -w start >/dev/null
  trap 'run "$PG_BIN/pg_ctl" -D "$TMP/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$TMP"' EXIT
  DATABASE_URL="postgresql://postgres@/postgres?host=$TMP&port=54329"
fi

psql_run() { psql "$DATABASE_URL" -v ON_ERROR_STOP=1 -q -X "$@"; }
psql_run -f "$ROOT/supabase/tests/00_supabase_stub.sql"
for f in "$ROOT"/supabase/migrations/*.sql; do
  echo "migrate: $(basename "$f")"
  psql_run -f "$f"
done
psql_run -o /dev/null -f "$ROOT/supabase/tests/10_rls_test.sql"
