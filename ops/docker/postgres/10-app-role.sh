#!/bin/sh
# Creates the least-privilege runtime role used by the API (subject to RLS; it never owns tables).
# Runs once on a fresh volume (docker-entrypoint-initdb.d). Values come from the environment and
# are passed as psql variables, so they're quoted safely, with no string interpolation into SQL.
set -eu
: "${GUARDHUB_APP_DB_USER:?GUARDHUB_APP_DB_USER is required}"
: "${GUARDHUB_APP_DB_PASSWORD:?GUARDHUB_APP_DB_PASSWORD is required}"

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v app_user="$GUARDHUB_APP_DB_USER" -v app_pw="$GUARDHUB_APP_DB_PASSWORD" <<'EOSQL'
CREATE ROLE :"app_user" LOGIN PASSWORD :'app_pw' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
EOSQL
