#!/bin/sh
# Runs once when the Postgres volume is first created (docker-entrypoint-initdb.d).
# Creates ONE database owned by ONE least-privilege role. The superuser password is never given to the app.
#   DB_NAME / DB_USER / DB_PASSWORD come from the container environment.
set -eu
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname postgres <<SQL
CREATE ROLE "$DB_USER" LOGIN PASSWORD '$DB_PASSWORD' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS CONNECTION LIMIT 80;
CREATE DATABASE "$DB_NAME" OWNER "$DB_USER";
REVOKE ALL ON DATABASE "$DB_NAME" FROM PUBLIC;
REVOKE ALL ON DATABASE postgres FROM PUBLIC;
REVOKE ALL ON DATABASE template1 FROM PUBLIC;
ALTER ROLE "$DB_USER" SET statement_timeout = '15s';
ALTER ROLE "$DB_USER" SET idle_in_transaction_session_timeout = '30s';
ALTER ROLE "$DB_USER" SET lock_timeout = '5s';
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$DB_NAME" <<SQL
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT ALL ON SCHEMA public TO "$DB_USER";
SQL
