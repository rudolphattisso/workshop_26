#!/bin/sh
set -eu
secret() { tr -d '\r\n' < "/run/secrets/$1"; }

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v payment_pw="$(secret payment_db_password)" \
  -v auth_pw="$(secret auth_db_password)" \
  -v exporter_pw="$(secret exporter_db_password)" <<'SQL'
CREATE ROLE payment_api  LOGIN PASSWORD :'payment_pw';
CREATE ROLE auth_service LOGIN PASSWORD :'auth_pw';
CREATE ROLE exporter     LOGIN PASSWORD :'exporter_pw';
GRANT pg_monitor TO exporter;
CREATE DATABASE payment OWNER payment_api;
CREATE DATABASE auth    OWNER auth_service;
SQL
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname payment -c "GRANT ALL ON SCHEMA public TO payment_api; GRANT CONNECT ON DATABASE payment TO exporter;"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname auth    -c "GRANT ALL ON SCHEMA public TO auth_service; GRANT CONNECT ON DATABASE auth TO exporter;"
echo "init: bases payment/auth et rôles créés (schéma : Alembic ; comptes : app.seed)"
