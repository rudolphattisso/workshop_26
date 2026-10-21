#!/bin/sh
# Exécuté UNE SEULE FOIS par l'image postgres, au premier démarrage sur un volume vide.
# Crée le schéma, des rôles applicatifs à moindre privilège et les comptes fictifs.
# Les mots de passe proviennent des secrets Docker (/run/secrets), jamais du dépôt.
set -eu

secret() { tr -d '\r\n' < "/run/secrets/$1"; }

psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  -v payment_pw="$(secret payment_db_password)" \
  -v auth_pw="$(secret auth_db_password)" \
  -v exporter_pw="$(secret exporter_db_password)" \
  -v alice_pw="$(secret demo_user_password)" \
  -v probe_pw="$(secret probe_user_password)" <<'SQL'
CREATE EXTENSION IF NOT EXISTS pgcrypto;

CREATE TABLE users (
    id            SERIAL PRIMARY KEY,
    username      TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL DEFAULT 'customer',
    active        BOOLEAN NOT NULL DEFAULT TRUE,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE transactions (
    id          UUID PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id),
    amount      NUMERIC(12,2) NOT NULL CHECK (amount > 0),
    currency    CHAR(3) NOT NULL,
    merchant    TEXT NOT NULL,
    reference   TEXT,
    status      TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX transactions_user_created_idx ON transactions (user_id, created_at DESC);

-- Comptes fictifs : alice (démo jury), synthetic-probe (sonde de transaction)
INSERT INTO users (username, password_hash, role) VALUES
    ('alice',           crypt(:'alice_pw', gen_salt('bf', 10)), 'customer'),
    ('synthetic-probe', crypt(:'probe_pw', gen_salt('bf', 10)), 'probe');

-- Rôles applicatifs : chaque service n'a que ce dont il a besoin
REVOKE ALL ON SCHEMA public FROM PUBLIC;
CREATE ROLE payment_svc LOGIN PASSWORD :'payment_pw';
CREATE ROLE auth_svc    LOGIN PASSWORD :'auth_pw';
CREATE ROLE exporter    LOGIN PASSWORD :'exporter_pw';
GRANT USAGE ON SCHEMA public TO payment_svc, auth_svc;
GRANT SELECT, INSERT ON transactions TO payment_svc;
GRANT SELECT ON users TO auth_svc;
GRANT pg_monitor TO exporter;
SQL
echo "init: schéma et rôles créés"
