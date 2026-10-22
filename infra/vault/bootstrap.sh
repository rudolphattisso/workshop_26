#!/bin/sh
# Sidecar « vault-unsealer » : initialise, descelle et configure Vault, puis veille.
#   1. 1er démarrage : vault operator init -> clés + root token stockés dans /vault/keys (volume dédié)
#   2. à chaque (re)démarrage de Vault : descellement automatique -> reprise SANS humain
#   3. configuration idempotente : moteur KV v2 « resilience/ », audit, politique + jeton « ansible-ops »
# COMPROMIS DE LAB (documenté dans docs/INFRA.md) : les clés de descellement sont stockées à côté
# de Vault. En production : auto-unseal via KMS/HSM, ou clés Shamir réparties entre opérateurs.
set -u
export VAULT_ADDR="${VAULT_ADDR:-http://vault:8200}"
KEYS=/vault/keys
mkdir -p "$KEYS"; chmod 700 "$KEYS"
READY="$KEYS/.ready"
rm -f "$READY"

log() { echo "{\"ts\":\"$(date -u +%Y-%m-%dT%H:%M:%SZ)\",\"service\":\"vault-unsealer\",\"level\":\"info\",\"msg\":\"$1\"}"; }

wait_api() { until vault status -format=json >/dev/null 2>&1 || [ $? -eq 2 ]; do sleep 2; done; }

json_field() { sed -n "s/.*\"$1\": *\"\([^\"]*\)\".*/\1/p" | head -1; }

bootstrap_config() {
  export VAULT_TOKEN="$(cat $KEYS/root_token)"
  vault secrets list -format=json | grep -q '"resilience/"' || { vault secrets enable -path=resilience -version=2 kv >/dev/null && log "kv v2 resilience/ active"; }
  vault audit list -format=json 2>/dev/null | grep -q '"stdout/"' || { vault audit enable -path=stdout file file_path=stdout >/dev/null && log "audit stdout actif"; }
  vault policy write ansible-ops - >/dev/null <<'POL'
# Jeton d'exploitation (Ansible) : lecture/écriture des secrets de la plateforme UNIQUEMENT.
path "resilience/data/*"     { capabilities = ["create", "update", "read"] }
path "resilience/metadata/*" { capabilities = ["read", "list"] }
path "sys/health"            { capabilities = ["read"] }
POL
  vault policy write resilience-readonly - >/dev/null <<'POL'
# Lecture seule des secrets (futurs consommateurs : Vault Agent / services).
path "resilience/data/*"     { capabilities = ["read"] }
path "resilience/metadata/*" { capabilities = ["read", "list"] }
POL
  if [ ! -s "$KEYS/ansible_token" ]; then
    vault token create -policy=ansible-ops -orphan -period=8760h -display-name=ansible-ops -format=json \
      | json_field client_token > "$KEYS/ansible_token"
    chmod 600 "$KEYS/ansible_token"; log "jeton ansible-ops cree"
  fi
  unset VAULT_TOKEN
}

wait_api
while true; do
  STATUS="$(vault status -format=json 2>/dev/null)"
  if echo "$STATUS" | grep -q '"initialized": *false'; then
    log "initialisation de Vault"
    vault operator init -key-shares=1 -key-threshold=1 -format=json > "$KEYS/init.json" || { sleep 5; continue; }
    chmod 600 "$KEYS/init.json"
    sed -n 's/.*"unseal_keys_b64": *\[ *"\([^"]*\)".*/\1/p' "$KEYS/init.json" | head -1 > "$KEYS/unseal_key"
    # le format JSON de operator init est multiligne : repli robuste
    [ -s "$KEYS/unseal_key" ] || tr -d '\n ' < "$KEYS/init.json" | sed -n 's/.*"unseal_keys_b64":\["\([^"]*\)".*/\1/p' > "$KEYS/unseal_key"
    json_field root_token < "$KEYS/init.json" > "$KEYS/root_token"
    chmod 600 "$KEYS/unseal_key" "$KEYS/root_token"
    STATUS="$(vault status -format=json 2>/dev/null)"
  fi
  if echo "$STATUS" | grep -q '"sealed": *true'; then
    if [ -s "$KEYS/unseal_key" ]; then
      vault operator unseal "$(cat $KEYS/unseal_key)" >/dev/null 2>&1 && log "Vault descelle automatiquement"
      rm -f "$READY"
    else
      log "Vault scelle et aucune cle disponible"
    fi
  fi
  if echo "$STATUS" | grep -q '"sealed": *false'; then
    if [ ! -f "$READY" ]; then bootstrap_config && touch "$READY" && log "Vault pret"; fi
  fi
  sleep 5
done
