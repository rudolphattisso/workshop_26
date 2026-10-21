#!/bin/sh
# Démarrage de payment-api : schéma à jour, comptes de démo présents, puis serveur.
# Tout est idempotent : un conteneur recréé par la remédiation repart sans intervention.
set -e

# La base peut redémarrer en même temps que nous (remédiation, docker compose up) : on l'attend un peu.
attempt=1
until alembic upgrade head; do
  if [ "$attempt" -ge 30 ]; then
    echo '{"level":"ERROR","service":"payment-api","event":"migration_failed"}'
    exit 1
  fi
  attempt=$((attempt + 1))
  sleep 2
done

python -m app.seed

# exec : uvicorn devient le PID 1 et reçoit directement les signaux d'arrêt de Docker.
exec uvicorn app.main:app --host 0.0.0.0 --port 8000
