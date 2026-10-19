#!/usr/bin/env bash
# Démonstration d'attaque + reprise — à lancer depuis le PC Attaquant.
#   ./run_demo.sh http://192.168.137.1
# Test local (sur le PC Hôte) : ./run_demo.sh http://127.0.0.1 localhost
set -u
TARGET="${1:-http://192.168.137.1}"
HOSTH="${2:-}"
HOPT=""; [ -n "$HOSTH" ] && HOPT="--host-header $HOSTH"
DIR="$(cd "$(dirname "$0")" && pwd)"
PY="python3"; command -v python3 >/dev/null || PY="python"

echo "############################################################"
echo "#  PROJECT RESILIENCE-ALPHA — démonstration (cible $TARGET)"
echo "#  À regarder en parallèle :"
echo "#   - Grafana  http://127.0.0.1:3000  (dashboard Resilience-Alpha, section Sécurité)"
echo "#   - Wazuh    https://127.0.0.1:8443  (Threat Hunting / alertes)"
echo "############################################################"

echo; echo "### 1. État initial : une transaction légitime passe"
$PY "$DIR/attack.py" probe --target "$TARGET" $HOPT --password "${DEMO_PASSWORD:-}"

echo; echo "### 2. Attaque XSS / injection (le WAF doit bloquer)"
$PY "$DIR/attack.py" xss --target "$TARGET" $HOPT

echo; echo "### 3. DDoS applicatif contrôlé (limitation de débit puis bannissement auto)"
$PY "$DIR/attack.py" ddos --target "$TARGET" $HOPT --workers 25 --duration 25

echo; echo "### 4. Après l'attaque"
echo "  - L'attaquant est maintenant limité/banni par le WAF (403/429)."
echo "  - La transaction SYNTHÉTIQUE interne reste verte dans Grafana : le service tient."
echo "  - Wazuh a journalisé XSS + DDoS (règles 1001xx) ; BunkerWeb a journalisé le bannissement."
echo "  - Nouvelle transaction légitime depuis l'attaquant (peut être 403 si l'IP est bannie) :"
$PY "$DIR/attack.py" probe --target "$TARGET" $HOPT --password "${DEMO_PASSWORD:-}"
echo
echo "Note : en lab (Docker Desktop), tout le trafic externe est vu sous une même IP ;"
echo "le bannissement touche donc aussi les clients légitimes partageant cette IP. La preuve"
echo "de continuité est la transaction synthétique interne (source distincte) et la reprise auto."
