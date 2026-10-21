#!/usr/bin/env bash
# Équivalent Linux / WSL / Git Bash de scripts/ops.ps1.
#   ./scripts/ops.sh deploy
#   ./scripts/ops.sh chaos -e target=auth
set -euo pipefail
PLAYBOOK="${1:-deploy}"; shift || true
RUNNER_IMAGE="resilience/ops-runner:1.0"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

case "$PLAYBOOK" in
  deploy|verify|backup|restore|recover|chaos|ddos_demo|reload|teardown) ;;
  *) echo "usage: $0 {deploy|verify|backup|restore|recover|chaos|ddos_demo|reload|teardown} [args ansible]" >&2; exit 2 ;;
esac

docker info >/dev/null 2>&1 || { echo "Docker n'est pas joignable" >&2; exit 1; }
if [[ "${REBUILD_RUNNER:-0}" == 1 ]] || ! docker image inspect "$RUNNER_IMAGE" >/dev/null 2>&1; then
  docker build -t "$RUNNER_IMAGE" "$REPO_ROOT/ansible"
fi

# Chemin du dépôt tel que le moteur Docker le voit
SRC="$REPO_ROOT"; DAEMON_PATH="$REPO_ROOT"
if command -v cygpath >/dev/null 2>&1; then          # Git Bash sous Windows (Docker Desktop)
  SRC="$(cygpath -w "$REPO_ROOT")"
  DAEMON_PATH="/run/desktop/mnt/host/$(cygpath -u "$REPO_ROOT" | sed -E 's#^/([a-zA-Z])/#\L\1/#')"
elif [[ "$REPO_ROOT" == /mnt/[a-z]/* ]] && docker info 2>/dev/null | grep -q "Docker Desktop"; then
  DAEMON_PATH="/run/desktop/mnt/host/${REPO_ROOT#/mnt/}"   # WSL + Docker Desktop
fi

TTY=(); [[ -t 1 ]] && TTY=(-t)
export MSYS_NO_PATHCONV=1
exec docker run --rm "${TTY[@]}" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$SRC:$DAEMON_PATH" \
  -w "$DAEMON_PATH/ansible" \
  -e PROJECT_DIR="$DAEMON_PATH" \
  -e OPS_RUNNER=1 \
  -e ANSIBLE_CONFIG="$DAEMON_PATH/ansible/ansible.cfg" \
  -e ANSIBLE_FORCE_COLOR=1 \
  "$RUNNER_IMAGE" "playbooks/$PLAYBOOK.yml" "$@"
