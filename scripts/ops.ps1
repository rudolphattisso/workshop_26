<#
.SYNOPSIS
  Point d'entrée unique des opérations : lance un playbook Ansible dans un conteneur.

.DESCRIPTION
  Aucun Ansible/Python n'est requis sur le PC Hôte : seul Docker Desktop l'est.
  Le dépôt est monté dans le runner au chemin que le moteur Docker Desktop connaît
  (/run/desktop/mnt/host/<lecteur>/...), ce qui permet à « docker compose » exécuté
  dans le runner de monter correctement les fichiers de configuration du dépôt.

.EXAMPLE
  .\scripts\ops.ps1 deploy
  .\scripts\ops.ps1 verify
  .\scripts\ops.ps1 chaos -e target=auth -e fault=kill
  .\scripts\ops.ps1 restore -e restore_file=payments-20261020T101500Z.dump
#>
# Pas de [Parameter()]/[CmdletBinding()] : sinon PowerShell interprète « -e » comme -ErrorAction.
# Tout ce qui suit le nom du playbook est transmis tel quel à ansible-playbook ($args).
param(
  [ValidateSet('deploy', 'verify', 'backup', 'restore', 'recover', 'chaos', 'ddos_demo', 'reload', 'teardown')]
  [string]$Playbook = 'deploy'
)
$AnsibleArgs = @($args | Where-Object { $_ -ne '-RebuildRunner' })
$RebuildRunner = $args -contains '-RebuildRunner'
$ErrorActionPreference = 'Stop'
$RunnerImage = 'resilience/ops-runner:1.0'
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path

docker info --format '{{.ServerVersion}}' *> $null
if ($LASTEXITCODE -ne 0) { throw "Docker n'est pas joignable : démarrer Docker Desktop puis relancer." }

docker image inspect $RunnerImage *> $null
if ($RebuildRunner -or $LASTEXITCODE -ne 0) {
  Write-Host "==> Construction du runner Ansible ($RunnerImage)" -ForegroundColor Cyan
  docker build -t $RunnerImage (Join-Path $RepoRoot 'ansible')
  if ($LASTEXITCODE -ne 0) { throw "Échec de la construction du runner" }
}

# C:\Users\x\WS  ->  /run/desktop/mnt/host/c/Users/x/WS  (chemin vu par le moteur Docker Desktop)
$drive = $RepoRoot.Substring(0, 1).ToLower()
$DaemonPath = "/run/desktop/mnt/host/$drive" + $RepoRoot.Substring(2).Replace([char]92, [char]47)

$tty = @()
if (-not [Console]::IsOutputRedirected) { $tty = @('-t') }

Write-Host "==> ansible-playbook playbooks/$Playbook.yml $AnsibleArgs" -ForegroundColor Cyan
docker run --rm @tty `
  -v /var/run/docker.sock:/var/run/docker.sock `
  -v "${RepoRoot}:${DaemonPath}" `
  -w "$DaemonPath/ansible" `
  -e PROJECT_DIR=$DaemonPath `
  -e OPS_RUNNER=1 `
  -e ANSIBLE_CONFIG="$DaemonPath/ansible/ansible.cfg" `
  -e ANSIBLE_FORCE_COLOR=1 `
  $RunnerImage "playbooks/$Playbook.yml" @AnsibleArgs
exit $LASTEXITCODE
