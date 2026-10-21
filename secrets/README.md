# secrets/

Dossier **non versionné** (voir `.gitignore`). Chaque fichier contient un secret, sans
retour à la ligne, monté dans les conteneurs en *Docker secret* (`/run/secrets/<nom>`).

Les fichiers manquants sont générés aléatoirement par `scripts/ops.ps1 deploy`
(tâche `ansible/tasks/secrets.yml`) ; les fichiers existants ne sont jamais écrasés.

| Fichier | Utilisé par |
|---|---|
| `postgres_password` | super-utilisateur PostgreSQL `payments_admin` |
| `payment_db_password` / `auth_db_password` / `exporter_db_password` | rôles applicatifs à moindre privilège |
| `jwt_secret` | signature des jetons (auth, payment-api) |
| `demo_user_password` | compte fictif `alice` (démo) |
| `probe_user_password` | compte `synthetic-probe` (sonde de transaction) |
| `remediation_token` | authentification Alertmanager -> moteur de remédiation |
| `grafana_admin_password` | compte `admin` de Grafana |

Intégration SOPS/Vault (pôle cyber) : ce dossier peut être alimenté par
`sops -d secrets.enc.yaml` ou par un agent Vault — le reste de la chaîne est inchangé.
