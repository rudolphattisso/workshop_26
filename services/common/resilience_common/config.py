"""Lecture de la configuration sensible : secrets et URL de la base de données.

Convention `<NOM>_FILE` (celle des images officielles postgres, grafana…) : en déploiement, la plateforme
monte chaque secret en fichier dans `/run/secrets/<nom>` (Docker secrets, alimentés par Vault) et nous
indique son chemin dans `<NOM>_FILE`. Le secret n'apparaît donc jamais dans `docker inspect` ni dans
l'environnement du processus. En développement local, la variable `<NOM>` suffit (services/.env).
"""

import os
from urllib.parse import quote


class MissingSecret(Exception):
    pass


def secret(name: str, required: bool = True) -> str | None:
    """Valeur du secret `name` : fichier désigné par `<name>_FILE` en priorité, sinon variable `<name>`."""
    path = os.getenv(f"{name}_FILE")
    if path:
        with open(path, encoding="utf-8") as f:
            # Un fichier édité à la main finit souvent par un saut de ligne, parfois Windows (\r\n).
            return f.read().strip()
    value = os.getenv(name)
    if value is None and required:
        raise MissingSecret(f"{name} ou {name}_FILE doit être défini")
    return value


def database_url() -> str:
    """URL SQLAlchemy de la base du service.

    - `DATABASE_URL` si défini (développement local, tests) ;
    - sinon assemblée depuis `DB_HOST`, `DB_PORT` (5432), `DB_NAME`, `DB_USER` et le secret `DB_PASSWORD`
      (donc `DB_PASSWORD_FILE` en déploiement) : c'est le format fourni par l'Infra.
    """
    url = os.getenv("DATABASE_URL")
    if url:
        return url
    password = quote(secret("DB_PASSWORD"), safe="")  # un mot de passe généré peut contenir @, / ou :
    return (
        f"postgresql+psycopg://{os.environ['DB_USER']}:{password}"
        f"@{os.environ['DB_HOST']}:{os.getenv('DB_PORT', '5432')}/{os.environ['DB_NAME']}"
    )
