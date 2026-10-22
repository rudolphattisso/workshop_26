import pytest

from resilience_common.config import MissingSecret, database_url, secret


def test_secret_file_wins_over_variable_and_is_stripped(tmp_path, monkeypatch):
    path = tmp_path / "demo_user_password"
    path.write_text("from-file-secret\r\n", encoding="utf-8")
    monkeypatch.setenv("DEMO_PASSWORD", "from-env")
    monkeypatch.setenv("DEMO_PASSWORD_FILE", str(path))
    assert secret("DEMO_PASSWORD") == "from-file-secret"


def test_secret_falls_back_to_variable(monkeypatch):
    monkeypatch.delenv("DEMO_PASSWORD_FILE", raising=False)
    monkeypatch.setenv("DEMO_PASSWORD", "from-env")
    assert secret("DEMO_PASSWORD") == "from-env"


def test_missing_secret(monkeypatch):
    monkeypatch.delenv("DEMO_PASSWORD_FILE", raising=False)
    monkeypatch.delenv("DEMO_PASSWORD", raising=False)
    assert secret("DEMO_PASSWORD", required=False) is None
    with pytest.raises(MissingSecret, match="DEMO_PASSWORD"):
        secret("DEMO_PASSWORD")


def test_missing_secret_file_fails_loudly(monkeypatch, tmp_path):
    # Un secret mal monté doit arrêter le conteneur au démarrage, pas être remplacé par une valeur vide.
    monkeypatch.setenv("DEMO_PASSWORD_FILE", str(tmp_path / "absent"))
    with pytest.raises(FileNotFoundError):
        secret("DEMO_PASSWORD")


def test_database_url_prefers_explicit_url(monkeypatch):
    monkeypatch.setenv("DATABASE_URL", "postgresql+psycopg://u:p@localhost:5433/payment")
    assert database_url() == "postgresql+psycopg://u:p@localhost:5433/payment"


def test_database_url_is_built_from_infra_variables(tmp_path, monkeypatch):
    path = tmp_path / "payment_db_password"
    path.write_text("p@ss/w:rd\n", encoding="utf-8")
    monkeypatch.delenv("DATABASE_URL", raising=False)
    monkeypatch.delenv("DB_PORT", raising=False)
    monkeypatch.setenv("DB_HOST", "postgres")
    monkeypatch.setenv("DB_NAME", "payment")
    monkeypatch.setenv("DB_USER", "payment_api")
    monkeypatch.setenv("DB_PASSWORD_FILE", str(path))
    # Caractères spéciaux encodés : sinon « @ » et « / » casseraient l'URL.
    assert database_url() == "postgresql+psycopg://payment_api:p%40ss%2Fw%3Ard@postgres:5432/payment"
