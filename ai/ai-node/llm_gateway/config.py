"""Paramètres du llm-gateway, surchargeables par variables d'environnement (docker-compose)."""
from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path


def _env(name: str, default, cast=str):
    value = os.getenv(name)
    return default if value is None or value == "" else cast(value)


@dataclass(frozen=True)
class GatewayConfig:
    # Jeton partagé avec le ml-detector (en-tête Authorization: Bearer <jeton>). Obligatoire.
    token: str = field(default_factory=lambda: _env("LLM_GATEWAY_TOKEN", ""))

    # Ollama (GPU du PC IA). La sortie JSON contrainte par schéma demande Ollama >= 0.5.
    ollama_url: str = field(default_factory=lambda: _env("OLLAMA_URL", "http://ollama:11434"))
    ollama_model: str = field(default_factory=lambda: _env("OLLAMA_MODEL", "qwen2.5:7b-instruct"))
    embed_model: str = field(default_factory=lambda: _env("EMBED_MODEL", "nomic-embed-text"))
    llm_timeout_s: float = field(default_factory=lambda: _env("LLM_TIMEOUT_S", 120.0, float))
    temperature: float = field(default_factory=lambda: _env("LLM_TEMPERATURE", 0.1, float))
    # Taille de contexte en tokens. Ollama est à 4096 par défaut : notre prompt (~4 350) était tronqué.
    num_ctx: int = field(default_factory=lambda: _env("LLM_NUM_CTX", 8192, int))
    # Durée pendant laquelle Ollama garde le modèle en mémoire GPU entre deux analyses.
    keep_alive: str = field(default_factory=lambda: _env("LLM_KEEP_ALIVE", "24h"))

    # RAG : "chroma" (serveur ChromaDB) ou "memory" (index en mémoire, reconstruit au démarrage).
    vector_store: str = field(default_factory=lambda: _env("VECTOR_STORE", "chroma"))
    # "ollama" (modèle d'embedding) ou "hashing" (sans GPU : développement et tests).
    embedder: str = field(default_factory=lambda: _env("EMBEDDER", "ollama"))
    chroma_host: str = field(default_factory=lambda: _env("CHROMA_HOST", "chroma"))
    chroma_port: int = field(default_factory=lambda: _env("CHROMA_PORT", 8000, int))
    collection: str = field(default_factory=lambda: _env("CHROMA_COLLECTION", "soc-knowledge"))
    knowledge_dir: Path = field(default_factory=lambda: Path(_env("KNOWLEDGE_DIR", "knowledge")))
    rag_top_k: int = field(default_factory=lambda: _env("RAG_TOP_K", 4, int))
    rag_max_chars: int = field(default_factory=lambda: _env("RAG_MAX_CHARS", 1500, int))

    # Règles recommandées : un fichier Markdown par analyse, relu puis copié par un humain.
    rules_dir: Path = field(default_factory=lambda: Path(_env("RULES_DIR", "reports")))
    # Identifiants réservés aux règles ModSecurity proposées par l'IA (plage « locale » 1-99 999).
    rule_id_min: int = field(default_factory=lambda: _env("AI_RULE_ID_MIN", 99000, int))
    rule_id_max: int = field(default_factory=lambda: _env("AI_RULE_ID_MAX", 99999, int))

    max_body_bytes: int = field(default_factory=lambda: _env("MAX_BODY_BYTES", 256_000, int))
    # Une règle déjà proposée dans les N dernières heures est citée, pas recopiée.
    recent_rules_hours: int = field(default_factory=lambda: _env("RECENT_RULES_HOURS", 24, int))
    # Consultation des rapports dans un navigateur (/reports, authentification « basic », utilisateur
    # « soc ») : désactivée tant qu'aucun mot de passe n'est défini.
    reports_password: str = field(default_factory=lambda: _env("REPORTS_PASSWORD", ""))
