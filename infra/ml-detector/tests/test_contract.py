"""Contrat avec le PC IA : le détecteur produit-il encore la forme des exemples de contracts/analyze ?

Compare les champs (et leur imbrication), pas les valeurs : régler le détecteur ne casse rien,
renommer ou supprimer un champ que la gateway lit, si. Changement voulu : relancer
`python -m scripts.contract_examples` et relire le diff (la suite de l'ai-node vérifie l'autre côté).
"""
import json

import pytest

from scripts.contract_examples import CONTRACTS, baseline_pipeline, build_examples, dumps

# Dictionnaires dont les clés sont des données (statuts HTTP, méthodes), pas des champs.
_MAPS = {"statuses", "methods"}

pytestmark = pytest.mark.skipif(not CONTRACTS.is_dir(), reason="contracts/ absent (image Docker : tests hors dépôt)")


def shape(value, path="") -> set[str]:
    if isinstance(value, dict):
        if path.rsplit(".", 1)[-1] in _MAPS:
            return {path + "{}"}
        return {p for k, v in value.items() for p in shape(v, f"{path}.{k}")} or {path + "{}"}
    if isinstance(value, list):
        return {p for v in value for p in shape(v, path + "[]")} or {path + "[]"}
    return {path}


@pytest.fixture(scope="module")
def produced():
    return {name: json.loads(dumps(body)) for name, body in build_examples(baseline_pipeline()).items()}


def test_every_example_is_still_produced(produced):
    assert sorted(produced) == sorted(p.stem for p in CONTRACTS.glob("*.json"))


@pytest.mark.parametrize("name", sorted(p.stem for p in CONTRACTS.glob("*.json")) if CONTRACTS.is_dir() else [])
def test_shape_matches_the_contract(produced, name):
    expected = json.loads((CONTRACTS / f"{name}.json").read_text(encoding="utf-8"))
    missing = shape(expected) - shape(produced[name])
    added = shape(produced[name]) - shape(expected)
    assert not missing and not added, (
        f"forme modifiée — disparus : {sorted(missing)} ; nouveaux : {sorted(added)}. "
        "Si c'est voulu : python -m scripts.contract_examples, puis vérifier la gateway (ai-node).")
