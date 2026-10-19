# attack/ — banc d'attaque de démonstration (pôle Cybersécurité)

> **Périmètre strict.** À exécuter **uniquement** depuis le PC Attaquant, **contre le PC Hôte
> de votre propre consortium**. Jamais contre les réseaux du campus, un autre groupe, un
> équipement tiers ou un service accessible sur Internet (cahier des charges, §9). Tout est
> fictif. Les outils sont volontairement simples et à débit modéré : leur but est de rendre
> une attaque **observable** par la chaîne de détection, pas de nuire.

## Prérequis
- `python3` (bibliothèque standard uniquement, rien à installer).
- L'IP du PC Hôte sur le hotspot (ex. `192.168.137.1`).

## Utilisation

```bash
# Transaction légitime (preuve que le service répond)
DEMO_PASSWORD=<mot de passe alice> python3 attack.py probe --target http://192.168.137.1

# Attaque XSS / injection SQL (le WAF BunkerWeb doit renvoyer 403)
python3 attack.py xss  --target http://192.168.137.1

# DDoS applicatif contrôlé (déclenche limitation de débit puis auto-ban)
python3 attack.py ddos --target http://192.168.137.1 --workers 25 --duration 25

# Démonstration complète enchaînée
DEMO_PASSWORD=<mot de passe alice> ./run_demo.sh http://192.168.137.1
```

Test local sur le PC Hôte (le WAF n'accepte que certains noms d'hôte) :
```bash
./run_demo.sh http://127.0.0.1 localhost
```

Le mot de passe de l'utilisateur fictif `alice` est dans `secrets/demo_user_password` sur le PC Hôte.

## Ce que la démo doit montrer

| Étape | Attendu côté défense |
|---|---|
| XSS / SQLi | BunkerWeb (ModSecurity/OWASP CRS) renvoie **403** ; Wazuh lève les règles 100101/100102 ; panneau « Sécurité » de Grafana |
| DDoS | BunkerWeb **limite (429)** puis **bannit (403)** l'IP source ; Wazuh lève la règle DDoS ; la **transaction synthétique interne reste verte** |
| Après | La reprise automatique et/ou le bannissement ont préservé le service ; nouvelle transaction interne OK |

## Démo « avant / après » du WAF (XSS)
Pour montrer la valeur du WAF, basculer ModSecurity en observation puis en blocage :
```powershell
# Sur le PC Hôte
# 1) Observation : les XSS PASSENT mais sont journalisées
(Get-Content .env) -replace 'WAF_RULE_ENGINE=On','WAF_RULE_ENGINE=DetectionOnly' | Set-Content .env
.\scripts\ops.ps1 reload
#   -> rejouer attack.py xss : les charges passent (200), Wazuh/Loki les voient
# 2) Blocage : les XSS sont rejetées (403)
(Get-Content .env) -replace 'WAF_RULE_ENGINE=DetectionOnly','WAF_RULE_ENGINE=On' | Set-Content .env
.\scripts\ops.ps1 reload
```

## Limite connue (à présenter au jury)
Sur Docker Desktop, le trafic externe est traduit (NAT) vers une IP unique : le bannissement
par IP touche donc aussi les clients légitimes partageant cette IP. La **preuve de continuité**
repose sur la transaction synthétique interne (source distincte) et sur la reprise automatique,
pas sur l'accès de l'attaquant lui-même.
