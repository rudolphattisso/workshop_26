# ADR-DEV-0002 — Paiement synchrone et idempotent

- **Statut** : accepté
- **Date** : 2026-10-20
- **Domaine** : Dev
- **Contrat impacté** : `contracts/openapi-payment.yaml`

## Contexte

La reprise du service se prouve par une **nouvelle transaction fictive réussie** et des **données cohérentes**.
Deux traitements étaient envisagés pour `POST /payments` :

1. **Synchrone** : débit, crédit et statut écrits dans une seule transaction SQL, réponse immédiate.
2. **Deux temps** : enregistrement `PENDING` (réponse 202), puis traitement par un worker.

Pendant un incident (DDoS, conteneur redémarré), un client peut ne pas recevoir la réponse et **réessayer**,
ce qui risque un double débit.

## Décision

- Traitement **synchrone** dans **une transaction SQL unique**. Le paiement est `CAPTURED` ou `REJECTED`,
  jamais dans un état intermédiaire.
- En-tête **`Idempotency-Key` obligatoire**. Une clé déjà traitée renvoie la réponse d'origine (200) sans
  nouveau débit. La même clé avec un corps différent renvoie 409.
- Les paiements refusés sont **enregistrés** (`REJECTED` + motif) pour la traçabilité.
- Montants en **centimes entiers**.

## Conséquences

- ✅ Moins de composants qui peuvent tomber (pas de file ni de worker) : c'est le plus fiable en démo.
- ✅ Le smoke test reste simple : une requête, un statut, pas d'attente.
- ✅ La cohérence reste vérifiable : la somme des soldes ne change pas, et chaque `CAPTURED` a un débit et un crédit.
- ✅ Le rejeu idempotent montre une vraie bonne pratique de résilience applicative.
- ⚠️ Si la base est indisponible, l'API renvoie 503 au lieu de mettre la demande en file. C'est acceptable :
  le client réessaie avec la même clé, et la remédiation rétablit la base.
- ⚠️ La table des clés d'idempotence grossit. C'est négligeable sur la durée d'une démo (purge possible après 24 h).

## Alternatives écartées

- **Deux temps (PENDING → worker)** : montre des paiements qui survivent à un crash, mais ajoute un composant
  à superviser et à remédier, et complique le smoke test. Ce serait une évolution possible après un scénario 100 % fiable.
