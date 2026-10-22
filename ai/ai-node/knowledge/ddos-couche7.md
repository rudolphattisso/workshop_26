# Déni de service applicatif (couche 7) : reconnaître et répondre

## Formes qui échappent à un WAF qui raisonne par IP

- **Botnet distribué** : des centaines ou milliers d'IP, chacune sous les seuils (quelques requêtes par seconde), réponses 200. Signes : beaucoup d'IP nouvelles qui répètent le même endpoint, sans parcours utilisateur (pas de connexion, pas de paiement, pas de ressources annexes), user-agents de navigateurs variés mais usurpés, montée des 503.
  - Réponse : défi anti-bot (JavaScript) sur les pages visées ; mise en cache de la page d'accueil ; réputation d'IP (DNSBL) ; contacter l'hébergeur ou le fournisseur anti-DDoS si le volume sature le lien.
- **Contournement de cache** : paramètres aléatoires (`?_=123456`, `?v=...`) pour que chaque requête atteigne l'application.
  - Réponse : ignorer les paramètres inconnus dans la clé de cache ; refuser le paramètre anti-cache sans Referer sur les pages publiques ; défi anti-bot.
- **Requêtes coûteuses** : peu de requêtes mais très chères (export massif, recherche complexe, pagination énorme), souvent depuis des comptes connectés. Signes : réponses volumineuses, 503 et latence alors que le débit reste faible.
  - Réponse : plafonner côté application (pagination maximale) ; règle WAF sur le paramètre abusif ; limitation de débit sur l'endpoint ; examiner et suspendre les comptes concernés.

## Distinguer d'un trafic légitime

- **Afflux promotionnel** : beaucoup d'IP nouvelles, mais avec un vrai parcours (accueil avec paramètres marketing, connexion, paiements, pages variées), un Referer, des user-agents cohérents. Verdict : faux positif probable. Ne pas bloquer.
- **NAT d'entreprise banni par le WAF** : une IP au passé sain (paiements réussis, plusieurs navigateurs) qui ne reçoit plus que des 403. Verdict : bannissement collatéral probable. Recommander à l'opérateur de vérifier le bannissement, jamais une liste blanche automatique.
- **Sondes de supervision** : automatisées par nature, IP stables et connues. Les exclure de toute règle.

## Mesurer l'impact

- Part de 503 dans le groupe et chez les sondes : le service est-il dégradé pour les clients ?
- Les clients légitimes touchés par la saturation reçoivent aussi des 503 : ils ne sont pas des attaquants.
