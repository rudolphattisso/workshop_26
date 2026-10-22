"""ml-detector — détection d'anomalies sur les journaux du WAF (pôle IA).

Chaîne : LogSource -> parsing -> features -> IsolationForest (score) -> DBSCAN (clusters)
-> ClusterSummary (JSON) -> envoyé plus tard au llm-gateway du PC IA.
Le module ne déclenche AUCUNE action : il mesure et résume, l'opérateur décide.
"""
