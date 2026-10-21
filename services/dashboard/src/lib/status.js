// États publiés par le watchdog (contracts/openapi-remediation.yaml, schéma Topology) et leur affichage.

export const STATES = {
  up: { label: "OK", dot: "bg-emerald-400", text: "text-emerald-300", stroke: "#34d399", fill: "#064e3b" },
  degraded: { label: "Dégradé", dot: "bg-amber-400", text: "text-amber-300", stroke: "#fbbf24", fill: "#78350f" },
  down: { label: "En panne", dot: "bg-red-500", text: "text-red-300", stroke: "#ef4444", fill: "#7f1d1d" },
  unknown: { label: "Inconnu", dot: "bg-slate-500", text: "text-slate-400", stroke: "#64748b", fill: "#1e293b" },
};

export const styleOf = (state) => STATES[state] ?? STATES.unknown;

/**
 * Verdict global affiché en tête :
 * - « en panne » si la transaction de bout en bout échoue : c'est ce que vit un client ;
 * - « dégradée » si un composant ou un lien n'est pas OK alors que la transaction passe encore ;
 * - « opérationnelle » sinon.
 */
export function overall(topology) {
  if (!topology) return "unknown";
  const endToEnd = topology.links.find((l) => l.source === "smoke-test" && l.target === "bunkerweb");
  if (endToEnd?.state === "down") return "down";
  const all = [...topology.nodes, ...topology.links];
  if (all.some((item) => item.state !== "up")) return "degraded";
  return "up";
}

export const OVERALL_TEXT = {
  up: "Plateforme opérationnelle",
  degraded: "Plateforme dégradée",
  down: "Service indisponible pour les clients",
  unknown: "En attente des premières mesures…",
};
