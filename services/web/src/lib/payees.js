// Bénéficiaires fictifs de démonstration. Un client ne peut pas lister les comptes des autres (cloisonnement de
// l'API) : leurs identifiants sont donc publiés ici. Ce sont les UUID déterministes calculés par
// resilience_common.identity.account_id(<nom>), identiques dans payment-api.
export const PAYEES = [
  { username: "cafe-demo", label: "Café Démo", kind: "Marchand", accountId: "f8b1b7d0-0b7b-5f1c-b711-68e4ca29b2a3" },
  { username: "alice", label: "Alice", kind: "Particulier", accountId: "4e7d5e48-18f1-541e-993c-9271c064546e" },
  { username: "bob", label: "Bob", kind: "Particulier", accountId: "26220b60-c4d3-5bae-ba80-569ef4417b50" },
];

export function payeeName(accountId) {
  return PAYEES.find((p) => p.accountId === accountId)?.label ?? "Compte externe";
}
