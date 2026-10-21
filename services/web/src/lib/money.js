// Montants : l'API ne manipule que des centimes entiers (contracts/openapi-payment.yaml).
// On convertit la saisie par manipulation de texte, jamais par un calcul à virgule flottante
// (0.1 + 0.2 !== 0.3 : « 19,99 € » pourrait devenir 1998 centimes).

const AMOUNT_PATTERN = /^(\d{1,7})(?:[.,](\d{1,2}))?$/;
export const MAX_CENTS = 1_000_000; // plafond de l'API : 10 000 € par paiement

/** "12,5" → 1250 ; renvoie null si la saisie n'est pas un montant valide et positif. */
export function parseEuros(input) {
  const match = AMOUNT_PATTERN.exec(String(input).trim().replace(/\s/g, ""));
  if (!match) return null;
  const cents = Number(match[1]) * 100 + Number((match[2] ?? "").padEnd(2, "0"));
  return cents >= 1 && cents <= MAX_CENTS ? cents : null;
}

const formatter = new Intl.NumberFormat("fr-FR", { style: "currency", currency: "EUR" });

/** 150000 → "1 500,00 €" */
export function formatCents(cents) {
  return formatter.format(cents / 100);
}
