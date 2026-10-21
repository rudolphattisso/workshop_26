import { useState } from "react";
import { createPayment } from "../lib/api.js";
import { formatCents, parseEuros } from "../lib/money.js";
import { PAYEES } from "../lib/payees.js";

const REJECTIONS = {
  INSUFFICIENT_FUNDS: "Solde insuffisant",
  SAME_ACCOUNT: "Impossible de vous payer vous-même",
  UNKNOWN_DESTINATION: "Bénéficiaire inconnu",
};

const newKey = () => crypto.randomUUID();

export default function PaymentForm({ token, account, onDone, onError }) {
  const payees = PAYEES.filter((p) => p.accountId !== account.id);
  const [to, setTo] = useState(payees[0].accountId);
  const [amount, setAmount] = useState("");
  const [label, setLabel] = useState("");
  const [pending, setPending] = useState(false);
  const [result, setResult] = useState(null);
  // Une clé d'idempotence par paiement : conservée si l'envoi échoue (réessayer ne débite pas deux fois),
  // renouvelée dès que l'API a donné une réponse définitive.
  const [idempotencyKey, setIdempotencyKey] = useState(newKey);

  const cents = parseEuros(amount);

  async function submit(event) {
    event.preventDefault();
    setPending(true);
    setResult(null);
    try {
      const { status, data } = await createPayment(token, idempotencyKey, {
        from_account_id: account.id,
        to_account_id: to,
        amount_cents: cents,
        ...(label.trim() ? { label: label.trim() } : {}),
      });
      setIdempotencyKey(newKey());
      if (data.status === "CAPTURED") {
        const text =
          status === 200
            ? "Paiement déjà enregistré : renvoi sans nouveau débit."
            : `Paiement de ${formatCents(data.amount_cents)} accepté.`;
        setResult({ ok: true, text });
        setAmount("");
        setLabel("");
      } else {
        setResult({ ok: false, text: `Paiement refusé : ${REJECTIONS[data.rejection_reason] ?? data.rejection_reason}.` });
      }
      onDone();
    } catch (err) {
      if (err.status === 401) return onError(err);
      // Erreur réseau ou serveur : on garde la même clé, un nouvel essai ne pourra pas débiter deux fois.
      setResult({ ok: false, text: `${err.message} Vous pouvez réessayer sans risque de double débit.` });
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="mb-4 text-lg font-semibold">Payer</h2>
      <form onSubmit={submit} className="space-y-4">
        <label className="block">
          <span className="text-sm font-medium">Bénéficiaire</span>
          <select
            value={to}
            onChange={(e) => setTo(e.target.value)}
            className="mt-1 w-full rounded-lg border border-slate-300 bg-white px-3 py-2"
          >
            {payees.map((p) => (
              <option key={p.accountId} value={p.accountId}>
                {p.label} — {p.kind}
              </option>
            ))}
          </select>
        </label>
        <label className="block">
          <span className="text-sm font-medium">Montant (€)</span>
          <input
            value={amount}
            onChange={(e) => setAmount(e.target.value)}
            inputMode="decimal"
            placeholder="12,50"
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
          />
          {amount && cents === null && (
            <span className="mt-1 block text-xs text-red-600">Montant invalide : de 0,01 € à 10 000 €, 2 décimales max.</span>
          )}
        </label>
        <label className="block">
          <span className="text-sm font-medium">Libellé (facultatif)</span>
          <input
            value={label}
            onChange={(e) => setLabel(e.target.value)}
            maxLength={140}
            className="mt-1 w-full rounded-lg border border-slate-300 px-3 py-2"
          />
        </label>
        <button
          disabled={pending || cents === null}
          className="w-full rounded-lg bg-indigo-600 py-2 font-medium text-white hover:bg-indigo-700 disabled:opacity-50"
        >
          {pending ? "Paiement en cours…" : cents ? `Payer ${formatCents(cents)}` : "Payer"}
        </button>
        {result && (
          <p className={`rounded-lg px-3 py-2 text-sm ${result.ok ? "bg-emerald-50 text-emerald-700" : "bg-red-50 text-red-700"}`}>
            {result.text}
          </p>
        )}
      </form>
    </section>
  );
}
