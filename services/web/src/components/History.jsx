import { formatCents } from "../lib/money.js";
import { payeeName } from "../lib/payees.js";

const dateFormat = new Intl.DateTimeFormat("fr-FR", { dateStyle: "short", timeStyle: "medium" });

export default function History({ payments, myAccountIds }) {
  return (
    <section className="rounded-xl border border-slate-200 bg-white p-6 shadow-sm">
      <h2 className="mb-4 text-lg font-semibold">Dernières opérations</h2>
      {payments.length === 0 ? (
        <p className="text-sm text-slate-500">Aucune opération pour le moment.</p>
      ) : (
        <ul className="divide-y divide-slate-100">
          {payments.map((p) => {
            const outgoing = myAccountIds.has(p.from_account_id);
            const counterpart = payeeName(outgoing ? p.to_account_id : p.from_account_id);
            const rejected = p.status === "REJECTED";
            const amountColor = rejected ? "text-slate-400 line-through" : outgoing ? "text-slate-900" : "text-emerald-600";
            return (
              <li key={p.id} className="flex items-center justify-between py-3">
                <div>
                  <p className="text-sm font-medium">
                    {outgoing ? "À " : "De "}
                    {counterpart}
                    {p.label && <span className="font-normal text-slate-500"> · {p.label}</span>}
                  </p>
                  <p className="text-xs text-slate-500">{dateFormat.format(new Date(p.created_at))}</p>
                </div>
                <div className="text-right">
                  <p className={`font-semibold ${amountColor}`}>
                    {outgoing ? "−" : "+"}
                    {formatCents(p.amount_cents)}
                  </p>
                  {rejected && <p className="text-xs text-red-600">refusé</p>}
                </div>
              </li>
            );
          })}
        </ul>
      )}
    </section>
  );
}
