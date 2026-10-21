import { useCallback, useEffect, useState } from "react";
import { getAccounts, getPayments } from "../lib/api.js";
import { formatCents } from "../lib/money.js";
import PaymentForm from "./PaymentForm.jsx";
import History from "./History.jsx";

export default function Wallet({ session, onExpired }) {
  const [accounts, setAccounts] = useState(null);
  const [payments, setPayments] = useState([]);
  const [error, setError] = useState(null);

  // Toute erreur 401 (jeton expiré, ou révoqué par un redémarrage de l'auth) ramène à l'écran de connexion.
  const guard = useCallback(
    (err) => {
      if (err.status === 401) onExpired("Session expirée, reconnectez-vous.");
      else setError(err.message);
    },
    [onExpired],
  );

  const refresh = useCallback(async () => {
    try {
      const [acc, pay] = await Promise.all([getAccounts(session.token), getPayments(session.token)]);
      setAccounts(acc);
      setPayments(pay);
      setError(null);
    } catch (err) {
      guard(err);
    }
  }, [session.token, guard]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (session.role === "operator") {
    return (
      <p className="rounded-xl border border-slate-200 bg-white p-6 text-slate-700">
        Compte opérateur : il ne possède pas de compte de paiement. La supervision se fait depuis le dashboard.
      </p>
    );
  }

  if (accounts === null) {
    return error ? <ErrorBanner message={error} onRetry={refresh} /> : <p className="text-slate-500">Chargement…</p>;
  }

  const account = accounts[0];
  const myAccountIds = new Set(accounts.map((a) => a.id));

  return (
    <div className="space-y-6">
      {error && <ErrorBanner message={error} onRetry={refresh} />}

      <section className="rounded-xl bg-gradient-to-br from-indigo-600 to-indigo-800 p-6 text-white shadow">
        <p className="text-sm text-indigo-200">{account.label}</p>
        <p className="mt-2 text-4xl font-semibold tracking-tight">{formatCents(account.balance_cents)}</p>
        <p className="mt-2 font-mono text-xs text-indigo-300">{account.id}</p>
      </section>

      <div className="grid gap-6 md:grid-cols-2">
        <PaymentForm token={session.token} account={account} onDone={refresh} onError={guard} />
        <History payments={payments} myAccountIds={myAccountIds} />
      </div>
    </div>
  );
}

function ErrorBanner({ message, onRetry }) {
  return (
    <div className="flex items-center justify-between rounded-lg bg-red-50 px-4 py-3 text-sm text-red-700">
      <span>{message}</span>
      <button onClick={onRetry} className="font-medium underline">
        Réessayer
      </button>
    </div>
  );
}
