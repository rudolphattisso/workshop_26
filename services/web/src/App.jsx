import { useCallback, useState } from "react";
import { readToken } from "./lib/api.js";
import LoginForm from "./components/LoginForm.jsx";
import Wallet from "./components/Wallet.jsx";

// Le jeton vit uniquement en mémoire (état React), jamais dans localStorage : un script injecté (XSS) ne
// pourrait pas le lire depuis le stockage du navigateur. Contrepartie assumée : recharger la page déconnecte.
export default function App() {
  const [session, setSession] = useState(null);
  const [notice, setNotice] = useState(null);

  const signIn = useCallback((token) => {
    setNotice(null);
    setSession({ token, ...readToken(token) });
  }, []);

  const signOut = useCallback((message = null) => {
    setSession(null);
    setNotice(message);
  }, []);

  return (
    <div className="min-h-screen">
      <header className="border-b border-slate-200 bg-white">
        <div className="mx-auto flex max-w-4xl items-center justify-between px-4 py-3">
          <div className="flex items-center gap-2">
            <span className="grid h-8 w-8 place-items-center rounded-lg bg-indigo-600 font-bold text-white">R</span>
            <span className="font-semibold">Resilience Pay</span>
            <span className="rounded bg-amber-100 px-2 py-0.5 text-xs font-medium text-amber-800">données fictives</span>
          </div>
          {session && (
            <button onClick={() => signOut()} className="text-sm text-slate-600 hover:text-slate-900">
              Se déconnecter
            </button>
          )}
        </div>
      </header>

      <main className="mx-auto max-w-4xl px-4 py-8">
        {session ? <Wallet session={session} onExpired={signOut} /> : <LoginForm onSuccess={signIn} notice={notice} />}
      </main>
    </div>
  );
}
