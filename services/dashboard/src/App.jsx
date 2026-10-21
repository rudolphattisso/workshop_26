import { useCallback, useState } from "react";
import { login, readToken } from "./lib/auth.js";
import Supervision from "./components/Supervision.jsx";

// Jeton en mémoire seulement (pas de localStorage) : recharger la page impose de se reconnecter.
export default function App() {
  const [token, setToken] = useState(null);
  const [notice, setNotice] = useState(null);

  const signOut = useCallback((message = null) => {
    setToken(null);
    setNotice(message);
  }, []);

  return token ? (
    <Supervision token={token} onSignOut={signOut} />
  ) : (
    <LoginForm
      notice={notice}
      onSuccess={(t) => {
        if (readToken(t).role !== "operator") return setNotice("Accès réservé au compte opérateur.");
        setNotice(null);
        setToken(t);
      }}
    />
  );
}

function LoginForm({ onSuccess, notice }) {
  const [username, setUsername] = useState("operator");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);

  async function submit(event) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      onSuccess(await login(username.trim(), password));
    } catch (err) {
      setError(err.message);
    } finally {
      setPassword("");
      setPending(false);
    }
  }

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form onSubmit={submit} className="w-full max-w-sm space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-6">
        <div>
          <h1 className="text-xl font-semibold">Supervision</h1>
          <p className="text-sm text-slate-400">RESILIENCE-ALPHA · accès opérateur</p>
        </div>
        {notice && <p className="rounded-lg bg-amber-950 px-3 py-2 text-sm text-amber-300">{notice}</p>}
        <label className="block">
          <span className="text-sm text-slate-300">Identifiant</span>
          <input
            value={username}
            onChange={(e) => setUsername(e.target.value)}
            autoComplete="username"
            required
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 focus:border-indigo-400 focus:outline-none"
          />
        </label>
        <label className="block">
          <span className="text-sm text-slate-300">Mot de passe</span>
          <input
            type="password"
            value={password}
            onChange={(e) => setPassword(e.target.value)}
            autoComplete="current-password"
            required
            className="mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 focus:border-indigo-400 focus:outline-none"
          />
        </label>
        {error && <p className="text-sm text-red-400">{error}</p>}
        <button
          disabled={pending}
          className="w-full rounded-lg bg-indigo-500 py-2 font-medium text-white hover:bg-indigo-400 disabled:opacity-60"
        >
          {pending ? "Connexion…" : "Se connecter"}
        </button>
      </form>
    </div>
  );
}
