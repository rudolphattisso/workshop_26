import { useCallback, useEffect, useState } from "react";
import { identify, login, readToken } from "./lib/auth.js";
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

// Délai imposé après un identifiant non reconnu : la LED reste rouge fixe 30 s (docs/IOT.md § 4).
const UNRECOGNIZED_WAIT_SECONDS = 30;

// Connexion en deux étapes (consigne additionnelle 1) : identifiant d'abord, mot de passe ensuite.
// Chaque étape pilote la LED de l'objet connecté côté auth ; la reconnaissance faciale n'est pas livrée,
// « reconnu » signifie « compte opérateur existant ».
function LoginForm({ onSuccess, notice }) {
  const [step, setStep] = useState("identify"); // identify | password
  const [username, setUsername] = useState("operator");
  const [password, setPassword] = useState("");
  const [error, setError] = useState(null);
  const [pending, setPending] = useState(false);
  const [waitSeconds, setWaitSeconds] = useState(0);

  useEffect(() => {
    if (waitSeconds <= 0) return undefined;
    const timer = setTimeout(() => setWaitSeconds((s) => s - 1), 1000);
    return () => clearTimeout(timer);
  }, [waitSeconds]);

  function restart(message) {
    setStep("identify");
    setUsername(""); // consigne : l'identifiant est remis à vide
    setError(message);
  }

  async function submitIdentify(event) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      if (await identify(username.trim())) {
        setStep("password");
      } else {
        restart("Identifiant non reconnu.");
        setWaitSeconds(UNRECOGNIZED_WAIT_SECONDS);
      }
    } catch (err) {
      setError(err.message);
    } finally {
      setPending(false);
    }
  }

  async function submitPassword(event) {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      onSuccess(await login(username.trim(), password));
    } catch (err) {
      restart(`${err.message}. Recommencez l'identification.`);
    } finally {
      setPassword("");
      setPending(false);
    }
  }

  const inputClass =
    "mt-1 w-full rounded-lg border border-slate-700 bg-slate-950 px-3 py-2 focus:border-indigo-400 focus:outline-none disabled:opacity-60";
  const buttonClass =
    "w-full rounded-lg bg-indigo-500 py-2 font-medium text-white hover:bg-indigo-400 disabled:opacity-60";

  return (
    <div className="grid min-h-screen place-items-center px-4">
      <form
        onSubmit={step === "identify" ? submitIdentify : submitPassword}
        className="w-full max-w-sm space-y-4 rounded-xl border border-slate-800 bg-slate-900 p-6"
      >
        <div>
          <h1 className="text-xl font-semibold">Supervision</h1>
          <p className="text-sm text-slate-400">RESILIENCE-ALPHA · accès opérateur</p>
        </div>
        {notice && <p className="rounded-lg bg-amber-950 px-3 py-2 text-sm text-amber-300">{notice}</p>}

        {step === "identify" ? (
          <>
            <label className="block">
              <span className="text-sm text-slate-300">Identifiant</span>
              <input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                autoComplete="username"
                required
                autoFocus
                disabled={waitSeconds > 0}
                className={inputClass}
              />
            </label>
            {error && <p className="text-sm text-red-400">{error}</p>}
            <button disabled={pending || waitSeconds > 0} className={buttonClass}>
              {waitSeconds > 0 ? `Nouvel essai dans ${waitSeconds} s` : pending ? "Vérification…" : "Continuer"}
            </button>
          </>
        ) : (
          <>
            <p className="text-sm text-slate-300">
              Identifiant reconnu : <span className="font-medium text-emerald-400">{username.trim()}</span>
            </p>
            <label className="block">
              <span className="text-sm text-slate-300">Mot de passe</span>
              <input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                autoComplete="current-password"
                required
                autoFocus
                className={inputClass}
              />
            </label>
            {error && <p className="text-sm text-red-400">{error}</p>}
            <button disabled={pending} className={buttonClass}>
              {pending ? "Connexion…" : "Se connecter"}
            </button>
          </>
        )}
      </form>
    </div>
  );
}
