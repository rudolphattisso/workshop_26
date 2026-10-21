import { useCallback, useEffect, useRef, useState } from "react";
import { dropRecovered, groupAlerts, takeNewChanges, toAlert, trackOutages } from "../lib/alerts.js";
import { readEvents, Unauthorized } from "../lib/sse.js";
import { OVERALL_TEXT, overall, styleOf } from "../lib/status.js";
import AlertPopups from "./AlertPopups.jsx";
import TopologyMap from "./TopologyMap.jsx";
import ComponentList from "./ComponentList.jsx";
import ChangeLog from "./ChangeLog.jsx";

const MAX_POPUPS = 6;
const PAGE_TITLE = "Supervision — Resilience";

const RETRY_MS = 2000;
const STALE_MS = 20000; // pas un octet depuis 20 s (battement toutes les 15 s) : le flux est considéré coupé

export default function Supervision({ token, onSignOut }) {
  const [topology, setTopology] = useState(null);
  const [lastMessageAt, setLastMessageAt] = useState(null);
  const [now, setNow] = useState(Date.now());
  const [alerts, setAlerts] = useState([]);
  const seen = useRef(new Set()); // changements déjà traités (pas de doublon après une reconnexion)
  const firstLoad = useRef(true);
  const outageSince = useRef({}); // id → début de l'interruption en cours, pour annoncer sa durée au retour

  const closeAlert = useCallback((id) => setAlerts((current) => current.filter((a) => a.id !== id)), []);

  // Chaque nouveau changement d'état devient une popup. Un retour à la normale remplace la popup de panne.
  const notify = useCallback((changes) => {
    const fresh = takeNewChanges(changes, seen.current, firstLoad.current);
    if (firstLoad.current) {
      // Historique d'avant l'ouverture : pas de popup, mais on retient les interruptions en cours pour la durée.
      trackOutages([...changes].reverse(), outageSince.current);
      firstLoad.current = false;
    }
    if (!fresh.length) return;
    const created = [];
    const recovered = new Set();
    for (const change of fresh) {
      const alert = toAlert(change, outageSince.current); // avant trackOutages : le début est encore connu
      trackOutages([change], outageSince.current);
      if (change.to !== "down") recovered.add(change.id); // plus en panne : retiré de la popup de panne
      if (alert) created.push(alert);
    }
    const popups = groupAlerts(created).reverse(); // la plus récente en haut
    setAlerts((current) => [...popups, ...dropRecovered(current, recovered)].slice(0, MAX_POPUPS));
  }, []);

  // Onglet du navigateur : « ⚠ » tant qu'une panne est affichée, visible même depuis un autre onglet.
  useEffect(() => {
    const open = alerts.filter((a) => a.level === "critical").reduce((n, a) => n + a.items.length, 0);
    document.title = open ? `⚠ ${open} en panne — ${PAGE_TITLE}` : PAGE_TITLE;
    return () => {
      document.title = PAGE_TITLE;
    };
  }, [alerts]);

  // Flux temps réel avec reconnexion automatique : à chaque reconnexion, le moteur renvoie l'état complet.
  useEffect(() => {
    const controller = new AbortController();
    let retry;
    const connect = async () => {
      try {
        await readEvents(
          "/api/remediation/events",
          token,
          ({ event, data }) => {
            setLastMessageAt(Date.now());
            if (event === "services") {
              setTopology(data);
              notify(data.changes ?? []);
            }
          },
          controller.signal,
        );
      } catch (err) {
        if (controller.signal.aborted) return;
        if (err instanceof Unauthorized) return onSignOut("Session expirée, reconnectez-vous.");
      }
      if (!controller.signal.aborted) retry = setTimeout(connect, RETRY_MS);
    };
    connect();
    return () => {
      controller.abort();
      clearTimeout(retry);
    };
  }, [token, onSignOut, notify]);

  useEffect(() => {
    const timer = setInterval(() => setNow(Date.now()), 1000);
    return () => clearInterval(timer);
  }, []);

  const live = lastMessageAt !== null && now - lastMessageAt < STALE_MS;
  const verdict = live ? overall(topology) : "unknown";
  const verdictStyle = styleOf(verdict);

  return (
    <div className="mx-auto max-w-6xl space-y-6 px-4 py-6">
      <AlertPopups alerts={alerts} onClose={closeAlert} />
      <header className="flex flex-wrap items-center justify-between gap-4">
        <div>
          <h1 className="text-xl font-semibold">Supervision · RESILIENCE-ALPHA</h1>
          <p className="text-sm text-slate-400">
            {live ? (
              <>
                <span className="mr-1 inline-block h-2 w-2 animate-pulse rounded-full bg-emerald-400" />
                Temps réel · dernière mesure {topology && new Date(topology.checked_at).toLocaleTimeString("fr-FR")}
              </>
            ) : (
              <>
                <span className="mr-1 inline-block h-2 w-2 rounded-full bg-red-500" />
                Flux interrompu — reconnexion au moteur de remédiation…
              </>
            )}
          </p>
        </div>
        <button onClick={() => onSignOut()} className="text-sm text-slate-400 hover:text-white">
          Se déconnecter
        </button>
      </header>

      <div className={`flex items-center gap-3 rounded-xl border border-slate-800 px-5 py-4`} style={{ backgroundColor: verdictStyle.fill }}>
        <span className={`h-3 w-3 rounded-full ${verdictStyle.dot}`} />
        <span className="text-lg font-semibold">{live ? OVERALL_TEXT[verdict] : "État inconnu : le moteur ne répond pas"}</span>
      </div>

      {topology ? (
        <>
          <TopologyMap topology={topology} />
          <div className="grid gap-6 lg:grid-cols-2">
            <ComponentList topology={topology} />
            <ChangeLog changes={topology.changes ?? []} />
          </div>
        </>
      ) : (
        <p className="text-slate-400">En attente du premier passage du watchdog…</p>
      )}
    </div>
  );
}
