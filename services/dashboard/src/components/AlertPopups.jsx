import { useEffect } from "react";

const LOOK = {
  critical: { box: "border-red-500 bg-red-950", heading: "text-red-300", icon: "⚠" },
  warning: { box: "border-amber-500 bg-amber-950", heading: "text-amber-300", icon: "!" },
  recovered: { box: "border-emerald-500 bg-emerald-950", heading: "text-emerald-300", icon: "✓" },
};

// Pile de popups en haut à droite. role="alert" : les lecteurs d'écran annoncent chaque nouvelle popup.
export default function AlertPopups({ alerts, onClose }) {
  return (
    <div className="pointer-events-none fixed right-4 top-4 z-50 flex w-96 max-w-[calc(100vw-2rem)] flex-col gap-3">
      {alerts.map((alert) => (
        <Popup key={alert.id} alert={alert} onClose={onClose} />
      ))}
    </div>
  );
}

function Popup({ alert, onClose }) {
  const look = LOOK[alert.level];

  useEffect(() => {
    if (alert.sticky) return undefined; // une panne reste affichée tant qu'elle dure
    const timer = setTimeout(() => onClose(alert.id), alert.timeoutMs);
    return () => clearTimeout(timer);
  }, [alert, onClose]);

  return (
    <div role="alert" className={`pointer-events-auto rounded-xl border-l-4 p-4 shadow-2xl ${look.box} animate-popin`}>
      <div className="flex items-start gap-3">
        <span className={`text-lg font-bold ${look.heading}`}>{look.icon}</span>
        <div className="min-w-0 flex-1">
          <div className="flex items-baseline justify-between gap-2">
            <p className={`font-semibold ${look.heading}`}>{alert.heading}</p>
            <time className="font-mono text-xs text-slate-400">{new Date(alert.at).toLocaleTimeString("fr-FR")}</time>
          </div>
          <ul className="mt-1 space-y-1">
            {alert.items.map((item) => (
              <li key={item.target}>
                <p className="font-medium text-slate-100">{item.title}</p>
                <p className="break-words text-sm text-slate-300">{item.detail}</p>
              </li>
            ))}
          </ul>
        </div>
        <button
          onClick={() => onClose(alert.id)}
          aria-label="Fermer"
          className="text-slate-400 hover:text-white"
        >
          ×
        </button>
      </div>
    </div>
  );
}
