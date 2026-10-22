import { styleOf } from "../lib/status.js";

export default function ChangeLog({ changes }) {
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">Journal des changements</h2>
      {changes.length === 0 ? (
        <p className="text-sm text-slate-500">Aucun changement d'état depuis le démarrage du moteur.</p>
      ) : (
        <ol className="max-h-[420px] space-y-2 overflow-y-auto pr-1">
          {changes.map((c, i) => (
            <li key={`${c.at}-${c.id}-${i}`} className="rounded-lg bg-slate-950 px-3 py-2 text-sm">
              <div className="flex items-center justify-between gap-2">
                <span className="font-medium">{c.label}</span>
                <time className="font-mono text-xs text-slate-500">{new Date(c.at).toLocaleTimeString("fr-FR")}</time>
              </div>
              <div className="text-xs">
                <span className={styleOf(c.from).text}>{styleOf(c.from).label}</span>
                <span className="text-slate-500"> → </span>
                <span className={styleOf(c.to).text}>{styleOf(c.to).label}</span>
                <span className="text-slate-500"> · {c.detail}</span>
              </div>
            </li>
          ))}
        </ol>
      )}
    </section>
  );
}
