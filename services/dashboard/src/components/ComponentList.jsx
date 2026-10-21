import { styleOf } from "../lib/status.js";

export default function ComponentList({ topology }) {
  const labels = Object.fromEntries(topology.nodes.map((n) => [n.name, n.label]));
  return (
    <section className="rounded-xl border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-3 text-sm font-medium uppercase tracking-wide text-slate-400">Détail des mesures</h2>
      <Rows title="Services (healthcheck)" items={topology.nodes.map((n) => ({ key: n.name, label: n.label, ...n }))} />
      <Rows
        title="Connexions"
        items={topology.links.map((l) => ({
          key: `${l.source}-${l.target}`,
          label: `${labels[l.source]} → ${labels[l.target]}`,
          ...l,
        }))}
      />
    </section>
  );
}

function Rows({ title, items }) {
  return (
    <div className="mb-4 last:mb-0">
      <h3 className="mb-1 text-xs text-slate-500">{title}</h3>
      <ul className="divide-y divide-slate-800">
        {items.map((item) => {
          const style = styleOf(item.state);
          return (
            <li key={item.key} className="flex items-start justify-between gap-3 py-2 text-sm">
              <span className="flex items-center gap-2">
                <span className={`h-2 w-2 shrink-0 rounded-full ${style.dot}`} />
                {item.label}
              </span>
              <span className="text-right">
                <span className={`font-medium ${style.text}`}>{style.label}</span>
                <span className="block text-xs text-slate-500">{item.detail}</span>
              </span>
            </li>
          );
        })}
      </ul>
    </div>
  );
}
