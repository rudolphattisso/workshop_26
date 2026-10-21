import { styleOf } from "../lib/status.js";

// Disposition fixe et lisible : le trafic entre par le WAF en haut et descend vers les bases.
const POSITIONS = {
  "smoke-test": { x: 140, y: 70 },
  bunkerweb: { x: 480, y: 70 },
  frontend: { x: 820, y: 70 },
  auth: { x: 300, y: 230 },
  "payment-api": { x: 660, y: 230 },
  "auth-db": { x: 300, y: 390 },
  "payment-db": { x: 660, y: 390 },
};
const NODE_W = 180;
const NODE_H = 64;

export default function TopologyMap({ topology }) {
  return (
    <section className="overflow-x-auto rounded-xl border border-slate-800 bg-slate-900 p-4">
      <h2 className="mb-2 text-sm font-medium uppercase tracking-wide text-slate-400">Services et connexions</h2>
      <svg viewBox="0 0 960 460" className="min-w-[720px]" role="img" aria-label="Carte des services et de leurs connexions">
        {topology.links.map((link) => (
          <Link key={`${link.source}-${link.target}`} link={link} />
        ))}
        {topology.nodes.map((node) => (
          <Node key={node.name} node={node} />
        ))}
      </svg>
      <Legend />
    </section>
  );
}

function Link({ link }) {
  const a = POSITIONS[link.source];
  const b = POSITIONS[link.target];
  if (!a || !b) return null;
  const style = styleOf(link.state);
  const midX = (a.x + b.x) / 2;
  const midY = (a.y + b.y) / 2;
  return (
    <g>
      <title>{`${link.label} : ${style.label} — ${link.detail}`}</title>
      <line
        x1={a.x}
        y1={a.y}
        x2={b.x}
        y2={b.y}
        stroke={style.stroke}
        strokeWidth={link.state === "up" ? 3 : 4}
        strokeDasharray={link.state === "up" ? undefined : "8 6"}
      />
      <rect x={midX - 74} y={midY - 11} width={148} height={22} rx={6} fill="#0f172a" stroke={style.stroke} strokeWidth={1} />
      <text x={midX} y={midY + 4} textAnchor="middle" fontSize="11" fill={style.stroke}>
        {link.label}
      </text>
    </g>
  );
}

function Node({ node }) {
  const p = POSITIONS[node.name];
  if (!p) return null;
  const style = styleOf(node.state);
  return (
    <g>
      <title>{`${node.label} : ${style.label} — ${node.detail}`}</title>
      <rect x={p.x - NODE_W / 2} y={p.y - NODE_H / 2} width={NODE_W} height={NODE_H} rx={12} fill={style.fill} stroke={style.stroke} strokeWidth={2} />
      <text x={p.x} y={p.y - 4} textAnchor="middle" fontSize="15" fontWeight="600" fill="#f1f5f9">
        {node.label}
      </text>
      <text x={p.x} y={p.y + 16} textAnchor="middle" fontSize="12" fill={style.stroke}>
        {style.label}
      </text>
    </g>
  );
}

function Legend() {
  return (
    <div className="mt-2 flex flex-wrap gap-4 text-xs text-slate-400">
      {["up", "degraded", "down", "unknown"].map((state) => (
        <span key={state} className="flex items-center gap-1">
          <span className={`h-2 w-2 rounded-full ${styleOf(state).dot}`} />
          {styleOf(state).label}
        </span>
      ))}
      <span>· trait pointillé = connexion en défaut · survol = détail</span>
    </div>
  );
}
