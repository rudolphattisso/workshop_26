"""Génère docs/diagrams/architecture.drawio (3 pages : architecture, matrice de flux, inventaire).

Le diagramme est produit par code pour rester aligné avec docker-compose.yml :
modifier ce script puis relancer `python docs/diagrams/gen_architecture.py`.
Le fichier .drawio reste éditable à la main dans draw.io / diagrams.net.
"""
from pathlib import Path
from xml.sax.saxutils import escape

OUT = Path(__file__).with_name("architecture.drawio")

# --------------------------------------------------------------------------- styles
ZONE = {
    "edge":    ("#ffe6cc", "#d79b00"),
    "app":     ("#dae8fc", "#6c8ebf"),
    "data":    ("#fff2cc", "#d6b656"),
    "mon":     ("#d5e8d4", "#82b366"),
    "control": ("#f8cecc", "#b85450"),
    "ro":      ("#fbe4e3", "#b85450"),
    "mgmt":    ("#e1d5e7", "#9673a6"),
    "engine":  ("#f5f5f5", "#666666"),
    "ext":     ("#ffffff", "#333333"),
}
FLOW = {  # type -> (couleur, pointillé)
    "metier":  ("#1f5eff", 0),
    "superv":  ("#2e7d32", 1),
    "control": ("#c62828", 0),
    "admin":   ("#6a1b9a", 1),
}


class Page:
    def __init__(self, name, w, h):
        self.name, self.w, self.h, self.cells, self.n = name, w, h, [], 0

    def _id(self):
        self.n += 1
        return f"c{self.n}"

    def box(self, x, y, w, h, text, fill="#ffffff", stroke="#333333", extra="", cid=None):
        cid = cid or self._id()
        style = (f"rounded=1;whiteSpace=wrap;html=1;fillColor={fill};strokeColor={stroke};"
                 f"arcSize=6;fontSize=11;{extra}")
        self.cells.append(
            f'<mxCell id="{cid}" value="{escape(text, {chr(34): "&quot;"})}" style="{style}" vertex="1" parent="1">'
            f'<mxGeometry x="{x}" y="{y}" width="{w}" height="{h}" as="geometry"/></mxCell>')
        return cid

    def zone(self, x, y, w, h, title, key):
        fill, stroke = ZONE[key]
        return self.box(x, y, w, h, title, fill, stroke,
                        "dashed=1;verticalAlign=top;align=left;spacingLeft=8;spacingTop=4;"
                        "fontStyle=1;fontSize=12;container=0;arcSize=3;")

    def svc(self, x, y, w, h, title, detail, key, cid=None):
        _, stroke = ZONE[key]
        html = f"<b>{title}</b><br><font style='font-size:9px' color='#444'>{detail}</font>"
        return self.box(x, y, w, h, html, "#ffffff", stroke, "strokeWidth=1.5;", cid)

    def text(self, x, y, w, h, html, extra=""):
        return self.box(x, y, w, h, html, "none", "none",
                        "align=left;verticalAlign=top;rounded=0;" + extra)

    def edge(self, src, dst, label, kind, extra="", points=()):
        color, dashed = FLOW[kind]
        cid = self._id()
        pts = ("<Array as=\"points\">" + "".join(f'<mxPoint x="{x}" y="{y}"/>' for x, y in points)
               + "</Array>") if points else ""
        style = (f"edgeStyle=orthogonalEdgeStyle;rounded=1;html=1;strokeColor={color};strokeWidth=2;"
                 f"dashed={dashed};endArrow=block;endFill=1;fontSize=10;fontStyle=1;fontColor={color};"
                 f"labelBackgroundColor=#ffffff;{extra}")
        self.cells.append(
            f'<mxCell id="{cid}" value="{label}" style="{style}" edge="1" parent="1" source="{src}" target="{dst}">'
            f'<mxGeometry relative="1" as="geometry">{pts}</mxGeometry></mxCell>')

    def table(self, x, y, cols, rows, header_fill="#1d2330", row_h=40, fills=None):
        """cols = [(titre, largeur)], rows = [[cellules]] ; fills = couleur 1re colonne par ligne."""
        cx = x
        for title, w in cols:
            self.box(cx, y, w, 30, f"<b>{title}</b>", header_fill, header_fill,
                     "rounded=0;fontColor=#ffffff;")
            cx += w
        for i, row in enumerate(rows):
            cy, cx = y + 30 + i * row_h, x
            zebra = "#ffffff" if i % 2 == 0 else "#f6f7f9"
            for j, (val, (_, w)) in enumerate(zip(row, cols)):
                fill = fills[i] if (fills and j == 0) else zebra
                self.box(cx, cy, w, row_h, val, fill, "#c8ccd4",
                         "rounded=0;align=left;spacingLeft=4;fontSize=10;")
                cx += w
        return y + 30 + len(rows) * row_h

    def xml(self, idx):
        body = "".join(self.cells)
        return (f'<diagram id="p{idx}" name="{escape(self.name)}"><mxGraphModel dx="1600" dy="1000" grid="1" '
                f'gridSize="10" guides="1" tooltips="1" connect="1" arrows="1" fold="1" page="1" pageScale="1" '
                f'pageWidth="{self.w}" pageHeight="{self.h}" math="0" shadow="0"><root>'
                f'<mxCell id="0"/><mxCell id="1" parent="0"/>{body}</root></mxGraphModel></diagram>')


# =========================================================================== PAGE 1
p1 = Page("1 - Architecture", 1800, 1180)
p1.text(20, 5, 1400, 30, "<font style='font-size:20px'><b>PROJECT RESILIENCE-ALPHA</b> — Architecture de déploiement"
        " (Docker Compose + Ansible)</font>")

# Machines externes
atk = p1.box(20, 110, 220, 110, "<b>PC Attaquant</b><br>192.168.137.x (DHCP hotspot)<br>"
             "<font style='font-size:9px'>Kali / outils Red Team<br>Cible autorisée : 192.168.137.1:80</font>",
             "#ffffff", "#b85450", "strokeWidth=2;")
jury = p1.box(20, 250, 220, 70, "<b>Jury / navigateur</b><br><font style='font-size:9px'>http://192.168.137.1/</font>",
              "#ffffff", "#333333")
ia = p1.box(20, 560, 220, 120, "<b>PC IA (optionnel)</b><br>192.168.137.y<br><font style='font-size:9px'>"
            "Ollama (LLM ≤ 8B) :11434<br>Assistant RAG LangChain<br>aucun accès au plan de contrôle</font>",
            "#ffffff", "#9673a6", "dashed=1;strokeWidth=2;")
p1.box(262, 60, 36, 1040, "Point d'accès mobile Windows « RESILIENCE-G&lt;n&gt; » — 192.168.137.0/24",
       "#eeeeee", "#999999", "horizontal=0;fontStyle=1;rounded=0;")

# PC Hôte
p1.box(320, 40, 1460, 1080, "<b>PC Hôte — 192.168.137.1</b> · Windows 11 · Docker Desktop (WSL2) · projet Compose "
       "« resilience » — 18 conteneurs", "#fafafa", "#333333",
       "verticalAlign=top;align=left;spacingLeft=10;fontSize=13;strokeWidth=2;arcSize=1;")

# Zones réseau
p1.zone(340, 80, 230, 240, "edge · 172.30.10.0/24 (publié LAN)", "edge")
p1.zone(600, 80, 770, 240, "app · 172.30.20.0/24 · interne", "app")
p1.zone(600, 350, 770, 150, "data · 172.30.30.0/24 · interne", "data")
p1.zone(340, 530, 1030, 300, "monitoring · 172.30.40.0/24 · interne", "mon")
p1.zone(340, 860, 520, 220, "control · 172.30.50.0/24 · interne", "control")
p1.zone(880, 860, 230, 220, "dockerapi-ro · 172.30.60.0/24", "ro")
p1.zone(1400, 80, 360, 420, "mgmt · 172.30.70.0/24 → 127.0.0.1 uniquement", "mgmt")
p1.zone(1130, 860, 630, 220, "Moteur Docker & stockage", "engine")
p1.zone(1400, 530, 360, 300, "Exploitation (Ansible)", "mgmt")

# Services
waf = p1.svc(360, 140, 190, 150, "WAF", "nginx + ModSecurity<br>OWASP CRS 4.25 (PL1)<br>rate-limit / IP<br>"
             ":8080 ← 0.0.0.0:80<br>réseaux : edge, app, monitoring", "edge")
fe = p1.svc(620, 140, 170, 150, "frontend", "nginx non-root<br>:8080<br>FS lecture seule<br>réseau : app", "app")
auth = p1.svc(810, 140, 170, 150, "auth", "FastAPI · JWT<br>:8000<br>rôle BDD auth_svc<br>app, data, monitoring", "app")
pay = p1.svc(1000, 140, 170, 150, "payment-api", "FastAPI · paiements<br>:8000<br>rôle BDD payment_svc<br>app, data, monitoring", "app")
txp = p1.svc(1190, 140, 165, 150, "txprobe", "transaction synthétique<br>toutes les 5 s<br>:8000 · GET /check<br>app, monitoring", "app")
pg = p1.svc(880, 390, 220, 95, "PostgreSQL 16", "uid 70 · FS lecture seule<br>:5432 jamais publié<br>volume pgdata", "data")

prom = p1.svc(360, 570, 180, 100, "Prometheus", "scrape 5 s · règles<br>:9090 · rétention 7 j", "mon")
am = p1.svc(560, 570, 180, 100, "Alertmanager", "groupage · inhibition<br>:9093 → webhook", "mon")
loki = p1.svc(760, 570, 180, 100, "Loki", "logs · ruler SOC<br>:3100 · rétention 7 j", "mon")
alloy = p1.svc(960, 570, 180, 100, "Alloy", "collecte logs Docker<br>user alloy (non-root)", "mon")
graf = p1.svc(1160, 570, 190, 100, "Grafana", "dashboards as code<br>:3000", "mon")
bb = p1.svc(360, 710, 180, 100, "blackbox-exporter", "sondes HTTP via WAF<br>:9115", "mon")
we = p1.svc(560, 710, 180, 100, "waf-exporter", "stub_status nginx<br>:9113", "mon")
pge = p1.svc(760, 710, 180, 100, "postgres-exporter", "rôle exporter (pg_monitor)<br>:9187 · data, monitoring", "mon")
cad = p1.svc(960, 710, 180, 100, "cAdvisor", "CPU / RAM conteneurs<br>:8080 · privilégié (exception)", "mon")

rem = p1.svc(360, 910, 220, 150, "Moteur de remédiation", "webhook authentifié (Bearer)<br>liste blanche + cooldown<br>"
             "vérif. par transaction<br>:8000 ← 127.0.0.1:8090<br>monitoring, control, mgmt", "control")
dp = p1.svc(620, 910, 220, 150, "docker-proxy", "HAProxy durci<br>GET /containers<br>POST start/stop/restart SEULS<br>"
            "create/exec/kill → 403", "control")
dpro = p1.svc(900, 910, 190, 150, "docker-proxy-ro", "GET containers,<br>networks, events<br>POST interdit", "ro")
eng = p1.svc(1150, 910, 250, 150, "Docker Engine", "/var/run/docker.sock<br>restart: unless-stopped<br>"
             "healthchecks · limites mém/CPU", "engine")
p1.svc(1420, 910, 320, 150, "Volumes nommés", "pgdata · prometheus-data · loki-data<br>grafana-data · alertmanager-data · alloy-data<br>"
       "+ fichiers hôte : ./secrets (Docker secrets),<br>./backups (dumps + SHA-256)", "engine")

admin = p1.svc(1420, 130, 320, 80, "Opérateur sur le PC Hôte", "navigateur local", "mgmt")
ports = p1.svc(1420, 250, 320, 220, "Interfaces d'administration",
               "127.0.0.1:3000 → Grafana<br>127.0.0.1:9090 → Prometheus<br>127.0.0.1:9093 → Alertmanager<br>"
               "127.0.0.1:8090 → Remédiation (/events)<br><br>Base, Loki, exporters, proxies :<br>"
               "<b>jamais publiés</b>", "mgmt")
ans = p1.svc(1420, 570, 320, 240, "Runner Ansible (conteneur éphémère)",
             "scripts/ops.ps1 &lt;action&gt;<br>deploy · verify · backup · restore<br>recover (PRA) · chaos · reload · teardown<br><br>"
             "socket Docker de l'hôte + rejoint<br>edge &amp; mgmt pour les vérifications<br>"
             "(docker compose, promtool, amtool,<br>pg_dump / pg_restore)", "mgmt")

# Flux (numérotation = matrice de flux, page 2)
p1.edge(atk, waf, "F01", "metier", "exitX=1;exitY=0.5;entryX=0;entryY=0.3;")
p1.edge(jury, waf, "F01", "metier", "exitX=1;exitY=0.5;entryX=0;entryY=0.7;")
p1.edge(waf, fe, "F02", "metier")
p1.edge(waf, auth, "F03", "metier", "exitX=0.5;exitY=0;entryX=0.5;entryY=0;")
p1.edge(waf, pay, "F04", "metier", "exitX=0.7;exitY=0;entryX=0.5;entryY=0;")
p1.edge(auth, pg, "F05", "metier", "exitX=0.5;exitY=1;entryX=0;entryY=0.5;")
p1.edge(pay, pg, "F06", "metier", "exitX=0.5;exitY=1;entryX=1;entryY=0.5;")
p1.edge(txp, waf, "F07", "metier", "exitX=0.5;exitY=1;entryX=0.5;entryY=1;dashed=1;")
p1.edge(prom, auth, "F08", "superv", "exitX=0.3;exitY=0;entryX=0.3;entryY=1;")
p1.edge(prom, bb, "F09", "superv")
p1.edge(bb, waf, "F10", "superv", "exitX=0;exitY=0.5;entryX=0.2;entryY=1;")
p1.edge(we, waf, "F11", "superv", "exitX=1;exitY=0.3;entryX=0.6;entryY=1;", [(750, 740), (750, 515), (474, 515)])
p1.edge(pge, pg, "F12", "superv", "exitX=1;exitY=0.3;entryX=0.318;entryY=1;", [(950, 740)])
p1.edge(alloy, dpro, "F13", "superv", "exitX=1;exitY=0.8;entryX=0.5;entryY=0;", [(1150, 650), (1150, 845), (995, 845)])
p1.edge(alloy, loki, "F14", "superv")
p1.edge(prom, am, "F15", "control")
p1.edge(loki, am, "F16", "control", "exitX=0.5;exitY=0;entryX=0.5;entryY=0;")
p1.edge(am, rem, "F17", "control", "exitX=0;exitY=0.8;entryX=0.5;entryY=0;", [(550, 650), (550, 840), (470, 840)])
p1.edge(rem, dp, "F18", "control")
p1.edge(graf, loki, "F20", "superv", "exitX=0.5;exitY=0;entryX=0.7;entryY=0;")
p1.edge(admin, ports, "F21", "admin")
p1.edge(ans, eng, "F22", "admin", "exitX=0.3;exitY=1;entryX=0.5;entryY=0;")
p1.edge(dp, eng, "F23", "control", "exitX=0.5;exitY=1;entryX=0.2;entryY=1;")
p1.edge(dpro, eng, "F23", "superv", "exitX=1;exitY=0.7;entryX=0;entryY=0.7;")

# Légende
p1.box(20, 720, 230, 380,
       "<b>Légende</b><br><br>"
       "<font color='#1f5eff'><b>━━ </b></font>flux métier<br>"
       "<font color='#2e7d32'><b>╍╍ </b></font>supervision (métriques, logs)<br>"
       "<font color='#c62828'><b>━━ </b></font>détection → remédiation<br>"
       "<font color='#6a1b9a'><b>╍╍ </b></font>administration / exploitation<br><br>"
       "Fxx = n° dans la matrice de flux (page 2)<br>F19 : remédiation → txprobe:8000/check<br>"
       "F20 : Grafana → Prometheus, Loki, Alertmanager<br>F08 : Prometheus scrape aussi payment-api, txprobe, remediation<br><br>"
       "<b>Zones « interne »</b> : aucune route vers l'extérieur<br>"
       "<b>Seul port publié sur le LAN</b> : 80/tcp (WAF)<br><br>"
       "<b>Boucle de reprise</b> : règle → Alertmanager → remédiation → proxy → restart → "
       "transaction synthétique OK",
       "#ffffff", "#333333", "align=left;verticalAlign=top;spacing=8;fontSize=10;")

# =========================================================================== PAGE 2
p2 = Page("2 - Matrice de flux", 1700, 1600)
p2.text(20, 10, 1600, 30, "<font style='font-size:20px'><b>Matrice des flux autorisés</b> — tout flux non listé est "
        "bloqué (réseaux internes Docker, ports non publiés, proxy Docker filtrant)</font>")
cols = [("ID", 50), ("Source", 165), ("Destination", 185), ("Réseau", 115), ("Port / protocole", 150),
        ("Objet", 330), ("Contrôles de sécurité", 400)]
M, S, C, A = (FLOW[k][0] for k in ("metier", "superv", "control", "admin"))
flows = [
    ("F01", "PC Attaquant, jury (LAN hotspot)", "WAF", "LAN → edge", "TCP 80 → 8080 HTTP", "Accès à l'application (seul flux entrant)", "OWASP CRS (PL1, seuil 5), rate-limit 20 r/s API / 5 r/s login, corps ≤ 64 Ko, /api/* non routé → 404", M),
    ("F02", "WAF", "frontend", "app", "TCP 8080 HTTP", "Pages web (/)", "Inspection WAF préalable ; frontal non-root, FS lecture seule", M),
    ("F03", "WAF", "auth", "app", "TCP 8000 HTTP", "/api/auth/login, /api/auth/ready", "Rate-limit login (anti brute force) ; journal JSON login_failed", M),
    ("F04", "WAF", "payment-api", "app", "TCP 8000 HTTP", "/api/payments*, /api/payments/ready", "JWT HS256 obligatoire ; validation des montants (pydantic)", M),
    ("F05", "auth", "PostgreSQL", "data", "TCP 5432 PostgreSQL", "Lecture des comptes", "Rôle auth_svc : SELECT sur users uniquement ; mots de passe bcrypt", M),
    ("F06", "payment-api", "PostgreSQL", "data", "TCP 5432 PostgreSQL", "Écriture / lecture des transactions", "Rôle payment_svc : SELECT, INSERT sur transactions ; pas d'UPDATE/DELETE", M),
    ("F07", "txprobe", "WAF", "app", "TCP 8080 HTTP", "Transaction synthétique (login → paiement → relecture) / 5 s", "Compte dédié synthetic-probe (rôle probe) ; passe par le WAF comme un client", M),
    ("F08", "Prometheus", "auth, payment-api, txprobe, remediation", "monitoring", "TCP 8000 HTTP GET /metrics", "Métriques applicatives", "Réseau interne ; lecture seule", S),
    ("F09", "Prometheus", "blackbox, waf-exporter, postgres-exporter, cAdvisor, Loki, Grafana, Alloy, Alertmanager", "monitoring", "TCP 9115 / 9113 / 9187 / 8080 / 3100 / 3000 / 12345 / 9093", "Métriques d'infrastructure", "Réseau interne ; aucun de ces ports n'est publié", S),
    ("F10", "blackbox-exporter", "WAF", "monitoring", "TCP 8080 HTTP", "Sondes de disponibilité vues du client", "User-Agent dédié ; même chemin que les utilisateurs", S),
    ("F11", "waf-exporter", "WAF /metrics/nginx", "monitoring", "TCP 8080 HTTP", "stub_status nginx", "allow 172.30.40.0/24 ; deny all", S),
    ("F12", "postgres-exporter", "PostgreSQL", "data", "TCP 5432 PostgreSQL", "Statistiques de la base", "Rôle exporter : pg_monitor (pas d'accès aux tables métier)", S),
    ("F13", "Alloy", "docker-proxy-ro", "dockerapi-ro", "TCP 2375 HTTP (API Docker)", "Découverte des conteneurs et lecture des logs", "GET containers / networks / events uniquement ; POST = 403 ; Alloy non-root", S),
    ("F14", "Alloy", "Loki", "monitoring", "TCP 3100 HTTP push", "Envoi des journaux de tous les conteneurs", "Réseau interne", S),
    ("F15", "Prometheus", "Alertmanager", "monitoring", "TCP 9093 HTTP", "Alertes métriques (dont aiops_anomaly_score)", "Labels remediation / target portés par les règles versionnées", C),
    ("F16", "Loki (ruler)", "Alertmanager", "monitoring", "TCP 9093 HTTP", "Alertes sur logs (WAF burst, brute force, remédiation échouée)", "Règles LogQL versionnées (fonction SOC)", C),
    ("F17", "Alertmanager", "Moteur de remédiation", "monitoring", "TCP 8000 HTTP POST /webhook/alertmanager", "Déclenchement de la remédiation", "Jeton Bearer (Docker secret) ; inhibition des effets de bord ; send_resolved", C),
    ("F18", "Moteur de remédiation", "docker-proxy", "control", "TCP 2375 HTTP (API Docker)", "Redémarrage du service ciblé", "Liste blanche (waf, frontend, auth, payment-api, postgres) ; cooldown 45 s ; proxy : start/stop/restart seuls", C),
    ("F19", "Moteur de remédiation", "txprobe", "monitoring", "TCP 8000 HTTP GET /check", "Preuve de reprise par transaction réelle", "La reprise n'est déclarée réussie qu'après une transaction OK", C),
    ("F20", "Grafana", "Prometheus, Loki, Alertmanager", "monitoring", "TCP 9090 / 3100 / 9093 HTTP", "Visualisation", "Datasources provisionnées ; anonyme en lecture seule (Viewer)", S),
    ("F21", "Opérateur (navigateur du PC Hôte)", "Grafana, Prometheus, Alertmanager, Remédiation", "mgmt (loopback)", "127.0.0.1 : 3000 / 9090 / 9093 / 8090", "Administration et démonstration", "Liés à 127.0.0.1 : inaccessibles depuis le LAN / PC Attaquant", A),
    ("F22", "Runner Ansible", "Docker Engine (+ réseaux edge, mgmt)", "socket local", "unix:///var/run/docker.sock", "Déploiement, vérification, sauvegarde, restauration, PRA, chaos", "Conteneur éphémère lancé par l'opérateur ; silence Alertmanager pendant les opérations", A),
    ("F23", "docker-proxy, docker-proxy-ro, cAdvisor", "Docker Engine / hôte", "socket local", "unix:///var/run/docker.sock (ro)", "Accès API Docker filtré ; métriques cgroups", "Seuls composants à toucher le socket ; aucun port publié", C),
    ("F24", "Assistant RAG (PC IA)", "Ollama", "LAN hotspot", "TCP 11434 HTTP", "Inférence du LLM local (optionnel, 3e poste)", "Pare-feu : PC Hôte uniquement ; aucun accès à la remédiation ni au proxy Docker", A),
]
end = p2.table(20, 60, cols, [list(f[:7]) for f in flows], row_h=46, fills=[f[7] + "33" for f in flows])

p2.text(20, end + 30, 1600, 30, "<font style='font-size:16px'><b>Flux explicitement refusés</b> (testés)</font>")
deny_cols = [("Source", 230), ("Destination", 260), ("Résultat", 260), ("Mécanisme", 645)]
denied = [
    ["PC Attaquant", "PostgreSQL :5432", "injoignable", "port non publié ; réseau data interne"],
    ["PC Attaquant", "Grafana / Prometheus / Alertmanager / Remédiation", "injoignable", "publiés sur 127.0.0.1 uniquement"],
    ["PC Attaquant", "WAF avec injection SQL (?id=1' OR 1=1--)", "HTTP 403", "OWASP CRS (règles 942xxx) ; journalisé dans Loki"],
    ["PC Attaquant (flood)", "WAF /api/*", "HTTP 429", "limit_req 20 r/s par IP, burst 40"],
    ["Conteneurs app / data / monitoring", "Internet", "aucune route", "réseaux Docker internal: true (anti-exfiltration)"],
    ["Moteur de remédiation", "docker-proxy : create / exec / kill / images / volumes", "HTTP 403", "configuration HAProxy durcie (infra/docker-proxy)"],
    ["Moteur de remédiation", "conteneur hors liste blanche", "refusé", "remediation_refused journalisé"],
    ["Tiers sans jeton", "webhook de remédiation", "HTTP 401", "Bearer token (Docker secret remediation_token)"],
]
p2.table(20, end + 70, deny_cols, denied, header_fill="#b85450", row_h=36)

# =========================================================================== PAGE 3
p3 = Page("3 - Inventaire serveurs", 1700, 1300)
p3.text(20, 10, 1600, 30, "<font style='font-size:20px'><b>Inventaire</b> — machines physiques et conteneurs</font>")
mcols = [("Machine", 150), ("Adresse", 170), ("Système", 260), ("Ressources", 250), ("Rôle", 330), ("Exposition", 330)]
machines = [
    ["PC Hôte", "192.168.137.1 (hotspot)", "Windows 11 · Docker Desktop 29 (WSL2)", "4+ cœurs · 16 Go (6–8 Go pour Docker) · 50 Go SSD", "Exécute les 18 conteneurs + runner Ansible", "80/tcp sur le hotspot ; admin sur 127.0.0.1"],
    ["PC Attaquant", "192.168.137.x (DHCP)", "Kali Linux / outils Red Team", "8–16 Go RAM", "Scénarios offensifs depuis un poste distinct", "Aucune ; cible autorisée = 192.168.137.1:80"],
    ["PC IA (optionnel)", "192.168.137.y (DHCP)", "Windows / Linux · Ollama", "16 Go RAM, GPU conseillé", "LLM ≤ 8B + assistant RAG LangChain", "11434/tcp vers le PC Hôte uniquement"],
]
end = p3.table(20, 60, mcols, machines, row_h=46)

ccols = [("Service", 140), ("Image", 270), ("Rôle", 190), ("Port interne", 90), ("Publication", 130),
         ("Réseaux", 230), ("Utilisateur", 130), ("Lim. RAM", 80), ("Durcissement", 230)]
containers = [
    ["waf", "owasp/modsecurity-crs:4.25.2-nginx-alpine-lts", "WAF / reverse proxy", "8080", "0.0.0.0:80", "edge, app, monitoring", "nginx (101)", "256 Mo", "cap_drop ALL, no-new-privileges"],
    ["frontend", "resilience/frontend (nginx-unprivileged)", "Frontal web", "8080", "—", "app", "nginx (101)", "64 Mo", "FS lecture seule"],
    ["auth", "resilience/auth (python 3.12)", "Authentification JWT", "8000", "—", "app, data, monitoring", "10001", "192 Mo", "FS lecture seule, secrets fichiers"],
    ["payment-api", "resilience/payment-api (python 3.12)", "API de paiement", "8000", "—", "app, data, monitoring", "10001", "192 Mo", "FS lecture seule, secrets fichiers"],
    ["postgres", "postgres:16-alpine", "Base de données", "5432", "—", "data", "postgres (70)", "512 Mo", "FS lecture seule, rôles moindre privilège"],
    ["prometheus", "prom/prometheus:v3.5.0", "Métriques + règles", "9090", "127.0.0.1:9090", "monitoring, mgmt", "nobody", "512 Mo", "cap_drop ALL"],
    ["alertmanager", "prom/alertmanager:v0.28.1", "Routage des alertes", "9093", "127.0.0.1:9093", "monitoring, mgmt", "nobody", "128 Mo", "cap_drop ALL"],
    ["loki", "grafana/loki:3.5.3", "Logs + ruler SOC", "3100", "—", "monitoring", "10001", "512 Mo", "cap_drop ALL"],
    ["alloy", "grafana/alloy:v1.10.0", "Collecte des logs", "12345", "—", "monitoring, dockerapi-ro", "alloy", "256 Mo", "pas de socket Docker direct"],
    ["grafana", "grafana/grafana:12.1.0", "Visualisation", "3000", "127.0.0.1:3000", "monitoring, mgmt", "472", "384 Mo", "provisioning en lecture seule"],
    ["blackbox", "prom/blackbox-exporter:v0.27.0", "Sondes HTTP", "9115", "—", "monitoring", "nobody", "64 Mo", "cap_drop ALL"],
    ["waf-exporter", "nginx/nginx-prometheus-exporter:1.4.2", "Métriques WAF", "9113", "—", "monitoring", "nobody", "32 Mo", "cap_drop ALL"],
    ["postgres-exporter", "prometheuscommunity/postgres-exporter:v0.17.1", "Métriques BDD", "9187", "—", "data, monitoring", "nobody", "64 Mo", "rôle pg_monitor"],
    ["cadvisor", "gcr.io/cadvisor/cadvisor:v0.55.1", "Métriques conteneurs", "8080", "—", "monitoring", "root", "256 Mo", "privilégié (exception documentée)"],
    ["txprobe", "resilience/txprobe (python 3.12)", "Transaction synthétique", "8000", "—", "app, monitoring", "10001", "128 Mo", "FS lecture seule"],
    ["remediation", "resilience/remediation (python 3.12)", "Moteur de remédiation", "8000", "127.0.0.1:8090", "monitoring, control, mgmt", "10001", "128 Mo", "liste blanche, jeton, via proxy"],
    ["docker-proxy", "tecnativa/docker-socket-proxy:v0.4.2", "API Docker filtrée (rw)", "2375", "—", "control", "haproxy", "64 Mo", "HAProxy durci : start/stop/restart"],
    ["docker-proxy-ro", "tecnativa/docker-socket-proxy:v0.4.2", "API Docker lecture seule", "2375", "—", "dockerapi-ro", "haproxy", "64 Mo", "POST interdit"],
]
end = p3.table(20, end + 40, ccols, containers, row_h=32)
p3.text(20, end + 15, 1600, 40, "Mesuré au repos : ~0,95 Go de RAM pour les 18 conteneurs. Volumes : pgdata, prometheus-data, "
        "loki-data, grafana-data, alertmanager-data, alloy-data. Secrets : ./secrets (Docker secrets, non versionnés).")

doc = ('<mxfile host="app.diagrams.net" type="device">'
       + "".join(p.xml(i) for i, p in enumerate((p1, p2, p3), 1)) + "</mxfile>")
OUT.write_text(doc, encoding="utf-8")
print(f"OK -> {OUT}")
