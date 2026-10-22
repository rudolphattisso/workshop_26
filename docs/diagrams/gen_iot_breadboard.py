"""Génère la vue breadboard du câblage LED (Freenove ESP32-WROVER + carte d'extension GPIO)."""
import sys

PITCH = 22
X0 = 170
NCOLS = 34
def cx(c):
    return X0 + (c - 1) * PITCH

TOP_ROWS = [150, 168, 186, 204, 222]
BOT_ROWS = [268, 286, 304, 322, 340]
RAIL_TOP = {"EXT-3.3V": 92, "GND": 110}
RAIL_BOT = {"5V": 390, "GND": 408}

# Rangée basse de la carte d'extension, colonne 2 à 21
BOTTOM_PINS = ["3.3V", "EN", "36", "39", "34", "35", "32", "33", "25", "26", "27",
               "14", "12", "GND", "13", "3.3V", "3.3V", "3.3V", "5V", "5V"]
PIN_COL = {name: 2 + i for i, name in enumerate(BOTTOM_PINS) if name in ("14", "13", "GND")}
EXT_LAST_COL = 22

GREEN, RED, BLACK = "#16a34a", "#dc2626", "#111827"
o = []
a = o.append

a('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 1010 560" width="1010" height="560" '
  'font-family="Segoe UI, Helvetica, Arial, sans-serif">')
a("<title>Câblage breadboard — Freenove ESP32-WROVER + carte d'extension GPIO, LED verte (13) et rouge (14)</title>")
a('<rect width="1010" height="560" fill="#ffffff"/>')
a('<text x="20" y="30" font-size="16" font-weight="700" fill="#1f2933">Câblage des LED sur la breadboard (vue de dessus)</text>')
a('<text x="20" y="50" font-size="12" fill="#374151">Freenove ESP32-WROVER + GPIO Extension Board · LED verte sur 13, LED rouge sur 14 · cathodes sur le rail GND</text>')

# Breadboard
a('<rect x="150" y="72" width="770" height="352" rx="8" fill="#f3f4f6" stroke="#9ca3af"/>')
for name, y in {**RAIL_TOP, **RAIL_BOT}.items():
    a(f'<line x1="160" y1="{y}" x2="910" y2="{y}" stroke="#d1d5db" stroke-width="10" stroke-linecap="round"/>')
    for c in range(1, NCOLS + 1):
        a(f'<rect x="{cx(c)-3}" y="{y-3}" width="6" height="6" fill="#6b7280"/>')
a(f'<text x="928" y="{RAIL_TOP["EXT-3.3V"]+4}" font-size="11" fill="#6b7280">EXT-3.3V</text>')
a(f'<text x="928" y="{RAIL_TOP["GND"]+4}" font-size="11" font-weight="700" fill="{BLACK}">GND</text>')
a(f'<text x="928" y="{RAIL_BOT["5V"]+4}" font-size="11" fill="#6b7280">5V</text>')
a(f'<text x="928" y="{RAIL_BOT["GND"]+4}" font-size="11" font-weight="700" fill="{BLACK}">GND</text>')
for y in TOP_ROWS + BOT_ROWS:
    for c in range(1, NCOLS + 1):
        a(f'<rect x="{cx(c)-3}" y="{y-3}" width="6" height="6" fill="#9ca3af"/>')
a('<rect x="160" y="240" width="750" height="10" fill="#e5e7eb"/>')
a('<text x="535" y="248" font-size="9" fill="#6b7280" text-anchor="middle">tranchée centrale</text>')

# Carte ESP32 (hors breadboard, à gauche)
a('<rect x="20" y="120" width="140" height="190" rx="8" fill="#1e3a5f" stroke="#0f1f33" stroke-width="2"/>')
a('<circle cx="90" cy="175" r="16" fill="#111827" stroke="#9ca3af" stroke-width="3"/>')
a('<text x="90" y="222" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff">Freenove</text>')
a('<text x="90" y="238" text-anchor="middle" font-size="12" font-weight="700" fill="#ffffff">ESP32-WROVER</text>')
a('<text x="90" y="254" text-anchor="middle" font-size="10" fill="#cbd5e1">caméra non utilisée</text>')
a('<rect x="66" y="296" width="48" height="22" rx="4" fill="#9ca3af" stroke="#6b7280"/>')
a('<text x="90" y="336" text-anchor="middle" font-size="10" fill="#374151">USB-C → PC Hôte</text>')

# Carte d'extension : corps + languettes d'alimentation
ext_right = cx(EXT_LAST_COL) + 12
a(f'<rect x="150" y="128" width="{ext_right-150}" height="150" rx="6" fill="#111827" opacity="0.93"/>')
a(f'<text x="{(150+ext_right)/2}" y="176" text-anchor="middle" font-size="13" font-weight="700" fill="#e5e7eb">GPIO Extension Board</text>')
a(f'<text x="{(150+ext_right)/2}" y="194" text-anchor="middle" font-size="10" fill="#9ca3af">rangée du haut : non utilisée ici</text>')
tab_x = cx(EXT_LAST_COL) - 26
a(f'<rect x="{tab_x}" y="84" width="38" height="46" rx="4" fill="#111827" opacity="0.93"/>')
a(f'<rect x="{tab_x}" y="276" width="38" height="140" rx="4" fill="#111827" opacity="0.93"/>')
for y in list(RAIL_TOP.values()) + list(RAIL_BOT.values()):
    a(f'<circle cx="{tab_x+19}" cy="{y}" r="4" fill="#fbbf24"/>')

# Broches de la rangée basse (dans la rangée f de la breadboard)
for i, name in enumerate(BOTTOM_PINS):
    x = cx(2 + i)
    hl = {"14": RED, "13": GREEN, "GND": "#e5e7eb"}.get(name)
    if hl:
        a(f'<rect x="{x-11}" y="216" width="22" height="40" rx="3" fill="{hl}"/>')
    fill = "#111827" if name == "GND" else "#ffffff"
    a(f'<text x="{x}" y="250" text-anchor="middle" font-size="8.5" font-weight="700" fill="{fill}" '
      f'transform="rotate(-90 {x} 246)">{name}</text>')
    a(f'<circle cx="{x}" cy="{BOT_ROWS[0]}" r="4" fill="#fbbf24" stroke="#92400e"/>')

def wire(points, color, halo=False):
    pts = " ".join(f"{x},{y}" for x, y in points)
    if halo:
        a(f'<polyline points="{pts}" fill="none" stroke="#ffffff" stroke-width="9" stroke-linejoin="round"/>')
    a(f'<polyline points="{pts}" fill="none" stroke="{color}" stroke-width="4.5" stroke-linecap="round" stroke-linejoin="round"/>')
    for x, y in (points[0], points[-1]):
        a(f'<circle cx="{x}" cy="{y}" r="4.5" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>')

def resistor(c1, c2, y, label):
    x1, x2 = cx(c1), cx(c2)
    a(f'<line x1="{x1}" y1="{y}" x2="{x2}" y2="{y}" stroke="#6b7280" stroke-width="2"/>')
    mid = (x1 + x2) / 2
    a(f'<rect x="{mid-16}" y="{y-7}" width="32" height="14" rx="5" fill="#e8d5b5" stroke="#7c5e2a" stroke-width="1.5"/>')
    for dx, col in ((-9, RED), (-3, RED), (3, "#7c3f00")):
        a(f'<rect x="{mid+dx}" y="{y-7}" width="3" height="14" fill="{col}"/>')
    for x in (x1, x2):
        a(f'<circle cx="{x}" cy="{y}" r="3" fill="#6b7280"/>')
    a(f'<text x="{mid}" y="{y-11}" text-anchor="middle" font-size="10" fill="#1f2933" font-weight="600">{label}</text>')

def led(c_anode, c_cathode, y, color, name):
    xa, xk = cx(c_anode), cx(c_cathode)
    mid = (xa + xk) / 2
    a(f'<line x1="{xa}" y1="{y}" x2="{mid-4}" y2="{y-14}" stroke="#6b7280" stroke-width="2"/>')
    a(f'<line x1="{xk}" y1="{y}" x2="{mid+4}" y2="{y-14}" stroke="#6b7280" stroke-width="2"/>')
    a(f'<circle cx="{mid}" cy="{y-20}" r="10" fill="{color}" stroke="#1f2933" stroke-width="1.5"/>')
    a(f'<circle cx="{xa}" cy="{y}" r="3" fill="#6b7280"/><circle cx="{xk}" cy="{y}" r="3" fill="#6b7280"/>')
    a(f'<text x="{xa-4}" y="{y+14}" text-anchor="middle" font-size="10" font-weight="700" fill="{color}">+</text>')
    a(f'<text x="{xk+4}" y="{y+14}" text-anchor="middle" font-size="10" font-weight="700" fill="#1f2933">−</text>')
    a(f'<rect x="{mid-34}" y="198" width="68" height="20" rx="4" fill="#ffffff" stroke="{color}"/>')
    a(f'<text x="{mid}" y="212" text-anchor="middle" font-size="11" font-weight="700" fill="{color}">{name}</text>')

# Montage LED verte : broche 13 → col 25 → R → col 27 = anode, cathode col 28 → rail GND
gA, gB, gC = 25, 27, 28
# Montage LED rouge : broche 14 → col 30 → R → col 32 = anode, cathode col 33 → rail GND
rA, rB, rC = 30, 32, 33
row_j, row_h, row_i = BOT_ROWS[4], BOT_ROWS[2], BOT_ROWS[3]

# Fil rouge (passe sous le fil vert, dans l'espace avant les rails)
wire([(cx(PIN_COL["14"]), row_j), (cx(PIN_COL["14"]), 376), (cx(rA), 376), (cx(rA), row_j)], RED)
wire([(cx(PIN_COL["13"]), row_j), (cx(PIN_COL["13"]), 360), (cx(gA), 360), (cx(gA), row_j)], GREEN)
resistor(gA, gB, BOT_ROWS[1], "220 Ω")
resistor(rA, rB, BOT_ROWS[1], "220 Ω")
# anodes reliées à la résistance par la colonne ; LED plantée rangée i
led(gB, gC, row_i, GREEN, "LED verte")
led(rB, rC, row_i, RED, "LED rouge")
# Fils noirs : cathode → rail GND (enjambent le rail 5V)
wire([(cx(gC), row_j), (cx(gC), RAIL_BOT["GND"])], BLACK, halo=True)
wire([(cx(rC), row_j), (cx(rC), RAIL_BOT["GND"])], BLACK, halo=True)

# Repères de colonnes
for c, txt in ((gA, "A"), (gB, "B"), (gC, "C"), (rA, "A"), (rB, "B"), (rC, "C")):
    a(f'<text x="{cx(c)}" y="140" text-anchor="middle" font-size="10" font-weight="700" fill="#374151">{txt}</text>')
a(f'<text x="{(cx(gA)+cx(rC))/2}" y="124" text-anchor="middle" font-size="11" fill="#374151">zone libre (à droite de la carte d\'extension)</text>')

# Légende
leg = [
    "① Fil : trou libre sous la broche (13 ou 14) → colonne libre A.",
    "② Résistance 220 Ω : colonne A → colonne B.",
    "③ LED : patte longue (+) dans B, patte courte (−) dans C.",
    "④ Fil noir : colonne C → rail GND du bas (le plus à l'extérieur, PAS le rail 5V).",
    "Chaque colonne de 5 trous est reliée verticalement ; les rails sont reliés horizontalement. Les couleurs imprimées sur la",
    "breadboard ne comptent pas : seules les étiquettes de la carte d'extension (5V / GND / EXT-3.3V) font foi.",
]
for i, t in enumerate(leg):
    a(f'<text x="20" y="{452+i*17}" font-size="12" fill="#1f2933">{t}</text>')
a("</svg>")

open(sys.argv[1], "w", encoding="utf-8").write("\n".join(o))
