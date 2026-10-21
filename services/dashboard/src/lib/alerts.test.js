import { describe, expect, it } from "vitest";
import { dropRecovered, groupAlerts, takeNewChanges, toAlert } from "./alerts.js";

const change = (id, from, to, at = "2026-10-22T10:00:00+00:00") => ({
  at,
  id,
  kind: "node",
  label: id,
  from,
  to,
  detail: "détail",
});

describe("takeNewChanges", () => {
  it("n'affiche pas l'historique à l'ouverture du dashboard", () => {
    const seen = new Set();
    expect(takeNewChanges([change("auth", "up", "down")], seen, true)).toEqual([]);
    expect(seen.size).toBe(1);
  });

  it("renvoie seulement les nouveaux changements, du plus ancien au plus récent", () => {
    const seen = new Set();
    const old = change("auth", "up", "down", "2026-10-22T10:00:00+00:00");
    takeNewChanges([old], seen, true);
    const a = change("payment-db", "up", "down", "2026-10-22T10:01:00+00:00");
    const b = change("payment-db", "down", "up", "2026-10-22T10:02:00+00:00");
    // publié du plus récent au plus ancien
    expect(takeNewChanges([b, a, old], seen, false)).toEqual([a, b]);
    expect(takeNewChanges([b, a, old], seen, false)).toEqual([]); // déjà vus : pas de doublon à la reconnexion
  });
});

describe("toAlert", () => {
  it("une panne reste affichée", () => {
    expect(toAlert(change("auth", "up", "down"))).toMatchObject({ level: "critical", sticky: true });
  });

  it("un service dégradé est un avertissement", () => {
    expect(toAlert(change("payment-api", "up", "degraded"))).toMatchObject({ level: "warning" });
  });

  it("le retour à la normale indique la durée de l'interruption", () => {
    const back = change("auth", "down", "up", "2026-10-22T10:00:42+00:00");
    const alert = toAlert(back, { auth: "2026-10-22T10:00:00+00:00" });
    expect(alert).toMatchObject({ level: "recovered", detail: "Interruption de 42 s" });
  });

  it("ignore ce qui n'est pas un changement utile", () => {
    expect(toAlert(change("auth", "up", "up"))).toBeNull();
  });
});

describe("groupAlerts / dropRecovered", () => {
  const at = "2026-10-22T10:00:00+00:00";
  const down = ["payment-db", "payment-api->payment-db", "smoke-test->bunkerweb"].map((id) => toAlert(change(id, "up", "down", at)));

  it("une panne qui touche plusieurs éléments donne une seule popup", () => {
    const popups = groupAlerts([...down, toAlert(change("payment-api", "up", "degraded", at))]);
    expect(popups.map((p) => [p.level, p.items.length])).toEqual([
      ["critical", 3],
      ["warning", 1],
    ]);
  });

  it("la popup de panne se vide au fur et à mesure des retours, puis disparaît", () => {
    let popups = groupAlerts(down);
    popups = dropRecovered(popups, new Set(["payment-db"]));
    expect(popups[0].items.map((i) => i.target)).toEqual(["payment-api->payment-db", "smoke-test->bunkerweb"]);
    popups = dropRecovered(popups, new Set(["payment-api->payment-db", "smoke-test->bunkerweb"]));
    expect(popups).toEqual([]);
  });
});
