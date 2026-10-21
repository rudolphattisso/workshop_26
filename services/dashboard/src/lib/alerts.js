// Popups d'alerte : chaque changement d'état publié par le watchdog devient une notification.
// Logique pure (sans React) pour être testée : quels changements sont nouveaux, et comment les présenter.

const changeKey = (c) => `${c.at}|${c.id}|${c.to}`;

/**
 * Changements pas encore vus, du plus ancien au plus récent (le watchdog les publie du plus récent au plus ancien).
 * `seen` est mis à jour. Au premier appel (`firstLoad`), tout est marqué comme vu sans rien renvoyer :
 * on n'affiche pas en popup l'historique d'avant l'ouverture du dashboard.
 */
export function takeNewChanges(changes, seen, firstLoad) {
  const fresh = [];
  for (const change of [...changes].reverse()) {
    const key = changeKey(change);
    if (seen.has(key)) continue;
    seen.add(key);
    if (!firstLoad) fresh.push(change);
  }
  return fresh;
}

/**
 * Notification à afficher pour un changement, ou null s'il ne mérite pas d'interrompre l'opérateur.
 * - panne : reste affichée jusqu'au retour à la normale ou fermeture manuelle ;
 * - dégradé / plus mesurable : avertissement, disparaît seul ;
 * - retour à la normale après un incident : confirmation, avec la durée de l'interruption si on la connaît.
 */
export function toAlert(change, downSince) {
  const base = { id: changeKey(change), target: change.id, title: change.label, detail: change.detail, at: change.at };
  if (change.to === "down") {
    return { ...base, level: "critical", heading: "Panne détectée", sticky: true };
  }
  if (change.to === "degraded") {
    return { ...base, level: "warning", heading: "Service dégradé", timeoutMs: 15000 };
  }
  if (change.to === "unknown") {
    return { ...base, level: "warning", heading: "Plus mesurable", timeoutMs: 15000 };
  }
  if (change.to === "up" && change.from !== "up") {
    const since = downSince?.[change.id];
    const seconds = since ? Math.max(0, Math.round((Date.parse(change.at) - Date.parse(since)) / 1000)) : null;
    return {
      ...base,
      level: "recovered",
      heading: "Rétabli",
      detail: seconds !== null ? `Interruption de ${seconds} s` : change.detail,
      timeoutMs: 10000,
    };
  }
  return null;
}

/**
 * Mémorise le début de chaque interruption, du plus ancien au plus récent : dès qu'un élément quitte « up »
 * (panne, dégradé ou plus mesurable), jusqu'à son retour à « up ». Sert à annoncer la durée au retour.
 */
export function trackOutages(changes, since) {
  for (const change of changes) {
    if (change.to === "up") delete since[change.id];
    else if (change.from === "up" || !(change.id in since)) since[change.id] = change.at;
  }
}

/**
 * Une seule popup par passage du watchdog et par niveau : une panne de base change 5 éléments à la fois
 * (base, API, deux connexions, transaction), l'opérateur doit voir un incident, pas 5 popups.
 */
export function groupAlerts(alerts) {
  const groups = new Map();
  for (const alert of alerts) {
    const id = `${alert.at}|${alert.level}`;
    const group = groups.get(id) ?? {
      id,
      level: alert.level,
      heading: alert.heading,
      at: alert.at,
      sticky: alert.sticky ?? false,
      timeoutMs: alert.timeoutMs,
      items: [],
    };
    group.items.push({ target: alert.target, title: alert.title, detail: alert.detail });
    groups.set(id, group);
  }
  return [...groups.values()];
}

/** Retire des popups de panne les éléments rétablis ; une popup vide disparaît. */
export function dropRecovered(popups, recoveredTargets) {
  return popups
    .map((popup) =>
      popup.level === "recovered" ? popup : { ...popup, items: popup.items.filter((i) => !recoveredTargets.has(i.target)) },
    )
    .filter((popup) => popup.items.length > 0);
}
