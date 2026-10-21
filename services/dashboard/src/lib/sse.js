// Lecture du flux temps réel du moteur (GET /events, Server-Sent Events).
// EventSource ne sait pas envoyer l'en-tête Authorization : on lit donc le flux avec fetch() en streaming.
// Le jeton ne passe jamais dans l'URL, où il finirait dans les logs (contracts/openapi-remediation.yaml).

export class Unauthorized extends Error {}

/**
 * Découpe un texte SSE en événements complets. Renvoie les événements et le reste
 * (un événement coupé en deux par le réseau attend le morceau suivant).
 */
export function parseSse(buffer) {
  const events = [];
  const blocks = buffer.replace(/\r\n/g, "\n").split("\n\n");
  const rest = blocks.pop();
  for (const block of blocks) {
    let event = "message";
    const data = [];
    for (const line of block.split("\n")) {
      if (line.startsWith("event:")) event = line.slice(6).trim();
      else if (line.startsWith("data:")) data.push(line.slice(5).trimStart());
    }
    if (data.length) events.push({ event, data: JSON.parse(data.join("\n")) });
  }
  return { events, rest };
}

/** Lit le flux jusqu'à sa fin ou jusqu'à `signal.abort()`. */
export async function readEvents(url, token, onEvent, signal) {
  const response = await fetch(url, { headers: { Authorization: `Bearer ${token}` }, signal });
  if (response.status === 401 || response.status === 403) throw new Unauthorized();
  if (!response.ok || !response.body) throw new Error(`HTTP ${response.status}`);

  const reader = response.body.getReader();
  const decoder = new TextDecoder();
  let buffer = "";
  for (;;) {
    const { value, done } = await reader.read();
    if (done) return;
    buffer += decoder.decode(value, { stream: true });
    const { events, rest } = parseSse(buffer);
    buffer = rest;
    events.forEach(onEvent);
  }
}
