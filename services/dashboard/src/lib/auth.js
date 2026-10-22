// Connexion opérateur : même service d'auth que le front client, relayé par le nginx du dashboard.

async function post(path, body) {
  let response;
  try {
    response = await fetch(path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
  } catch {
    throw new Error("Service d'authentification injoignable.");
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.title ?? `Erreur ${response.status}`);
  return data;
}

/** Étape 1 (consigne additionnelle 1) : l'identifiant est-il celui d'un opérateur ? Pilote aussi la LED. */
export async function identify(username) {
  return (await post("/api/auth/login/identify", { username })).recognized;
}

export async function login(username, password) {
  return (await post("/api/auth/login", { username, password })).access_token;
}

/** Contenu du JWT, pour l'affichage seulement : le moteur vérifie lui-même la signature et le rôle. */
export function readToken(token) {
  const claims = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  return { role: claims.role, expiresAt: claims.exp * 1000 };
}
