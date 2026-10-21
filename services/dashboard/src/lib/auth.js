// Connexion opérateur : même service d'auth que le front client, relayé par le nginx du dashboard.

export async function login(username, password) {
  let response;
  try {
    response = await fetch("/api/auth/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username, password }),
    });
  } catch {
    throw new Error("Service d'authentification injoignable.");
  }
  const data = await response.json().catch(() => null);
  if (!response.ok) throw new Error(data?.title ?? `Erreur ${response.status}`);
  return data.access_token;
}

/** Contenu du JWT, pour l'affichage seulement : le moteur vérifie lui-même la signature et le rôle. */
export function readToken(token) {
  const claims = JSON.parse(atob(token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/")));
  return { role: claims.role, expiresAt: claims.exp * 1000 };
}
