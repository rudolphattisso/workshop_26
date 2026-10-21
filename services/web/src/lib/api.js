// Accès à l'API métier. Toujours la même origine (/api/...) : en production, le WAF route vers
// auth et payment-api ; pas de CORS à ouvrir, pas d'URL de back-end dans le code du navigateur.

export class ApiError extends Error {
  constructor(status, title, body) {
    super(title);
    this.status = status;
    this.body = body;
  }
}

async function request(path, { token, method = "GET", body, headers = {} } = {}) {
  let response;
  try {
    response = await fetch(path, {
      method,
      headers: {
        ...(body ? { "Content-Type": "application/json" } : {}),
        ...(token ? { Authorization: `Bearer ${token}` } : {}),
        ...headers,
      },
      body: body ? JSON.stringify(body) : undefined,
    });
  } catch {
    throw new ApiError(0, "Service injoignable. Réessayez dans quelques secondes.");
  }

  const data = await response.json().catch(() => null);
  // Un paiement refusé (422) est une réponse métier normale, renvoyée telle quelle à l'appelant.
  if (response.ok || (response.status === 422 && data?.status === "REJECTED")) {
    return { status: response.status, data };
  }
  // Erreurs au format RFC 9457 (application/problem+json) : « title » est lisible par un humain.
  const fallback = response.status === 429 ? "Trop de tentatives, patientez un instant." : `Erreur ${response.status}`;
  throw new ApiError(response.status, data?.title ?? fallback, data);
}

export async function login(username, password) {
  const { data } = await request("/api/auth/login", { method: "POST", body: { username, password } });
  return data.access_token;
}

export async function getAccounts(token) {
  return (await request("/api/accounts", { token })).data;
}

export async function getPayments(token) {
  return (await request("/api/payments?limit=20", { token })).data;
}

/**
 * La même idempotencyKey pour un même paiement : si le réseau coupe et que l'utilisateur réessaie,
 * l'API renvoie le paiement d'origine (200) au lieu de débiter deux fois.
 */
export async function createPayment(token, idempotencyKey, payment) {
  return request("/api/payments", {
    token,
    method: "POST",
    body: payment,
    headers: { "Idempotency-Key": idempotencyKey },
  });
}

/** Lecture du contenu du JWT pour l'affichage uniquement : c'est le serveur qui vérifie la signature et les droits. */
export function readToken(token) {
  const payload = token.split(".")[1].replace(/-/g, "+").replace(/_/g, "/");
  const claims = JSON.parse(atob(payload));
  return { userId: claims.sub, role: claims.role, expiresAt: claims.exp * 1000 };
}
