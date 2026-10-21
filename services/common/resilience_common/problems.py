"""Erreurs au format RFC 9457 (`application/problem+json`), avec le trace_id pour l'investigation.

Une exception non prévue ne renvoie jamais de trace Python au client : elle est logguée côté serveur
et le client reçoit un 500 générique.
"""

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from resilience_common.logs import trace_id_var

PROBLEM_MEDIA_TYPE = "application/problem+json"


def problem(status: int, title: str, detail: str | None = None, headers: dict | None = None) -> JSONResponse:
    body = {"type": "about:blank", "title": title, "status": status, "trace_id": trace_id_var.get()}
    if detail:
        body["detail"] = detail
    return JSONResponse(body, status_code=status, media_type=PROBLEM_MEDIA_TYPE, headers=headers)


def register_problem_handlers(app: FastAPI) -> None:
    @app.exception_handler(StarletteHTTPException)
    def http_error(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        title = exc.detail if isinstance(exc.detail, str) else "Erreur"
        return problem(exc.status_code, title, headers=getattr(exc, "headers", None))

    @app.exception_handler(RequestValidationError)
    def validation_error(request: Request, exc: RequestValidationError) -> JSONResponse:
        # On indique le champ fautif sans renvoyer la valeur reçue (pas d'écho de données dans l'erreur).
        fields = ", ".join(".".join(str(p) for p in err["loc"]) for err in exc.errors())
        return problem(400, "Requête invalide", f"Champs invalides : {fields}")

    # Les exceptions non prévues sont interceptées par ObservabilityMiddleware (500 avec trace_id).
