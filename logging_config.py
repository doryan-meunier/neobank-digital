"""
logging_config.py - Configuration du logging structuré JSON pour NeoBank Digital
Livrable 3.4 : Logging de sécurité complet (V9)

Structure JSON avec correlationId pour les systèmes de monitoring (SIEM, ELK, CloudWatch).
RÈGLE : Aucune donnée sensible (mot de passe, token, IBAN complet, numéro de carte) dans les logs.
"""

import logging
import logging.config
import os
import uuid
from contextvars import ContextVar
from pythonjsonlogger import jsonlogger

# ── Variable de contexte pour propager le correlationId entre fonctions ──────
correlation_id_var: ContextVar[str] = ContextVar("correlation_id", default="")


def get_correlation_id() -> str:
    """Retourne le correlationId de la requête courante, ou en génère un."""
    cid = correlation_id_var.get("")
    if not cid:
        cid = str(uuid.uuid4())
        correlation_id_var.set(cid)
    return cid


class CorrelationIdFilter(logging.Filter):
    """Injecte le correlationId dans chaque enregistrement de log."""

    def filter(self, record: logging.LogRecord) -> bool:
        record.correlation_id = get_correlation_id()
        return True


class SensitiveDataFilter(logging.Filter):
    """
    V9 : Masque les données sensibles avant l'écriture sur les sorties de logging.
    Évite que des tokens ou mots de passe soient accidentellement loggués.
    """

    SENSITIVE_FIELDS = {"password", "token", "secret", "authorization", "card_number", "cvv"}

    def filter(self, record: logging.LogRecord) -> bool:
        if isinstance(record.msg, dict):
            record.msg = self._mask_dict(record.msg)
        return True

    def _mask_dict(self, data: dict) -> dict:
        return {
            k: "***MASQUÉ***" if k.lower() in self.SENSITIVE_FIELDS else v
            for k, v in data.items()
        }


def configure_logging() -> None:
    """
    Configure le système de logging pour toute l'application.
    Appelé une seule fois au démarrage (main.py).
    """
    log_level = os.environ.get("LOG_LEVEL", "INFO").upper()
    log_file = os.environ.get("LOG_FILE")

    handlers: list[logging.Handler] = [logging.StreamHandler()]
    if log_file:
        handlers.append(logging.FileHandler(log_file, encoding="utf-8"))

    for handler in handlers:
        handler.setFormatter(
            jsonlogger.JsonFormatter(
                fmt="%(asctime)s %(levelname)s %(name)s %(message)s",
                datefmt="%Y-%m-%dT%H:%M:%S",
                rename_fields={"asctime": "timestamp", "levelname": "level"},
            )
        )
        handler.addFilter(CorrelationIdFilter())
        handler.addFilter(SensitiveDataFilter())

    logging.basicConfig(level=log_level, handlers=handlers, force=True)

    # Silence des loggers bruités (SQLAlchemy, uvicorn access)
    logging.getLogger("sqlalchemy.engine").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
