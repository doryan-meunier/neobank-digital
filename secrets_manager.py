"""
secrets_manager.py - Gestion sécurisée des secrets pour NeoBank Digital
Livrable 3.1 : Intégration AWS Secrets Manager (V4)

Ce module permet de récupérer les secrets depuis AWS Secrets Manager
en production, tout en tombant en fallback sur les variables d'environnement
en développement.
"""

import json
import logging
import os
from functools import lru_cache
from typing import Any

import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from dotenv import load_dotenv

load_dotenv()

logger = logging.getLogger("neobank.secrets")

APP_ENV = os.environ.get("APP_ENV", "development")
AWS_REGION = os.environ.get("AWS_REGION", "eu-west-1")
AWS_SECRET_ARN = os.environ.get("AWS_SECRET_ARN")


@lru_cache(maxsize=None)
def _get_aws_secrets() -> dict[str, Any]:
    """
    Récupère tous les secrets depuis AWS Secrets Manager.
    Le résultat est mis en cache pour éviter des appels répétés.

    En cas d'erreur AWS, lève une exception critique car les secrets
    sont indispensables au démarrage de l'application.
    """
    if not AWS_SECRET_ARN:
        raise EnvironmentError(
            "AWS_SECRET_ARN est requis en production. "
            "Consultez .env.example pour la configuration."
        )

    try:
        client = boto3.client("secretsmanager", region_name=AWS_REGION)
        response = client.get_secret_value(SecretId=AWS_SECRET_ARN)
        secret_string = response.get("SecretString")
        if not secret_string:
            raise ValueError("Le secret AWS est vide ou binaire (non supporté).")
        return json.loads(secret_string)

    except ClientError as exc:
        error_code = exc.response["Error"]["Code"]
        logger.critical(
            "Impossible de récupérer les secrets AWS",
            extra={"event": "secrets_fetch_error", "error_code": error_code},
        )
        raise RuntimeError(f"Erreur AWS Secrets Manager ({error_code}).") from exc

    except NoCredentialsError as exc:
        logger.critical("Credentials AWS absentes ou invalides.")
        raise RuntimeError("Credentials AWS manquantes.") from exc


def get_secret(key: str, fallback_env_var: str | None = None) -> str:
    """
    Récupère un secret par clé.

    En production  : depuis AWS Secrets Manager (sécurisé).
    En développement : depuis les variables d'environnement locales.

    Args:
        key: Clé du secret dans AWS Secrets Manager.
        fallback_env_var: Nom de la variable d'environnement de fallback (dev).

    Returns:
        La valeur du secret.

    Raises:
        EnvironmentError: Si le secret est introuvable.
    """
    if APP_ENV == "production":
        secrets = _get_aws_secrets()
        value = secrets.get(key)
        if not value:
            raise EnvironmentError(
                f"Le secret '{key}' est introuvable dans AWS Secrets Manager."
            )
        return value

    # En développement : utilise les variables d'environnement
    env_var = fallback_env_var or key.upper().replace("-", "_")
    value = os.environ.get(env_var)
    if not value:
        raise EnvironmentError(
            f"La variable d'environnement '{env_var}' est requise. "
            "Consultez .env.example."
        )
    return value


# ─────────────────────────────────────────────────────────────────────────────
# Accesseurs nommés (pour une utilisation pratique dans le code)
# ─────────────────────────────────────────────────────────────────────────────

def get_database_url() -> str:
    return get_secret("DATABASE_URL")


def get_jwt_secret() -> str:
    return get_secret("JWT_SECRET_KEY")


def get_kyc_api_key() -> str:
    return get_secret("KYC_API_KEY")
