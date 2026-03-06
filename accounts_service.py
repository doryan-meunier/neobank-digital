"""
accounts_service.py - Service Comptes NeoBank Digital
CORRIGÉ : V1 (Injection SQL), V3 (IDOR), V4 (Secrets en dur), V9 (Logging)

Livrable 1.1 : Requêtes paramétrées + ORM SQLAlchemy + Validation Pydantic
Livrable 2.2 : Vérification de propriété pour prévenir l'IDOR
"""

import logging
import os
import uuid
from typing import List

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from database import get_db
from models import Account, Transaction, User
from schemas import TransactionSearchRequest, TransactionResponse

# ──────────────────────────────────────────────────────────────────────────────
# Logger structuré (V9 - Logging des accès et actions sensibles)
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("neobank.accounts")

router = APIRouter(prefix="/accounts", tags=["accounts"])


# ──────────────────────────────────────────────────────────────────────────────
# Dépendances réutilisables
# ──────────────────────────────────────────────────────────────────────────────

def verify_account_ownership(
    account_id: str,
    current_user: User,
    db: Session,
) -> Account:
    """
    Livrable 2.2 - Middleware d'autorisation :
    Vérifie que le compte demandé appartient bien à l'utilisateur authentifié.
    Lève HTTP 403 (et non 404) pour éviter les fuites d'information sur l'existence du compte.
    Logue toute tentative d'accès non autorisé (V9).
    """
    try:
        account_uuid = uuid.UUID(account_id)
    except ValueError:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Identifiant de compte invalide.")

    account = db.query(Account).filter(Account.id == account_uuid).first()

    if account is None:
        # V10 : Message générique - ne révèle pas l'existence ou l'absence du compte
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès refusé.")

    if str(account.owner_id) != str(current_user.id):
        # V9 : Log de la tentative d'accès non autorisé avec corrélation ID
        logger.warning(
            "Tentative d'accès IDOR détectée",
            extra={
                "event": "idor_attempt",
                "user_id": str(current_user.id),
                "target_account_id": account_id,
                "owner_id": str(account.owner_id),
            },
        )
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Accès refusé.")

    return account


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.get("/transactions/search", response_model=List[TransactionResponse])
def search_transactions(
    account_id: str,
    params: TransactionSearchRequest = Depends(),
    current_user: User = Depends(),   # injecté par le middleware JWT (auth_service)
    db: Session = Depends(get_db),
):
    """
    Livrable 1.1 - CORRIGÉ : Injection SQL (V1)

    AVANT (vulnérable) :
        query = f"SELECT * FROM transactions WHERE user_id = '{user_id}'
                  AND description LIKE '%{keyword}%'"
        cursor.execute(query)

    APRÈS (sécurisé) :
    - Validation Pydantic des entrées (schemas.TransactionSearchRequest)
    - ORM SQLAlchemy avec requêtes entièrement paramétrées
    - Vérification de propriété du compte (V3 IDOR)
    """
    # V3 CORRIGÉ : Vérification que le compte appartient à l'utilisateur
    account = verify_account_ownership(account_id, current_user, db)

    # V1 CORRIGÉ : Requête paramétrée via ORM - SQLAlchemy empêche l'injection SQL
    transactions = (
        db.query(Transaction)
        .filter(
            Transaction.sender_account_id == account.id,
            # Utilisation de ilike() qui passe le keyword comme paramètre lié, jamais interpolé
            Transaction.description.ilike(f"%{params.keyword}%"),
        )
        .order_by(Transaction.created_at.desc())
        .limit(100)  # Limite de résultats pour éviter les attaques de déni de service
        .all()
    )

    # V9 : Log de l'action sensible
    logger.info(
        "Recherche de transactions effectuée",
        extra={
            "event": "transaction_search",
            "user_id": str(current_user.id),
            "account_id": str(account.id),
            "result_count": len(transactions),
        },
    )

    return [
        TransactionResponse(
            id=t.id,
            sender_account_id=t.sender_account_id,
            receiver_account_id=t.receiver_account_id,
            amount=float(t.amount),
            currency=t.currency,
            description=t.description,
            created_at=t.created_at.isoformat() if t.created_at else None,
        )
        for t in transactions
    ]


@router.get("/{account_id}")
def get_account(
    account_id: str,
    current_user: User = Depends(),
    db: Session = Depends(get_db),
):
    """
    Livrable 2.2 - CORRIGÉ : IDOR (V3)

    AVANT (vulnérable) :
        account = db.get_account(account_id)  # Aucune vérification de propriété
        return account

    APRÈS (sécurisé) :
    - Vérification explicite que le compte appartient à l'utilisateur JWT
    - Logging des tentatives d'accès non autorisées
    """
    account = verify_account_ownership(account_id, current_user, db)

    logger.info(
        "Consultation du compte",
        extra={
            "event": "account_read",
            "user_id": str(current_user.id),
            "account_id": str(account.id),
        },
    )

    return {
        "id": str(account.id),
        "iban": account.iban,
        "balance": float(account.balance),
        "currency": account.currency,
        "status": account.status,
    }
