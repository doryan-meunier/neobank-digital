"""
schemas.py - Schémas de validation Pydantic pour NeoBank Digital
Livrable 1.3 : Validation stricte des entrées / sorties.
Tous les messages d'erreur sont génériques pour éviter les fuites d'information (V10).
"""

from pydantic import BaseModel, Field, field_validator, UUID4
from typing import Optional, Annotated
import re
import uuid


# ──────────────────────────────────────────────────────────────────────────────
# Utilitaires
# ──────────────────────────────────────────────────────────────────────────────

def _validate_no_html(value: str) -> str:
    """Rejette les chaînes contenant des balises HTML/script (défense en profondeur, V5)."""
    if re.search(r"<[^>]+>", value):
        raise ValueError("Les balises HTML ne sont pas autorisées dans ce champ.")
    return value


# ──────────────────────────────────────────────────────────────────────────────
# Authentification
# ──────────────────────────────────────────────────────────────────────────────

class LoginRequest(BaseModel):
    """V2, V7 - Validation des identifiants de connexion."""
    username: Annotated[str, Field(min_length=3, max_length=50, pattern=r"^[a-zA-Z0-9_.-]+$")]
    password: Annotated[str, Field(min_length=8, max_length=128)]

    class Config:
        # Aucun champ supplémentaire n'est accepté (Mass Assignment, V6)
        extra = "forbid"


class TokenResponse(BaseModel):
    """Réponse JWT - expose uniquement les informations nécessaires."""
    access_token: str
    refresh_token: str
    token_type: str = "bearer"
    expires_in: int  # secondes


class RefreshTokenRequest(BaseModel):
    refresh_token: str

    class Config:
        extra = "forbid"


# ──────────────────────────────────────────────────────────────────────────────
# Transactions / Recherche (V1, V5)
# ──────────────────────────────────────────────────────────────────────────────

class TransactionSearchRequest(BaseModel):
    """
    V1 - La validation stricte des entrées est la première ligne de défense
    contre l'injection SQL avant l'utilisation des requêtes paramétrées.
    """
    keyword: Annotated[
        str,
        Field(
            min_length=1,
            max_length=100,
            description="Mot-clé de recherche dans les descriptions de transaction",
        ),
    ]

    @field_validator("keyword")
    @classmethod
    def sanitize_keyword(cls, v: str) -> str:
        # Refuse les séquences de commentaires SQL et les caractères dangereux
        forbidden_patterns = [r"--", r";", r"\/\*", r"\*\/", r"\bUNION\b", r"\bDROP\b"]
        for pattern in forbidden_patterns:
            if re.search(pattern, v, re.IGNORECASE):
                raise ValueError("Caractères non autorisés dans la recherche.")
        return _validate_no_html(v.strip())


class TransactionResponse(BaseModel):
    id: UUID4
    sender_account_id: UUID4
    receiver_account_id: Optional[UUID4]
    amount: float
    currency: str
    # La description est encodée HTML avant d'être exposée (V5)
    description: Optional[str]
    created_at: str

    class Config:
        from_attributes = True


# ──────────────────────────────────────────────────────────────────────────────
# Virements (V5 - XSS)
# ──────────────────────────────────────────────────────────────────────────────

class TransferRequest(BaseModel):
    """Livrable 1.2 - Sécurisation du endpoint /transfer contre XSS."""
    to_account: UUID4
    amount: Annotated[float, Field(gt=0, le=100_000, description="Montant en euros")]
    # V5 : description limitée et validée
    description: Annotated[
        Optional[str],
        Field(default=None, min_length=0, max_length=200),
    ]

    @field_validator("description")
    @classmethod
    def sanitize_description(cls, v: Optional[str]) -> Optional[str]:
        if v is None:
            return v
        # Suppression de toute balise HTML/script
        cleaned = re.sub(r"<[^>]*>", "", v)
        # Rejet si du contenu a été supprimé (indique une tentative malveillante)
        if cleaned != v:
            raise ValueError("Le champ description ne doit pas contenir de balises HTML.")
        return cleaned.strip()

    class Config:
        extra = "forbid"


# ──────────────────────────────────────────────────────────────────────────────
# Profil utilisateur (V6 - Mass Assignment)
# ──────────────────────────────────────────────────────────────────────────────

class UpdateProfileRequest(BaseModel):
    """
    Livrable 2.3 - DTO strict : seuls les champs listés ici sont modifiables.
    Les champs sensibles (role, balance, is_admin, id) sont intentionnellement absents.
    """
    email: Annotated[
        Optional[str],
        Field(default=None, min_length=5, max_length=255, pattern=r"^[^@\s]+@[^@\s]+\.[^@\s]+$"),
    ]
    display_name: Annotated[Optional[str], Field(default=None, min_length=1, max_length=100)]
    phone_number: Annotated[
        Optional[str],
        Field(default=None, pattern=r"^\+?[1-9]\d{6,14}$"),
    ]

    @field_validator("display_name")
    @classmethod
    def sanitize_display_name(cls, v: Optional[str]) -> Optional[str]:
        if v:
            return _validate_no_html(v.strip())
        return v

    class Config:
        extra = "forbid"  # Rejette tout champ non listé (protection Mass Assignment)


class ProfileResponse(BaseModel):
    """DTO de sortie - expose uniquement les informations publiques."""
    id: UUID4
    username: str
    email: str
    display_name: Optional[str]
    phone_number: Optional[str]
    role: str

    class Config:
        from_attributes = True
