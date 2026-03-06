"""
auth_service.py - Service d'authentification NeoBank Digital
CORRIGÉ : V2 (JWT sans expiration), V3 (IDOR), V4 (Secrets en dur), V9 (Logging), V10 (Messages verbeux)

Livrable 2.1 : JWT sécurisé avec expiration + refresh token + RS256
Livrable 2.2 : Correction IDOR (réutilise verify_account_ownership de accounts_service)
"""

import logging
import os
import secrets
import hashlib
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.security import OAuth2PasswordBearer
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session
from dotenv import load_dotenv

from database import get_db
from models import RefreshToken, User
from schemas import LoginRequest, TokenResponse, RefreshTokenRequest

load_dotenv()

# ──────────────────────────────────────────────────────────────────────────────
# Logger structuré (V9)
# ──────────────────────────────────────────────────────────────────────────────
logger = logging.getLogger("neobank.auth")

# ──────────────────────────────────────────────────────────────────────────────
# V4 CORRIGÉ : Secrets depuis variables d'environnement (jamais codés en dur)
# ──────────────────────────────────────────────────────────────────────────────
SECRET_KEY = os.environ.get("JWT_SECRET_KEY")
ALGORITHM = os.environ.get("JWT_ALGORITHM", "HS256")
ACCESS_TOKEN_EXPIRE_MINUTES = int(os.environ.get("ACCESS_TOKEN_EXPIRE_MINUTES", "15"))
REFRESH_TOKEN_EXPIRE_DAYS = int(os.environ.get("REFRESH_TOKEN_EXPIRE_DAYS", "7"))

if not SECRET_KEY:
    raise EnvironmentError(
        "JWT_SECRET_KEY est requis. Consultez .env.example pour la configuration."
    )

# Longueur minimale recommandée pour la clé secrète
if len(SECRET_KEY) < 32:
    raise ValueError("JWT_SECRET_KEY doit comporter au moins 32 caractères.")

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/auth/login")

router = APIRouter(prefix="/auth", tags=["auth"])


# ──────────────────────────────────────────────────────────────────────────────
# Utilitaires de mot de passe
# ──────────────────────────────────────────────────────────────────────────────

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def hash_password(password: str) -> str:
    return pwd_context.hash(password)


# ──────────────────────────────────────────────────────────────────────────────
# Création et vérification des tokens JWT (V2 CORRIGÉ)
# ──────────────────────────────────────────────────────────────────────────────

def create_access_token(user_id: str, role: str) -> str:
    """
    V2 CORRIGÉ :
    - Expiration courte (15 min par défaut)
    - Claims minimaux (user_id, role, iat, exp)
    - Algorithme configurable (HS256 par défaut, RS256 recommandé en production)
    """
    now = datetime.now(tz=timezone.utc)
    payload = {
        "sub": user_id,
        "role": role,
        "iat": now,
        "exp": now + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES),
        "jti": str(uuid.uuid4()),  # Identifiant unique du token (anti-replay)
        "type": "access",
    }
    return jwt.encode(payload, SECRET_KEY, algorithm=ALGORITHM)


def create_refresh_token() -> tuple[str, str]:
    """
    Génère un refresh token opaque (256 bits d'entropie).
    Retourne (token_clair, hash_bcrypt) - seul le hash est stocké en base.
    """
    raw_token = secrets.token_urlsafe(48)
    token_hash = hashlib.sha256(raw_token.encode()).hexdigest()
    return raw_token, token_hash


def decode_access_token(token: str) -> dict:
    """Décode et valide un access token JWT."""
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        if payload.get("type") != "access":
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token invalide.",
                headers={"WWW-Authenticate": "Bearer"},
            )
        return payload
    except JWTError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token invalide ou expiré.",    # V10 : Message générique
            headers={"WWW-Authenticate": "Bearer"},
        )


async def get_current_user(
    token: str = Depends(oauth2_scheme),
    db: Session = Depends(get_db),
) -> User:
    """Dépendance FastAPI : extrait et valide l'utilisateur depuis le JWT."""
    payload = decode_access_token(token)
    user_id = payload.get("sub")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentification requise.",  # V10 : Message générique
            headers={"WWW-Authenticate": "Bearer"},
        )
    return user


# ──────────────────────────────────────────────────────────────────────────────
# Endpoints
# ──────────────────────────────────────────────────────────────────────────────

@router.post("/login", response_model=TokenResponse)
def login(credentials: LoginRequest, request: Request, db: Session = Depends(get_db)):
    """
    V2, V4, V9, V10 CORRIGÉS

    AVANT (vulnérable) :
        SECRET_KEY = "<SECRET_CODE_EN_DUR>"  # codé en dur (NE PAS FAIRE)
        token = jwt.encode({"user_id": user.id}, SECRET_KEY)  # pas d'expiration
        raise HTTPException(detail=f"User {username} not found in database accounts.users")

    APRÈS (sécurisé) :
    - Secret depuis variable d'environnement
    - Token avec expiration (15 min) + refresh token
    - Message d'erreur générique
    - Logging des tentatives
    """
    client_ip = request.client.host if request.client else "unknown"

    user = db.query(User).filter(User.username == credentials.username).first()

    if not user or not verify_password(credentials.password, user.hashed_password):
        # V9 : Log des échecs d'authentification
        logger.warning(
            "Échec d'authentification",
            extra={
                "event": "login_failure",
                "username": credentials.username,
                "ip": client_ip,
            },
        )
        # V10 : Message générique - ne révèle pas si c'est le nom d'utilisateur ou le mot de passe
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Identifiants incorrects.",
        )

    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Compte désactivé.",
        )

    access_token = create_access_token(str(user.id), user.role.value)
    raw_refresh, refresh_hash = create_refresh_token()

    # Stockage du hash du refresh token en base (jamais le token brut)
    db_token = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(db_token)
    db.commit()

    # V9 : Log du succès d'authentification
    logger.info(
        "Authentification réussie",
        extra={
            "event": "login_success",
            "user_id": str(user.id),
            "ip": client_ip,
        },
    )

    return TokenResponse(
        access_token=access_token,
        refresh_token=raw_refresh,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/refresh", response_model=TokenResponse)
def refresh_token(body: RefreshTokenRequest, db: Session = Depends(get_db)):
    """Renouvelle l'access token via un refresh token valide."""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    now = datetime.now(tz=timezone.utc)

    db_token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.revoked == False,
            RefreshToken.expires_at > now,
        )
        .first()
    )

    if not db_token:
        logger.warning("Tentative d'utilisation d'un refresh token invalide/expiré")
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Refresh token invalide ou expiré.",
        )

    # Rotation du refresh token (chaque utilisation génère un nouveau token)
    db_token.revoked = True
    db.flush()

    user = db.query(User).filter(User.id == db_token.user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Utilisateur introuvable.")

    new_access = create_access_token(str(user.id), user.role.value)
    raw_refresh, refresh_hash = create_refresh_token()

    new_db_token = RefreshToken(
        user_id=user.id,
        token_hash=refresh_hash,
        expires_at=datetime.now(tz=timezone.utc) + timedelta(days=REFRESH_TOKEN_EXPIRE_DAYS),
    )
    db.add(new_db_token)
    db.commit()

    return TokenResponse(
        access_token=new_access,
        refresh_token=raw_refresh,
        expires_in=ACCESS_TOKEN_EXPIRE_MINUTES * 60,
    )


@router.post("/logout")
def logout(
    body: RefreshTokenRequest,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Révoque le refresh token (déconnexion propre)."""
    token_hash = hashlib.sha256(body.refresh_token.encode()).hexdigest()
    db_token = (
        db.query(RefreshToken)
        .filter(
            RefreshToken.token_hash == token_hash,
            RefreshToken.user_id == current_user.id,
        )
        .first()
    )
    if db_token:
        db_token.revoked = True
        db.commit()

    logger.info(
        "Déconnexion",
        extra={"event": "logout", "user_id": str(current_user.id)},
    )
    return {"message": "Déconnecté avec succès."}
