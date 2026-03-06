"""
database.py - Connexion à la base de données NeoBank Digital
Gestion de session SQLAlchemy - secrets via variables d'environnement (V4).
"""

import os
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker, Session
from dotenv import load_dotenv

load_dotenv()

# V4 CORRIGÉ : Suppression des secrets codés en dur - utilisation de variables d'environnement
DATABASE_URL = os.environ.get("DATABASE_URL")
if not DATABASE_URL:
    raise EnvironmentError(
        "La variable d'environnement DATABASE_URL est requise. "
        "Consultez .env.example pour la configuration."
    )

engine = create_engine(
    DATABASE_URL,
    pool_pre_ping=True,
    pool_size=10,
    max_overflow=20,
    echo=False  # Ne jamais activer echo=True en production (fuite de données sensibles)
)

SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)


def get_db() -> Session:
    """Dependency FastAPI pour obtenir une session de base de données."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
