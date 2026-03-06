"""
models.py - SQLAlchemy models pour NeoBank Digital
Fournit les modèles ORM pour les entités bancaires.
"""

from sqlalchemy import (
    Column, String, Numeric, DateTime, Boolean,
    ForeignKey, Text, Enum as SAEnum
)
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.orm import declarative_base, relationship
from sqlalchemy import func
import uuid
import enum

Base = declarative_base()


class UserRole(str, enum.Enum):
    USER = "user"
    ADMIN = "admin"


class AccountStatus(str, enum.Enum):
    ACTIVE = "active"
    SUSPENDED = "suspended"
    CLOSED = "closed"


class User(Base):
    __tablename__ = "users"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    username = Column(String(50), unique=True, nullable=False, index=True)
    email = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password = Column(String(255), nullable=False)
    role = Column(SAEnum(UserRole), default=UserRole.USER, nullable=False)
    is_active = Column(Boolean, default=True, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    accounts = relationship("Account", back_populates="owner")
    refresh_tokens = relationship("RefreshToken", back_populates="user")


class Account(Base):
    __tablename__ = "accounts"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    owner_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    iban = Column(String(34), unique=True, nullable=False)
    balance = Column(Numeric(15, 2), default=0, nullable=False)
    currency = Column(String(3), default="EUR", nullable=False)
    status = Column(SAEnum(AccountStatus), default=AccountStatus.ACTIVE, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    owner = relationship("User", back_populates="accounts")
    transactions_sent = relationship(
        "Transaction", foreign_keys="Transaction.sender_account_id", back_populates="sender"
    )
    transactions_received = relationship(
        "Transaction", foreign_keys="Transaction.receiver_account_id", back_populates="receiver"
    )


class Transaction(Base):
    __tablename__ = "transactions"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    sender_account_id = Column(UUID(as_uuid=True), ForeignKey("accounts.id"), nullable=False)
    receiver_account_id = Column(UUID(as_uuid=True), ForeignKey("accounts.id"), nullable=True)
    amount = Column(Numeric(15, 2), nullable=False)
    currency = Column(String(3), default="EUR", nullable=False)
    # Description sanitisée avant stockage (V5)
    description = Column(Text, nullable=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    sender = relationship("Account", foreign_keys=[sender_account_id], back_populates="transactions_sent")
    receiver = relationship("Account", foreign_keys=[receiver_account_id], back_populates="transactions_received")


class RefreshToken(Base):
    """Stockage des refresh tokens JWT (V2)."""
    __tablename__ = "refresh_tokens"

    id = Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    user_id = Column(UUID(as_uuid=True), ForeignKey("users.id"), nullable=False)
    token_hash = Column(String(255), unique=True, nullable=False)
    expires_at = Column(DateTime(timezone=True), nullable=False)
    revoked = Column(Boolean, default=False, nullable=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

    user = relationship("User", back_populates="refresh_tokens")
