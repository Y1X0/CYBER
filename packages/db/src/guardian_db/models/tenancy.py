"""Hybrid tenancy model (doc 07 §2).

- Tenant       : top isolation boundary. SaaS: one tenant ≈ one company. Managed: a security
                 firm tenant owning many customers.
- User         : a human principal (may be internal staff and/or an external contact).
- TenantMembership : internal STAFF ↔ tenant, with staff role (owner/admin/pentester/...).
- Customer     : a client company being secured.
- CustomerContact  : external PORTAL user ↔ one customer (customer_admin/customer_viewer).
"""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column, relationship

from guardian_db.base import Base, TimestampMixin, uuid_pk


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), unique=True, nullable=False)
    # "saas" | "managed" | "hybrid" — informational; both motions share the model.
    mode: Mapped[str] = mapped_column(String(20), default="hybrid", nullable=False)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    customers: Mapped[list[Customer]] = relationship(back_populates="tenant")
    memberships: Mapped[list[TenantMembership]] = relationship(back_populates="tenant")


class User(Base, TimestampMixin):
    __tablename__ = "users"

    id: Mapped[uuid.UUID] = uuid_pk()
    email: Mapped[str] = mapped_column(String(320), unique=True, nullable=False)
    name: Mapped[str] = mapped_column(String(200), default="", nullable=False)
    # Null when SSO-only. Argon2id hash otherwise.
    password_hash: Mapped[str | None] = mapped_column(String(512), nullable=True)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)


class TenantMembership(Base, TimestampMixin):
    __tablename__ = "tenant_memberships"
    __table_args__ = (UniqueConstraint("user_id", "tenant_id", name="uq_membership_user_tenant"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    # StaffRole value: owner | admin | pentester | analyst | reviewer
    role: Mapped[str] = mapped_column(String(20), nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="memberships")
    user: Mapped[User] = relationship()


class Customer(Base, TimestampMixin):
    __tablename__ = "customers"

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    # Feeds risk scoring (asset_criticality context, doc 01 §5).
    criticality: Mapped[str] = mapped_column(String(20), default="medium", nullable=False)
    status: Mapped[str] = mapped_column(String(20), default="active", nullable=False)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    tenant: Mapped[Tenant] = relationship(back_populates="customers")
    contacts: Mapped[list[CustomerContact]] = relationship(back_populates="customer")


class CustomerContact(Base, TimestampMixin):
    __tablename__ = "customer_contacts"
    __table_args__ = (UniqueConstraint("user_id", "customer_id", name="uq_contact_user_customer"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    customer_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("customers.id"), nullable=False)
    user_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("users.id"), nullable=False)
    # PortalRole value: customer_admin | customer_viewer
    role: Mapped[str] = mapped_column(String(20), nullable=False)

    customer: Mapped[Customer] = relationship(back_populates="contacts")
    user: Mapped[User] = relationship()
