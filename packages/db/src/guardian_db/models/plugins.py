"""Scanner plugin registry + per-tenant enablement (plugin architecture, doc 07 §4)."""

from __future__ import annotations

import uuid

from sqlalchemy import Boolean, ForeignKey, String, UniqueConstraint
from sqlalchemy.dialects.postgresql import ARRAY, JSONB
from sqlalchemy.orm import Mapped, mapped_column

from guardian_db.base import Base, TimestampMixin, uuid_pk


class ScannerPlugin(Base, TimestampMixin):
    __tablename__ = "scanner_plugins"
    __table_args__ = (UniqueConstraint("key", "version", name="uq_plugin_key_version"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    key: Mapped[str] = mapped_column(String(40), nullable=False)  # EngineKey value
    name: Mapped[str] = mapped_column(String(120), nullable=False)
    version: Mapped[str] = mapped_column(String(40), default="0.1.0", nullable=False)
    capabilities: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    target_kinds: Mapped[list[str]] = mapped_column(ARRAY(String), default=list)
    # Active engines (DAST/API/CSPM) blocked without an authorization record.
    requires_authorization: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    resource_profile: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)


class TenantScannerConfig(Base, TimestampMixin):
    """Enable/disable/configure a plugin per tenant — no code deploy needed."""

    __tablename__ = "tenant_scanner_configs"
    __table_args__ = (UniqueConstraint("tenant_id", "plugin_id", name="uq_tenant_plugin"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    tenant_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("tenants.id"), nullable=False)
    plugin_id: Mapped[uuid.UUID] = mapped_column(ForeignKey("scanner_plugins.id"), nullable=False)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    settings: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
