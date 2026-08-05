"""Interface ports for future subsystems (Phase 5B) — definitions + no-op defaults only.

Same pattern as the existing `LLMProvider` / `JobQueue` / `ScanEngine` ports: declare the seam now
so later phases (EASM, SOAR, enterprise, BYOK) plug in without touching the core. Each port ships a
safe no-op default; **no real behavior is implemented in Phase 5.**
"""

from __future__ import annotations

from typing import Any, Protocol, runtime_checkable


# ── SOAR: outbound notifications (Slack/PagerDuty/email...) — Phase 7 ──
@runtime_checkable
class Notifier(Protocol):
    def notify(
        self, *, channel: str, subject: str, body: str, meta: dict | None = None
    ) -> None: ...


class NullNotifier:
    """Default: does nothing. Real Notifiers arrive with SOAR (Phase 7)."""

    def notify(self, *, channel: str, subject: str, body: str, meta: dict | None = None) -> None:
        return None


# ── SOAR: ticketing/connectors (Jira/ServiceNow/GitHub Issues) — Phase 7 ──
@runtime_checkable
class Connector(Protocol):
    kind: str

    def create_ticket(self, *, title: str, body: str, meta: dict | None = None) -> str | None: ...


class NullConnector:
    kind = "null"

    def create_ticket(self, *, title: str, body: str, meta: dict | None = None) -> str | None:
        return None


# ── Attack-path graph projection from graph_edges — Phase 6 ──
@runtime_checkable
class GraphProjector(Protocol):
    def paths_to(self, *, tenant_id: str, target_type: str, target_id: str) -> list[list[dict]]: ...


class NullGraphProjector:
    def paths_to(self, *, tenant_id: str, target_type: str, target_id: str) -> list[list[dict]]:
        return []


# ── KMS / secrets provider for envelope encryption + BYOK — Phase 9 (local default now) ──
@runtime_checkable
class KMSProvider(Protocol):
    def encrypt(self, plaintext: bytes, *, context: dict | None = None) -> bytes: ...
    def decrypt(self, ciphertext: bytes, *, context: dict | None = None) -> bytes: ...


# ── EASM discovery collectors (domains/subdomains/IPs/cloud) — Phase 6 ──
@runtime_checkable
class DiscoveryProvider(Protocol):
    def discover(self, *, seed: str, scope: dict) -> list[dict[str, Any]]: ...


class NullDiscoveryProvider:
    def discover(self, *, seed: str, scope: dict) -> list[dict[str, Any]]:
        return []


# ── Enterprise identity (SAML/OIDC/SCIM) — Phase 9 ──
@runtime_checkable
class IdentityProvider(Protocol):
    kind: str

    def authenticate(self, assertion: str) -> dict | None: ...


class NullIdentityProvider:
    kind = "null"

    def authenticate(self, assertion: str) -> dict | None:
        return None
