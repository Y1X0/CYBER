"""Idempotent bootstrap seed (dev convenience).

Creates: a tenant, an owner staff user, a default customer, the plan catalog, a trial
subscription, and registers discovered scanner plugins. Safe to run repeatedly.

Run: `python -m guardian_api.seed`  (or `make seed`)
"""

from __future__ import annotations

import datetime as dt

from guardian_common.config import get_settings
from guardian_common.logging import configure_logging, get_logger
from guardian_common.security import hash_password
from guardian_core.enums import StaffRole
from guardian_db.kb_seed import seed_knowledge_base
from guardian_db.models import (
    Customer,
    Plan,
    PlanEntitlement,
    ScannerPlugin,
    Subscription,
    Tenant,
    TenantMembership,
    User,
)
from guardian_db.session import session_scope

log = get_logger("guardian.seed")

_PLANS = [
    ("free", "Free", [("max_assets", 3), ("scans_per_month", 20), ("seats", 2)]),
    ("pro", "Pro", [("max_assets", 50), ("scans_per_month", 1000), ("seats", 20)]),
    (
        "enterprise",
        "Enterprise",
        [("max_assets", None), ("scans_per_month", None), ("seats", None)],
    ),
]


def _slugify(name: str) -> str:
    return "".join(c if c.isalnum() else "-" for c in name.lower()).strip("-")


def seed() -> None:
    settings = get_settings()
    with session_scope() as db:
        # Plans
        plan_by_key: dict[str, Plan] = {}
        for key, name, ents in _PLANS:
            plan = db.query(Plan).filter(Plan.key == key).first()
            if plan is None:
                plan = Plan(key=key, name=name)
                db.add(plan)
                db.flush()
                for ek, ev in ents:
                    db.add(PlanEntitlement(plan_id=plan.id, key=ek, limit_value=ev))
            plan_by_key[key] = plan

        # Vulnerability knowledge base (offline seed) — CWE catalog + sample advisories
        kb_counts = seed_knowledge_base(db)

        # Register discovered scanner plugins (plugin registry, doc 07 §4)
        try:
            from guardian_scanner.registry import available_engines

            for eng in available_engines().values():
                exists = (
                    db.query(ScannerPlugin)
                    .filter(
                        ScannerPlugin.key == eng.key.value, ScannerPlugin.version == eng.version
                    )
                    .first()
                )
                if exists is None:
                    db.add(
                        ScannerPlugin(
                            key=eng.key.value,
                            name=eng.name,
                            version=eng.version,
                            requires_authorization=eng.requires_authorization,
                            capabilities={},
                            target_kinds=[],
                        )
                    )
        except Exception as exc:  # noqa: BLE001 - worker package may be absent in API-only image
            log.info("plugin_registration_skipped", reason=str(exc))

        # Tenant
        slug = _slugify(settings.bootstrap_tenant)
        tenant = db.query(Tenant).filter(Tenant.slug == slug).first()
        if tenant is None:
            tenant = Tenant(name=settings.bootstrap_tenant, slug=slug, mode="hybrid")
            db.add(tenant)
            db.flush()

        # Admin user + owner membership
        email = settings.bootstrap_admin_email.lower()
        user = db.query(User).filter(User.email == email).first()
        if user is None:
            user = User(
                email=email,
                name="Bootstrap Admin",
                password_hash=hash_password(settings.bootstrap_admin_password),
            )
            db.add(user)
            db.flush()
        membership = (
            db.query(TenantMembership)
            .filter(TenantMembership.user_id == user.id, TenantMembership.tenant_id == tenant.id)
            .first()
        )
        if membership is None:
            db.add(
                TenantMembership(user_id=user.id, tenant_id=tenant.id, role=StaffRole.OWNER.value)
            )

        # Default customer + trial subscription
        customer = (
            db.query(Customer)
            .filter(Customer.tenant_id == tenant.id, Customer.name == "Demo Customer")
            .first()
        )
        if customer is None:
            customer = Customer(tenant_id=tenant.id, name="Demo Customer", criticality="high")
            db.add(customer)
            db.flush()
            now = dt.datetime.now(dt.UTC)
            db.add(
                Subscription(
                    tenant_id=tenant.id,
                    customer_id=customer.id,
                    plan_id=plan_by_key["pro"].id,
                    status="trialing",
                    period_start=now,
                    period_end=now + dt.timedelta(days=30),
                )
            )

        log.info(
            "seed_complete",
            tenant=tenant.name,
            admin=email,
            customer=customer.name,
            kb=kb_counts,
        )
        print(  # noqa: T201 - user-facing CLI output
            f"✅ Seed complete. Login as {email} "
            f"(tenant: {tenant.name}, customer: {customer.name})."
        )


if __name__ == "__main__":
    configure_logging(get_settings().log_level)
    seed()
