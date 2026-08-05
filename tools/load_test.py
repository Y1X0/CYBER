"""Production-scale validation harness (Prod-Readiness sprint).

Seeds a realistic multi-tenant dataset and then measures the five things the architecture review
flagged: RLS index usage, list/aggregate latency, connection-pool stability, and — the important one
— cross-tenant isolation under concurrency. Read-mostly; writes go to a throwaway database.

Bulk seeding is done server-side (INSERT ... SELECT generate_series) as the owner, so 100k findings
land in seconds. The concurrency + latency phases go through the REAL app-session wiring
(guardian_db.session) as the non-owner guardian_app role, exercising transaction-local RLS binding.

Usage (env-driven, same vars as the app):
    GUARDIAN_DATABASE_URL=...owner...  GUARDIAN_APP_DATABASE_URL=...guardian_app...  \
    python tools/load_test.py [tenants] [assets_per_tenant] [findings_per_tenant]
Defaults: 100 tenants x 100 assets x 1000 findings = 10,000 assets / 100,000 findings.
"""

from __future__ import annotations

import concurrent.futures as cf
import sys
import time

from guardian_common.config import get_settings
from guardian_db.session import get_app_session, set_tenant
from sqlalchemy import create_engine, text

TENANTS = int(sys.argv[1]) if len(sys.argv) > 1 else 100
ASSETS_PER = int(sys.argv[2]) if len(sys.argv) > 2 else 100
FIND_PER = int(sys.argv[3]) if len(sys.argv) > 3 else 1000


def _fmt(ms: float) -> str:
    return f"{ms:8.2f} ms"


def seed(admin_url: str) -> list[str]:
    """Bulk-seed and return the list of tenant ids."""
    eng = create_engine(admin_url, future=True)
    tenant_ids: list[str] = []
    t0 = time.perf_counter()
    with eng.begin() as c:
        for i in range(TENANTS):
            tid = c.execute(text(
                "INSERT INTO tenants (id, name, slug, mode, settings, created_at, updated_at) "
                "VALUES (gen_random_uuid(), :n, :s, 'hybrid', '{}', now(), now()) RETURNING id"
            ), {"n": f"LT-{i}", "s": f"lt-{i}"}).scalar()
            cid = c.execute(text(
                "INSERT INTO customers (id, tenant_id, name, criticality, status, settings, "
                "created_at, updated_at) VALUES (gen_random_uuid(), :t, 'C', 'high', 'active', "
                "'{}', now(), now()) RETURNING id"
            ), {"t": tid}).scalar()
            # assets
            c.execute(text(
                "INSERT INTO assets (id, tenant_id, customer_id, name, kind, identifier, exposure, "
                "config, source, state, created_at, updated_at) "
                "SELECT gen_random_uuid(), :t, :c, 'a'||g, 'web', 'https://h'||:t||'-'||g, 'public', "  # noqa: E501
                "'{}', 'discovered', 'active', now(), now() FROM generate_series(1, :n) g"
            ), {"t": tid, "c": cid, "n": ASSETS_PER})
            aid = c.execute(text("SELECT id FROM assets WHERE tenant_id = :t LIMIT 1"),
                            {"t": tid}).scalar()
            sid = c.execute(text(
                "INSERT INTO scans (id, tenant_id, customer_id, asset_id, trigger, status, "
                "requested_engines, stats, created_at, updated_at) VALUES (gen_random_uuid(), :t, "
                ":c, :a, 'manual', 'completed', '{secrets}', '{}', now(), now()) RETURNING id"
            ), {"t": tid, "c": cid, "a": aid}).scalar()
            rid = c.execute(text(
                "INSERT INTO scan_engine_runs (id, scan_id, engine, status, tool_versions, "
                "created_at, updated_at) VALUES (gen_random_uuid(), :s, 'secrets', 'completed', "
                "'{}', now(), now()) RETURNING id"
            ), {"s": sid}).scalar()
            # findings (server-side generation; severity + risk spread across the set)
            c.execute(text(
                "INSERT INTO findings (id, tenant_id, customer_id, scan_id, engine_run_id, asset_id, "  # noqa: E501
                "fingerprint, title, description, category, severity, risk_score, risk_rationale, "
                "confidence, status, source, location, evidence, \"references\", kev, cve_ids, "
                "created_at, updated_at) "
                "SELECT gen_random_uuid(), :t, :c, :s, :r, :a, 'fp-'||:t||'-'||g, 'Finding '||g, '', "  # noqa: E501
                "'secret', (ARRAY['critical','high','medium','low','info'])[1+(g%5)], (g%101), "
                "'[]'::jsonb, 'medium', 'open', 'automated', '{}'::jsonb, '{}'::jsonb, '{}'::jsonb, "  # noqa: E501
                "false, '{}', now(), now() FROM generate_series(1, :n) g"
            ), {"t": tid, "c": cid, "s": sid, "r": rid, "a": aid, "n": FIND_PER})
            tenant_ids.append(str(tid))
    dt = time.perf_counter() - t0
    total_f = TENANTS * FIND_PER
    print(f"[seed] {TENANTS} tenants, {TENANTS*ASSETS_PER:,} assets, {total_f:,} findings "
          f"in {dt:,.1f}s ({total_f/dt:,.0f} findings/s)")
    eng.dispose()
    return tenant_ids


def explain(tenant_id: str) -> None:
    """Confirm the RLS-filtered hot query is index-backed (no Seq Scan)."""
    s = get_app_session()
    try:
        set_tenant(s, tenant_id)
        plan = "\n".join(r[0] for r in s.execute(text(
            "EXPLAIN (ANALYZE, BUFFERS) SELECT id, severity, risk_score FROM findings "
            "ORDER BY risk_score DESC LIMIT 50"
        )))
        uses_index = "Index" in plan and "Seq Scan on findings" not in plan
        print(f"[explain] findings top-50 under RLS: "
              f"{'INDEX-backed ✓' if uses_index else 'SEQ SCAN ✗'}")
        for line in plan.splitlines()[:4]:
            print(f"          {line.strip()}")
    finally:
        s.close()


def _time_query(tenant_id: str, sql: str, n: int = 20) -> float:
    s = get_app_session()
    try:
        set_tenant(s, tenant_id)
        s.execute(text(sql))  # warm
        t0 = time.perf_counter()
        for _ in range(n):
            s.execute(text(sql)).all()
        return (time.perf_counter() - t0) / n * 1000
    finally:
        s.close()


def latency(tenant_id: str) -> None:
    print("[latency] median-ish per-op (RLS-enforced app role):")
    ops = {
        "list findings top-50 (ORDER BY risk_score)":
            "SELECT id, title, severity, risk_score FROM findings ORDER BY risk_score DESC LIMIT 50",  # noqa: E501
        "dashboard severity aggregate (GROUP BY)":
            "SELECT severity, count(*) FROM findings GROUP BY severity",
        "list assets top-50":
            "SELECT id, name FROM assets ORDER BY created_at DESC LIMIT 50",
        "open-findings count":
            "SELECT count(*) FROM findings WHERE status = 'open'",
    }
    for label, sql in ops.items():
        print(f"          {_fmt(_time_query(tenant_id, sql))}  {label}")


def isolation_under_concurrency(tenant_ids: list[str], rounds: int = 4) -> None:
    """Each worker binds a distinct tenant and must see ONLY its own rows — no bleed under load."""
    expected = FIND_PER
    leaks = 0
    checks = 0

    def probe(tid: str) -> tuple[bool, int]:
        s = get_app_session()
        try:
            set_tenant(s, tid)
            seen = s.execute(text("SELECT DISTINCT tenant_id::text FROM findings")).scalars().all()
            cnt = s.execute(text("SELECT count(*) FROM findings")).scalar()
            ok = seen == [tid] and cnt == expected
            return ok, len(seen)
        finally:
            s.close()

    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=16) as ex:
        futures = []
        for _ in range(rounds):
            for tid in tenant_ids:
                futures.append(ex.submit(probe, tid))
        for f in cf.as_completed(futures):
            checks += 1
            ok, n_tenants = f.result()
            if not ok:
                leaks += 1
    dt = time.perf_counter() - t0
    print(f"[isolation] {checks:,} concurrent tenant-bound probes (16 workers) in {dt:,.1f}s: "
          f"{'NO cross-tenant leakage ✓' if leaks == 0 else f'{leaks} LEAKS ✗'}")


def pool_stability(tenant_ids: list[str]) -> None:
    """Hammer the pool with more concurrent sessions than pool_size to confirm it holds."""
    s = get_settings()
    ceiling = s.db_pool_size + s.db_max_overflow
    workers = ceiling + 20  # deliberately exceed the pool to prove overflow+queue behavior

    def one(tid: str) -> bool:
        sess = get_app_session()
        try:
            set_tenant(sess, tid)
            sess.execute(text("SELECT count(*) FROM findings")).scalar()
            return True
        finally:
            sess.close()

    t0 = time.perf_counter()
    with cf.ThreadPoolExecutor(max_workers=workers) as ex:
        results = list(ex.map(one, [tenant_ids[i % len(tenant_ids)] for i in range(workers * 4)]))
    dt = time.perf_counter() - t0
    print(f"[pool] app pool_size={s.db_pool_size}+overflow={s.db_max_overflow} (ceiling {ceiling}); "  # noqa: E501
          f"{workers} threads x4 = {len(results)} ops in {dt:,.1f}s: "
          f"{'stable, no exhaustion ✓' if all(results) else 'FAILURES ✗'}")


def main() -> int:
    settings = get_settings()
    admin_url = settings.database_url
    print(f"== Load test :: {TENANTS} tenants / {TENANTS*ASSETS_PER:,} assets / "
          f"{TENANTS*FIND_PER:,} findings ==")
    tenant_ids = seed(admin_url)
    probe_tid = tenant_ids[len(tenant_ids) // 2]
    explain(probe_tid)
    latency(probe_tid)
    isolation_under_concurrency(tenant_ids)
    pool_stability(tenant_ids)
    print("== done ==")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
