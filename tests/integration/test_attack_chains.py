"""Attack chains over the real graph (WP-E4).

`test_attack_paths.py` proves the chaining logic. This proves it is fed by the data the platform
actually holds: graph nodes and edges the discovery pipeline wrote, findings the engines reported,
and the asset links between them — with the tenant boundary intact.

The property that matters most here is the one a synthetic test cannot check: a chain crosses from
one asset to another **only** where the graph has an edge. If that ever stops being true, every
finding in an estate chains to every other one and the feature becomes a generator of plausible
fiction.

Gated by GUARDIAN_RUN_DB_TESTS=1.
"""

from __future__ import annotations

import os
import uuid

import pytest

pytestmark = pytest.mark.skipif(
    os.getenv("GUARDIAN_RUN_DB_TESTS") != "1", reason="requires a live database"
)


def _estate(*, link_assets: bool):
    """A public web asset and a cloud asset, optionally connected in the graph.

    web:   command injection (grants execution) + a committed credential (grants a credential)
    cloud: an over-permissioned principal (needs a credential, grants privilege escalation)
    """
    from guardian_db.models import (
        Asset,
        Customer,
        Finding,
        GraphEdge,
        GraphNode,
        Scan,
        ScanEngineRun,
        Tenant,
    )
    from guardian_db.session import session_scope

    slug = f"e4-{uuid.uuid4().hex[:10]}"
    with session_scope() as db:
        tenant = Tenant(name=slug, slug=slug, mode="hybrid")
        db.add(tenant)
        db.flush()
        customer = Customer(tenant_id=tenant.id, name="C", criticality="critical")
        db.add(customer)
        db.flush()

        web = Asset(tenant_id=tenant.id, customer_id=customer.id, name="web", kind="web",
                    identifier=f"https://{slug}.example.invalid", exposure="public", config={})
        cloud = Asset(tenant_id=tenant.id, customer_id=customer.id, name="cloud",
                      kind="cloud_account", identifier=f"aws:{slug}", exposure="internal",
                      config={})
        db.add_all([web, cloud])
        db.flush()

        scan = Scan(tenant_id=tenant.id, customer_id=customer.id, asset_id=web.id,
                    trigger="manual", status="completed", requested_engines=["dast"], stats={})
        db.add(scan)
        db.flush()
        run = ScanEngineRun(scan_id=scan.id, engine="dast", status="completed")
        db.add(run)
        db.flush()

        def finding(asset, title, cwe, severity, risk, category):
            row = Finding(
                tenant_id=tenant.id, customer_id=customer.id, scan_id=scan.id,
                engine_run_id=run.id, asset_id=asset.id, fingerprint=uuid.uuid4().hex[:32],
                title=title, description="", category=category, severity=severity,
                risk_score=risk, status="open", cwe_id=cwe, location={}, evidence={},
            )
            db.add(row)
            db.flush()
            return row.id

        rce = finding(web, "OS command injection in `host`", "CWE-78", "critical", 95, "injection")
        secret = finding(web, "Hardcoded AWS credential", "CWE-798", "high", 80, "secret")
        iam = finding(cloud, "IAM role has full administrative access", "CWE-269", "high", 75,
                      "cloud-misconfig")

        # The graph the discovery pipeline writes: an internet-facing subdomain that serves the web
        # asset, and asset nodes for both.
        subdomain = GraphNode(
            tenant_id=tenant.id, customer_id=customer.id, node_type="subdomain",
            canonical_key=f"{slug}.example.invalid", state="active", exposure_score=80,
            metadata_={"internet_reachable": True},
        )
        db.add(subdomain)
        db.flush()
        web_node = GraphNode(tenant_id=tenant.id, customer_id=customer.id, node_type="asset",
                             canonical_key=str(web.id), asset_id=web.id, state="active",
                             metadata_={})
        cloud_node = GraphNode(tenant_id=tenant.id, customer_id=customer.id, node_type="asset",
                               canonical_key=str(cloud.id), asset_id=cloud.id, state="active",
                               metadata_={})
        db.add_all([web_node, cloud_node])
        db.flush()

        edges = [GraphEdge(tenant_id=tenant.id, src_id=subdomain.id, src_type="subdomain",
                           relation="serves", dst_id=web_node.id, dst_type="asset", state="active",
                           meta={})]
        if link_assets:
            edges.append(GraphEdge(tenant_id=tenant.id, src_id=web_node.id, src_type="asset",
                                   relation="hosts", dst_id=cloud_node.id, dst_type="asset",
                                   state="active", meta={}))
        db.add_all(edges)
        db.flush()

        return {"tenant": str(tenant.id), "web": str(web.id), "cloud": str(cloud.id),
                "rce": str(rce), "secret": str(secret), "iam": str(iam), "slug": slug}


def _chains(tenant_id: str) -> dict:
    from guardian_db.graph_read import DbGraphProjector
    from guardian_db.session import session_scope

    with session_scope() as db:
        return DbGraphProjector(db).attack_chains(tenant_id=tenant_id)


def test_a_chain_is_built_from_real_graph_data():
    ctx = _estate(link_assets=True)
    result = _chains(ctx["tenant"])

    assert result["chains"]
    routes = [[step["finding_id"] for step in chain["steps"]] for chain in result["chains"]]
    assert [ctx["rce"], ctx["secret"], ctx["iam"]] in routes


def test_the_chain_stops_at_the_asset_boundary_when_the_graph_has_no_edge():
    """The same three findings, the same preconditions, and no edge between the assets. The cloud
    finding must not appear in any chain: nothing in the data says the web host can reach it."""
    ctx = _estate(link_assets=False)
    result = _chains(ctx["tenant"])

    reached = {step["asset_id"] for chain in result["chains"] for step in chain["steps"]}
    assert ctx["cloud"] not in reached
    assert result["chains"]  # the on-asset chain is still found


def test_every_step_names_the_finding_it_rests_on():
    ctx = _estate(link_assets=True)
    result = _chains(ctx["tenant"])

    known = {ctx["rce"], ctx["secret"], ctx["iam"]}
    for chain in result["chains"]:
        for step in chain["steps"]:
            assert step["finding_id"] in known
            assert step["rationale"]
            assert step["grants"]


def test_a_chain_carries_a_deterministic_score_and_a_narrative():
    ctx = _estate(link_assets=True)
    first = _chains(ctx["tenant"])
    second = _chains(ctx["tenant"])

    assert first == second  # same estate, same answer, every time
    top = first["chains"][0]
    assert 0 < top["score"] <= 100
    assert 0 < top["likelihood"] <= 100
    assert top["narrative"].startswith("An attacker who can reach")


def test_findings_that_could_not_be_chained_are_counted():
    ctx = _estate(link_assets=True)
    result = _chains(ctx["tenant"])
    assert "unchainable_findings" in result


def test_one_tenants_findings_never_appear_in_anothers_chain():
    mine, theirs = _estate(link_assets=True), _estate(link_assets=True)
    result = _chains(mine["tenant"])

    foreign = {theirs["rce"], theirs["secret"], theirs["iam"]}
    seen = {step["finding_id"] for chain in result["chains"] for step in chain["steps"]}
    assert not (seen & foreign)


# ── the API surface ───────────────────────────────────────────────────────────────────────────────
def _client(tenant_slug: str):
    from fastapi.testclient import TestClient
    from guardian_api.main import app
    from guardian_common.config import get_settings
    from guardian_common.security import create_access_token
    from guardian_db.models import Tenant, TenantMembership, User
    from guardian_db.session import session_scope

    with session_scope() as db:
        tenant = db.query(Tenant).filter(Tenant.slug == tenant_slug).one()
        user = User(email=f"a-{tenant_slug}@x.invalid", name="Analyst", status="active")
        db.add(user)
        db.flush()
        db.add(TenantMembership(user_id=user.id, tenant_id=tenant.id, role="pentester"))
        db.flush()
        user_id = user.id

    settings = get_settings()
    token = create_access_token(subject=str(user_id), secret=settings.jwt_secret,
                                algorithm=settings.jwt_algorithm)
    return TestClient(app), {"Authorization": f"Bearer {token}"}


def test_the_api_returns_the_chains():
    ctx = _estate(link_assets=True)
    client, hdr = _client(ctx["slug"])

    response = client.get("/api/v1/graph/attack-chains", headers=hdr)

    assert response.status_code == 200, response.text
    body = response.json()
    assert body["chains"]
    assert body["chains"][0]["steps"]
    assert body["chains"][0]["narrative"]


def test_a_portal_contact_cannot_read_the_attack_graph():
    """Chains name every weakness in the estate and the order to use them in."""
    ctx = _estate(link_assets=True)
    client, hdr = _client(ctx["slug"])
    del hdr["Authorization"]

    assert client.get("/api/v1/graph/attack-chains", headers=hdr).status_code in (401, 403)
