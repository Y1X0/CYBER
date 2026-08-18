"""The Kubernetes engine over this repository's own manifests (WP-D7).

`test_k8s_posture.py` tests each rule against a manifest written to trigger it. This runs the whole
engine over `infra/k8s/`, which is a real, reviewed set of NetworkPolicy objects that were written
to be correct — so it answers the question a rule-by-rule suite cannot: on manifests nobody wrote
for the scanner, does it stay quiet where it should?

It finds exactly one thing, and that thing is true: the ingress policy accepts traffic from
anywhere, which the file's own comment acknowledges. The other eight objects produce nothing.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from guardian_core.enums import EngineKey
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.k8s_engine import K8sEngine

REPO = Path(__file__).resolve().parents[2]
INFRA = REPO / "infra"

pytestmark = pytest.mark.skipif(not INFRA.exists(), reason="infra/ manifests are not present")


@pytest.fixture(scope="module")
def findings():
    ctx = ScanContext(scan_id="k8s-repo", asset_kind="repo", asset_identifier="guardian",
                      workspace_path=str(INFRA))
    return list(K8sEngine().run(ctx))


def test_the_real_manifests_parse_without_error(findings):
    """A coverage finding here would mean a file could not be read — which is the failure this
    package exists to stop being silent about."""
    assert not [f for f in findings if f.category == "scan-coverage"]


def test_the_one_genuinely_permissive_policy_is_reported(findings):
    """`ingress: - {}` accepts from every peer. The file's own comment says to scope it to the load
    balancer's source range."""
    reported = [f for f in findings if f.location.get("rule") == "netpol-open-ingress"]
    assert len(reported) == 1
    assert "NetworkPolicy/ingress" in reported[0].location["workload"]


def test_the_correctly_written_policies_produce_nothing(findings):
    """Eight reviewed objects, including a default-deny — none of them reported. A rule set that
    fires on a correct manifest is one an operator turns off."""
    assert len(findings) == 1


def test_every_finding_carries_its_control_and_location(findings):
    for finding in findings:
        assert finding.engine == EngineKey.K8S
        assert finding.location.get("path")
        assert finding.location.get("workload")
        assert finding.references.get("cis") or finding.location.get("cis")
