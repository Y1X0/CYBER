"""Chaining findings into attack paths (WP-E4).

`attack_graph.attack_paths` ends at the first finding it reaches. These tests are about what comes
after it — and, more than that, about the two ways an attack-path feature turns into fiction:

* a hop between assets that the data does not support ("these look related");
* a hop through a finding that grants nothing, dressed up as a step because it was nearby.

Both are tested for directly, because a chain that cannot be checked is worse than no chain: it is
a claim about the customer's estate that nobody can verify and everybody will act on.
"""

from __future__ import annotations

import pytest
from guardian_core.attack_paths import (
    Capability,
    FindingView,
    build_chains,
    describe,
    profile_for,
    score_chain,
)


def _f(fid, asset, *, cwe=None, category="", severity="high", risk=70, kev=False, maturity=None):
    return FindingView(id=fid, asset_id=asset, title=f"finding {fid}", severity=severity,
                       risk_score=risk, category=category, cwe_id=cwe, kev=kev,
                       exploit_maturity=maturity)


# ── what a finding grants ─────────────────────────────────────────────────────────────────────────
@pytest.mark.parametrize(("cwe", "capability"), [
    ("CWE-78", Capability.CODE_EXECUTION),
    ("CWE-1336", Capability.CODE_EXECUTION),
    ("CWE-89", Capability.DATA_ACCESS),
    ("CWE-22", Capability.DATA_ACCESS),
    ("CWE-798", Capability.CREDENTIAL_ACCESS),
    ("CWE-269", Capability.PRIVILEGE_ESCALATION),
    ("CWE-250", Capability.PRIVILEGE_ESCALATION),
    ("CWE-284", Capability.NETWORK_ACCESS),
])
def test_a_finding_class_grants_what_it_actually_grants(cwe, capability):
    profile = profile_for(_f("x", "a", cwe=cwe))
    assert profile is not None
    assert capability in profile.grants


def test_a_finding_class_with_no_capability_is_not_a_step():
    """Inventing a capability so a finding can be chained is how these features start describing
    attacks that are not possible."""
    assert profile_for(_f("x", "a", cwe="CWE-1004", category="")) is None


def test_a_category_covers_a_finding_with_no_cwe():
    assert profile_for(_f("x", "a", category="secret")) is not None


def test_exploit_intelligence_raises_reliability_without_inventing_a_capability():
    """A KEV-listed vulnerability is the same step with the uncertainty removed."""
    plain = profile_for(_f("x", "a", cwe="CWE-78"))
    weaponized = profile_for(_f("x", "a", cwe="CWE-78", kev=True, maturity="functional"))
    assert weaponized.reliability > plain.reliability
    assert weaponized.grants == plain.grants


# ── chaining ──────────────────────────────────────────────────────────────────────────────────────
def test_the_classic_chain_is_found():
    """Remote code execution on the public host, then the credential committed in its repository,
    then the over-permissioned principal that credential belongs to."""
    findings = [
        _f("rce", "web", cwe="CWE-78", severity="critical", risk=95),
        _f("secret", "web", cwe="CWE-798", severity="high", risk=80),
        _f("iam", "cloud", cwe="CWE-269", severity="high", risk=75),
    ]
    result = build_chains(findings, reachable={"web": {"cloud"}}, entry_assets={"web"})

    full = [c for c in result.chains
            if [s.finding_id for s in c.steps] == ["rce", "secret", "iam"]]
    assert full, [[s.finding_id for s in c.steps] for c in result.chains]
    assert full[0].length == 3
    # The last hop lands on a different asset, reached over an edge the graph has.
    assert full[0].steps[-1].asset_id == "cloud"


def test_a_shorter_route_to_the_same_capability_ranks_above_a_longer_one():
    """Both chains end with the attacker holding a credential. The two-step one requires fewer
    things to go right, and a ranking that ignored that would send the customer to the wrong one
    first."""
    findings = [
        _f("rce", "web", cwe="CWE-78", severity="critical", risk=95),
        _f("secret", "web", cwe="CWE-798", severity="high", risk=80),
        _f("iam", "cloud", cwe="CWE-269", severity="high", risk=75),
    ]
    result = build_chains(findings, reachable={"web": {"cloud"}}, entry_assets={"web"})
    assert result.chains[0].length < max(c.length for c in result.chains)


def test_a_chain_never_crosses_an_edge_the_graph_does_not_have():
    """The single most important property. Without it, every finding in the estate chains to every
    other one and the output is a graph of things that might be true."""
    findings = [
        _f("rce", "web", cwe="CWE-78"),
        _f("iam", "cloud", cwe="CWE-269"),
    ]
    result = build_chains(findings, reachable={}, entry_assets={"web"})

    assert all(step.asset_id == "web" for chain in result.chains for step in chain.steps)


def test_a_step_whose_precondition_is_unmet_is_not_taken():
    """`CWE-269` (over-permissioned principal) needs a credential first. On its own it is a finding,
    not a step in a chain from the internet."""
    findings = [_f("iam", "web", cwe="CWE-269")]
    assert build_chains(findings, reachable={}, entry_assets={"web"}).chains == ()


def test_a_chain_must_begin_somewhere_the_internet_can_reach():
    """A chain that starts on an internal host describes an attacker who is already inside, which
    is a different question from the one this answers."""
    findings = [
        _f("rce", "internal", cwe="CWE-78"),
        _f("secret", "internal", cwe="CWE-798"),
    ]
    assert build_chains(findings, reachable={}, entry_assets=set()).chains == ()


def test_a_single_finding_is_not_a_chain():
    """It is already reported as a finding. Calling it a one-step attack path adds nothing and
    doubles the noise."""
    findings = [_f("rce", "web", cwe="CWE-78")]
    assert build_chains(findings, reachable={}, entry_assets={"web"}).chains == ()


def test_a_step_that_grants_nothing_new_is_not_added():
    """Two SQL injections on the same host are two findings and one capability. A chain that lists
    both is longer without being more dangerous, and every extra hop is another thing to check."""
    findings = [
        _f("sqli-1", "web", cwe="CWE-89"),
        _f("sqli-2", "web", cwe="CWE-89"),
        _f("secret", "web", cwe="CWE-798"),
    ]
    result = build_chains(findings, reachable={}, entry_assets={"web"})
    for chain in result.chains:
        grants = [g for step in chain.steps for g in step.grants]
        assert len(grants) == len(set(grants))


def test_a_finding_is_never_used_twice_in_one_chain():
    findings = [
        _f("rce", "web", cwe="CWE-78"),
        _f("secret", "web", cwe="CWE-798"),
    ]
    for chain in build_chains(findings, reachable={}, entry_assets={"web"}).chains:
        ids = [step.finding_id for step in chain.steps]
        assert len(ids) == len(set(ids))


def test_findings_that_cannot_be_chained_are_reported_not_dropped():
    """"We found no attack path" and "we could not reason about half your findings" are different
    statements, and only one of them is reassuring."""
    findings = [
        _f("rce", "web", cwe="CWE-78"),
        _f("secret", "web", cwe="CWE-798"),
        _f("cookie", "web", cwe="CWE-1004"),
    ]
    result = build_chains(findings, reachable={}, entry_assets={"web"})
    assert result.unmapped == ("cookie",)


def test_the_chain_length_is_bounded():
    findings = [_f("rce", "web", cwe="CWE-78"), _f("secret", "web", cwe="CWE-798"),
                _f("iam", "cloud", cwe="CWE-269"), _f("sql", "db", cwe="CWE-89")]
    result = build_chains(findings, reachable={"web": {"cloud"}, "cloud": {"db"}},
                          entry_assets={"web"}, max_length=2)
    assert all(chain.length <= 2 for chain in result.chains)


def test_the_number_of_chains_is_bounded_and_truncation_is_reported():
    findings = [_f("rce", "web", cwe="CWE-78")]
    findings += [_f(f"s{i}", "web", cwe="CWE-798") for i in range(30)]
    result = build_chains(findings, reachable={}, entry_assets={"web"}, max_chains=5)
    assert len(result.chains) <= 5
    assert result.truncated is True


# ── scoring ───────────────────────────────────────────────────────────────────────────────────────
def test_a_longer_chain_is_less_likely_than_its_first_step():
    """Likelihood multiplies because every link has to hold. A five-step chain of coin flips is not
    a fifty-percent chain."""
    findings = [_f("rce", "web", cwe="CWE-78"), _f("secret", "web", cwe="CWE-798"),
                _f("iam", "cloud", cwe="CWE-269")]
    result = build_chains(findings, reachable={"web": {"cloud"}}, entry_assets={"web"})
    by_length = {chain.length: chain for chain in result.chains}
    assert by_length[3].likelihood < by_length[2].likelihood


def test_the_same_chain_into_a_critical_asset_outranks_one_into_a_sandbox():
    findings = [_f("rce", "web", cwe="CWE-78"), _f("secret", "web", cwe="CWE-798")]
    high = build_chains(findings, reachable={}, entry_assets={"web"},
                        criticality={"web": "critical"}).chains[0]
    low = build_chains(findings, reachable={}, entry_assets={"web"},
                       criticality={"web": "low"}).chains[0]
    assert high.score > low.score


def test_scoring_is_deterministic():
    findings = [_f("rce", "web", cwe="CWE-78"), _f("secret", "web", cwe="CWE-798")]
    first = build_chains(findings, reachable={}, entry_assets={"web"})
    second = build_chains(list(reversed(findings)), reachable={}, entry_assets={"web"})
    assert [c.score for c in first.chains] == [c.score for c in second.chains]
    assert [[s.finding_id for s in c.steps] for c in first.chains] == \
        [[s.finding_id for s in c.steps] for c in second.chains]


def test_an_empty_chain_scores_zero():
    assert score_chain(()) == (0, 0, 0)


# ── narrative ─────────────────────────────────────────────────────────────────────────────────────
def test_the_narrative_names_every_hop_in_order():
    """A chain a reader cannot check is a claim, not a finding."""
    findings = [_f("rce", "web", cwe="CWE-78"), _f("secret", "web", cwe="CWE-798")]
    chain = build_chains(findings, reachable={}, entry_assets={"web"},
                         entry_keys={"web": "app.example.com"}).chains[0]
    text = describe(chain)

    assert "app.example.com" in text
    for step in chain.steps:
        assert step.title in text
    assert text.index(chain.steps[0].title) < text.index(chain.steps[1].title)


def test_every_step_carries_the_finding_it_rests_on():
    findings = [_f("rce", "web", cwe="CWE-78"), _f("secret", "web", cwe="CWE-798")]
    for chain in build_chains(findings, reachable={}, entry_assets={"web"}).chains:
        for step in chain.steps:
            assert step.finding_id
            assert step.rationale
            assert step.grants
