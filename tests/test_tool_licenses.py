"""The licence gate that decides whether Guardian can legally be sold with a tool inside.

The critical property is the direction of failure. A false positive costs one row in the register;
a false negative ships an unreviewed binary and is discovered during due diligence. An earlier
version of the extractor anchored package names on "ends with @ or end-of-string", which silently
skipped every quoted pip pin — semgrep and checkov walked straight past the gate.
"""

from __future__ import annotations

import pytest

from tools.check_tool_licenses import (
    APPROVED_STATES,
    BLOCKED_STATES,
    _package_name,
    check,
    load_registry,
    render_notice,
    tools_in_image,
)


@pytest.fixture(scope="module")
def registry():
    return load_registry()


# ── the register itself ───────────────────────────────────────────────────────────────────────────
def test_registry_loads_and_is_not_trivially_small(registry):
    assert len(registry) > 30


def test_every_entry_has_a_recognised_state(registry):
    for name, entry in registry.items():
        assert entry.state in APPROVED_STATES | BLOCKED_STATES, name


@pytest.mark.parametrize("tool,reason", [
    ("nmap", "NPSL restricts commercial redistribution"),
    ("masscan", "AGPL-3.0"),
    ("trufflehog", "AGPL-3.0"),
    ("codeql", "commercial use requires a licence"),
])
def test_the_tools_that_cannot_ship_are_blocked(registry, tool, reason):
    assert tool in registry, f"{tool} must be recorded even though it cannot ship ({reason})"
    assert registry[tool].state in BLOCKED_STATES
    assert registry[tool].notes, "a blocked tool must explain why"


@pytest.mark.parametrize("tool", ["naabu", "zmap", "gitleaks", "trivy", "nuclei", "osv-scanner"])
def test_permissive_substitutes_are_available(registry, tool):
    """For every blocked tool there is an approved alternative, or the block is a dead end."""
    assert registry[tool].state in APPROVED_STATES


# ── extraction: the false-negative regression ─────────────────────────────────────────────────────
@pytest.mark.parametrize("token,expected", [
    ('"semgrep==1.101.0"', "semgrep"),      # the pin that used to slip through
    ("'checkov==3.2.334'", "checkov"),
    ("trivy", "trivy"),
    ("github.com/projectdiscovery/naabu@v2.3.0", "naabu"),
    ("nuclei@latest", "nuclei"),
    ("gitleaks=8.22.1", "gitleaks"),
    ("--no-cache-dir", None),
    ("-y", None),
    ("", None),
])
def test_package_names_are_extracted_from_every_install_form(token, expected):
    assert _package_name(token) == expected


def test_quoted_pip_pins_are_detected_in_an_image(tmp_path):
    image = tmp_path / "Dockerfile"
    image.write_text('FROM python:3.12\nRUN pip install --no-cache-dir "semgrep==1.101.0"\n')
    assert "semgrep" in tools_in_image(image)


def test_go_install_with_a_module_path_is_detected(tmp_path):
    image = tmp_path / "Dockerfile"
    image.write_text("FROM golang\nRUN go install github.com/projectdiscovery/naabu@v2.3.0\n")
    assert "naabu" in tools_in_image(image)


# ── enforcement ───────────────────────────────────────────────────────────────────────────────────
def test_a_prohibited_tool_is_refused(tmp_path, registry):
    image = tmp_path / "Dockerfile"
    image.write_text("FROM alpine\nRUN apk add masscan\n")
    problems = check(image, registry)
    assert any("masscan" in p and "PROHIBITED" in p for p in problems)


def test_an_unregistered_tool_is_refused(tmp_path, registry):
    """Unreviewed means refused — the opposite default ships a problem quietly."""
    image = tmp_path / "Dockerfile"
    image.write_text("FROM alpine\nRUN apk add some-unreviewed-scanner\n")
    problems = check(image, registry)
    assert any("some-unreviewed-scanner" in p and "absent from the licence registry" in p
               for p in problems)


def test_a_tool_awaiting_legal_review_is_refused(tmp_path, registry):
    image = tmp_path / "Dockerfile"
    image.write_text("FROM alpine\nRUN apk add nmap\n")
    assert any("nmap" in p and "LEGAL_REVIEW" in p for p in check(image, registry))


def test_the_real_scanner_image_passes(registry):
    """The image Guardian actually ships must clear its own gate."""
    from pathlib import Path

    image = Path("infra/docker/Dockerfile.scanner")
    if not image.exists():
        pytest.skip("scanner image not present")
    assert check(image, registry) == []


# ── attribution ───────────────────────────────────────────────────────────────────────────────────
def test_notice_lists_approved_tools_and_omits_blocked_ones(registry):
    notice = render_notice(registry)
    assert "trivy" in notice
    assert "gitleaks" in notice
    assert "masscan" not in notice, "a prohibited tool must never appear in attribution"
    assert "OSV.dev" in notice, "data sources carry their own attribution requirement"
