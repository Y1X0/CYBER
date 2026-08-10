"""Templated web checks provider (Framework — first L3 SENSITIVE, in-proc curated detection).

The first provider to exercise the full L3 machinery end-to-end:
Campaign → single-use Approval → signed job → provider → Evidence. It runs a SMALL, curated,
source-controlled set of safe detection signatures (exposed `.git`, `.env`, directory listing,
`server-status`, actuator …) against authorized web targets and reports one finding per detection.

Deliberately narrow (locked, Path B — NO Nuclei): detection only — never exploitation, fuzzing,
brute force, code execution, remote/auto-updated templates, or OOB/interactsh callbacks. The checks
are constants in this file (git review is their integrity boundary); a target's path is never taken
from the wire. In-process via `httpx`; not an external binary, so it uses the in-proc sandbox
backend. L3 ⇒ authorization + campaign + single-use approval (no independent approver — that is L4).

Anti-SSRF (same discipline as ct_surface — L3 active ≠ trusted network access):
  * connect ONLY to an authorized target host from the EffectiveScope, ports 80/443 only;
  * refuse a host that resolves to a private/loopback/link-local/metadata address (DNS-rebinding);
  * never follow a redirect to a response-chosen location (`follow_redirects=False`);
  * bounded timeout, response-size cap, and a cap on checks × targets.

Evidence is bounded: status + a short, secret-redacted matched snippet — never full bodies, never
raw secrets (a secret-adjacent check emits `<redacted>`). Offline-first: without `allow_live` it
reads `settings["snapshot"]` ({host: {path: {status, body}}}), so CI needs no network.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass

from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

_ALLOWED_PORTS = (80, 443)
_TIMEOUT = 8
_MAX_BYTES = 200_000       # per-response read cap
_SNIPPET_MAX = 80          # matched-snippet cap (never a full body)
_MAX_DETECTIONS = 500      # hard cap on emitted detections (checks × targets)
_HOST_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")
# Redact long token-like runs (base64/hex secrets) so a snippet never carries a credential.
_TOKEN_RE = re.compile(r"[A-Za-z0-9+/_\-]{16,}")


@dataclass(frozen=True)
class _Check:
    id: str
    path: str            # a fixed, source-controlled path — NEVER from the wire
    pattern: str         # regex whose match confirms exposure
    title: str
    severity: Severity
    redact: bool = False  # secret-adjacent ⇒ emit no body snippet


# Curated, conservative, high-signal detection checks. Detection only — no exploitation.
_CHECKS: tuple[_Check, ...] = (
    _Check("git_config", "/.git/config", r"\[core\]", "Exposed .git/config", Severity.HIGH),
    _Check("git_head", "/.git/HEAD", r"ref:\s*refs/", "Exposed .git/HEAD", Severity.MEDIUM),
    _Check("env_file", "/.env", r"(?m)^[A-Z][A-Z0-9_]{2,}=", "Exposed .env file",
           Severity.HIGH, redact=True),
    _Check("dir_listing", "/", r"Index of /", "Directory listing enabled", Severity.LOW),
    _Check("apache_status", "/server-status", r"Apache Server Status",
           "Exposed Apache server-status", Severity.MEDIUM),
    _Check("spring_actuator", "/actuator", r'"_links"', "Exposed Spring Boot actuator",
           Severity.MEDIUM),
)
_CHECK_BY_ID = {c.id: c for c in _CHECKS}


class EgressBlocked(RuntimeError):
    """A network egress was refused by the web-checks SSRF guard (fail-closed)."""


def _is_blocked_ip(ip: str) -> bool:
    """True for any address we must never probe: private/loopback/link-local (incl. cloud metadata)/
    multicast/reserved/unspecified, or a non-literal."""
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return True
    return bool(addr.is_private or addr.is_loopback or addr.is_link_local
                or addr.is_multicast or addr.is_reserved or addr.is_unspecified)


def _assert_target_public(host: str) -> None:
    """Resolve an authorized target host and refuse if ANY address is non-public (DNS-rebinding)."""
    infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
    ips = sorted({info[4][0] for info in infos})
    if not ips:
        raise EgressBlocked(f"no address for {host!r}")
    for ip in ips:
        if _is_blocked_ip(ip):
            raise EgressBlocked(f"{host!r} resolves to non-public {ip}")


def _redact(text: str) -> str:
    return _TOKEN_RE.sub("***", text)


def _match(check: _Check, body: str) -> str | None:
    """Return a bounded, secret-redacted snippet if the check matches, else None."""
    m = re.search(check.pattern, body or "", re.IGNORECASE)
    if m is None:
        return None
    if check.redact:
        return "<redacted>"
    start = max(0, m.start())
    return _redact((body[start:start + _SNIPPET_MAX]).strip())


def _url(host: str, port: int, path: str) -> str:
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{host}:{port}{path}"


def _fetch_live(host: str, port: int, path: str) -> tuple[int, str]:  # pragma: no cover - network
    """Hardened live GET: authorized host only, public-only resolution, no redirect follow."""
    import httpx

    _assert_target_public(host)
    with httpx.Client(follow_redirects=False, timeout=_TIMEOUT) as client:
        resp = client.get(_url(host, port, path), headers={"user-agent": "guardian-web-checks"})
        if 300 <= resp.status_code < 400:
            return resp.status_code, ""      # never follow a response-chosen Location
        return resp.status_code, resp.text[:_MAX_BYTES]


class WebChecksProvider:
    """A governed, in-proc L3 templated-web-check detector. Never authorizes itself."""

    key = "web_checks"
    name = "Templated Web Checks"
    version = "1"

    @property
    def capabilities(self) -> ToolCapabilities:
        # category "web_checks" ⇒ derived L3 SENSITIVE (campaign + approval); active + network,
        # never destructive; human approval required at the policy gate.
        return ToolCapabilities(
            category="web_checks", network=True, active=True, destructive=False,
            requires_authorization=True, requires_human_approval=True,
            supported_targets=("host", "domain", "subdomain"),
            ports=_ALLOWED_PORTS, protocols=("http", "https"),
        )

    def validate(self, job: ToolJob) -> None:
        """Reject a malformed job. NOT authorization — the Control Plane gate already ran."""
        if not job.scope.targets:
            raise ValueError("web_checks: no in-scope target")

    def _scan_evidence(self, job, host, *, status, reason=""):  # noqa: ANN001, ANN202
        return RawEvidence(
            tool=self.key, execution_id=job.job_id, target=host, kind="web_checks_scan",
            data={"host": host, "status": status, "reason": reason,
                  "checks": [c.id for c in _CHECKS]},
            provenance={"mode": "offline", "source": self.key}, occurred_at="")

    def _lookup_offline(self, snapshot, host, path):  # noqa: ANN001, ANN202
        entry = (snapshot.get(host) or {}) if isinstance(snapshot, dict) else {}
        resp = entry.get(path) if isinstance(entry, dict) else None
        if not isinstance(resp, dict):
            return None
        return int(resp.get("status", 0)), str(resp.get("body", ""))

    def execute(self, job: ToolJob):  # noqa: ANN201, C901
        settings = job.settings or {}
        allow_live = bool(settings.get("allow_live"))
        snapshot = settings.get("snapshot") or {}
        ports = tuple(p for p in (job.scope.ports or _ALLOWED_PORTS) if p in _ALLOWED_PORTS)
        mode = "live" if allow_live else "offline"
        emitted = 0

        for raw_host in job.scope.targets:
            host = str(raw_host).split(":", 1)[0].strip().lower().rstrip(".")
            if not _HOST_RE.match(host):
                continue                                   # never build a URL from a bad target
            failed = False
            for port in ports:
                for check in _CHECKS:
                    if allow_live:  # pragma: no cover - network
                        try:
                            status, body = _fetch_live(host, port, check.path)
                        except EgressBlocked:
                            failed = True
                            continue                       # fail-closed for this probe
                        except OSError:
                            continue
                    else:
                        got = self._lookup_offline(snapshot, host, check.path)
                        if got is None:
                            continue
                        status, body = got
                    if status != 200:
                        continue
                    snippet = _match(check, body)
                    if snippet is None or emitted >= _MAX_DETECTIONS:
                        continue
                    emitted += 1
                    yield RawEvidence(
                        tool=self.key, execution_id=job.job_id, target=host, kind="web_check",
                        data={"host": host, "port": port, "path": check.path,
                              "check_id": check.id, "status": status, "snippet": snippet},
                        provenance={"mode": mode, "source": self.key}, occurred_at="")
            yield self._scan_evidence(job, host, status="failed" if failed else "ok")

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:
        """One finding per detection (a `web_check` evidence item); scans derive nothing."""
        if evidence.kind != "web_check":
            return None
        d = evidence.data or {}
        check = _CHECK_BY_ID.get(d.get("check_id"))
        if check is None:
            return None
        host, port = d.get("host"), d.get("port")
        return RawFinding(
            engine=EngineKey.WEB_CHECKS, title=check.title, category="misconfig",
            base_severity=check.severity, confidence="high", cwe_id="CWE-200",
            description=f"{check.title} detected on {host}:{port}{check.path}.",
            location={"endpoint": host, "port": port, "path": check.path,
                      "rule": f"web-check-{check.id}"},
            evidence={"status": d.get("status"), "snippet": d.get("snippet"),
                      "check_id": check.id})
