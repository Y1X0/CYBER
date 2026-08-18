"""Templated web checks provider (L3 SENSITIVE, in-proc detection) — WP-D1.

Runs the full L3 machinery end to end: Campaign → single-use Approval → signed job → provider →
Evidence. It executes source-controlled detection templates against authorized web targets and
reports one finding per detection.

**What changed in WP-D1.** The checks used to be six `_Check` tuples hard-coded in this file. They
are now nuclei-format templates in `guardian_scanner/templates/library`, executed by Guardian's own
template engine. The original decision recorded here — "locked, Path B, NO Nuclei" — was aimed at
two specific risks, and both are still refused:

  * *A remote, auto-updating template feed is unreviewable code aimed at a customer's production.*
    Templates are files in this repository, loaded from disk, never fetched at scan time. Git review
    is still their integrity boundary.
  * *Nuclei can do far more than detect.* `templates/loader.py` denies by default: `http` only, GET
    and HEAD only, no DSL evaluation, no payload sets or attack modes, no raw requests, no
    redirects, no out-of-band callbacks. A template using any of them is refused by name, not
    silently downgraded.

What is gained is that adding a check is now a reviewed YAML file rather than a code change, and the
MIT-licensed public corpus can be adopted template by template through the same review.

Detection only — never exploitation, fuzzing, brute force, or code execution. In-process via
`httpx`; not an external binary, so it uses the in-proc sandbox backend and needs no kernel
privileges.

Anti-SSRF (unchanged — L3 active ≠ trusted network access):
  * connect ONLY to an authorized target host from the EffectiveScope, ports 80/443 only;
  * refuse a host that resolves to a private/loopback/link-local/metadata address (DNS-rebinding);
  * never follow a redirect to a response-chosen location (`follow_redirects=False`);
  * bounded timeout, response-size cap, and a cap on detections.

Evidence is bounded: status + a short, secret-redacted matched snippet — never full bodies, never
raw secrets (a secret-adjacent template emits `<redacted>`). Offline-first: without `allow_live` it
reads `settings["snapshot"]` ({host: {path: {status, body, headers}}}), so CI needs no network.
"""

from __future__ import annotations

import ipaddress
import re
import socket

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey
from guardian_core.findings import RawFinding
from guardian_core.tool import RawEvidence, ToolCapabilities, ToolJob

from guardian_scanner.templates import Response, Template, library_path, load_directory
from guardian_scanner.templates.runner import run_template

log = get_logger("guardian.web_checks")

_ALLOWED_PORTS = (80, 443)
_TIMEOUT = 8
_MAX_BYTES = 200_000       # per-response read cap
_MAX_DETECTIONS = 500      # hard cap on emitted detections (templates × targets)
_HOST_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)(\.(?!-)[a-z0-9-]{1,63}(?<!-))+$")

_LIBRARY: tuple[Template, ...] | None = None
_REJECTED: tuple[str, ...] = ()


def templates() -> tuple[Template, ...]:
    """The loaded template library, read once.

    Deliberately silent: `execute` runs inside the fork sandbox, which closes inherited file
    descriptors, so a log emitted from there writes to a descriptor that no longer exists — and the
    resulting OSError is caught as a containment, turning a logging call into an empty scan. The
    library is warmed and its rejections reported in `validate`, which runs in the parent.
    """
    global _LIBRARY, _REJECTED  # noqa: PLW0603 - process-wide cache of a read-only library
    if _LIBRARY is None:
        loaded, rejected = load_directory(library_path())
        _LIBRARY = loaded
        _REJECTED = tuple(f"{r.source}: {r.reason}" for r in rejected)
    return _LIBRARY


def template_by_id(template_id: str) -> Template | None:
    return next((t for t in templates() if t.id == template_id), None)


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


def _url(host: str, port: int, path: str) -> str:
    scheme = "https" if port == 443 else "http"
    return f"{scheme}://{host}:{port}{path}"


def _fetch_live(  # pragma: no cover - network
    host: str, port: int, method: str, path: str, headers: tuple[tuple[str, str], ...]
) -> Response:
    """Hardened live request: authorized host only, public-only resolution, no redirect follow."""
    import httpx

    _assert_target_public(host)
    sent = {"user-agent": "guardian-web-checks", **{k.lower(): v for k, v in headers}}
    with httpx.Client(follow_redirects=False, timeout=_TIMEOUT) as client:
        resp = client.request(method, _url(host, port, path), headers=sent)
        response_headers = {k.lower(): v for k, v in resp.headers.items()}
        if 300 <= resp.status_code < 400:
            # Never follow a response-chosen Location, and never treat its body as evidence.
            return Response(status=resp.status_code, headers=response_headers, body="")
        return Response(status=resp.status_code, headers=response_headers,
                        body=resp.text[:_MAX_BYTES])


class WebChecksProvider:
    """A governed, in-proc L3 template detector. Never authorizes itself."""

    key = "web_checks"
    name = "Templated Web Checks"
    version = "2"

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
        """Reject a malformed job. NOT authorization — the Control Plane gate already ran.

        Also warms the template library. This runs in the parent process, before the sandbox forks,
        which is the only place a rejected template can be reported somewhere a human will see it —
        and a template that silently stops loading is a check that silently stops running.
        """
        if not job.scope.targets:
            raise ValueError("web_checks: no in-scope target")
        loaded = templates()
        for reason in _REJECTED:
            log.error("template_rejected", detail=reason[:300])
        if not loaded:
            raise ValueError("web_checks: no usable templates — refusing to report a clean scan")
        log.info("template_library_loaded", loaded=len(loaded), rejected=len(_REJECTED))

    def _scan_evidence(self, job, host, *, status, reason=""):  # noqa: ANN001, ANN202
        return RawEvidence(
            tool=self.key, execution_id=job.job_id, target=host, kind="web_checks_scan",
            data={"host": host, "status": status, "reason": reason,
                  "templates": [t.id for t in templates()],
                  "templates_rejected": list(_REJECTED)},
            provenance={"mode": "offline", "source": self.key}, occurred_at="")

    def _offline_fetch(self, snapshot, host):  # noqa: ANN001, ANN202
        """Build a fetch over a recorded snapshot.

        A path with no recording is a miss, not a match: offline mode must never invent a response.
        """
        entry = (snapshot.get(host) or {}) if isinstance(snapshot, dict) else {}

        def fetch(method: str, path: str, headers: tuple[tuple[str, str], ...]) -> Response:
            del method, headers
            recorded = entry.get(path) if isinstance(entry, dict) else None
            if not isinstance(recorded, dict):
                raise KeyError(path)
            return Response(
                status=int(recorded.get("status", 0)),
                headers={str(k).lower(): str(v)
                         for k, v in (recorded.get("headers") or {}).items()},
                body=str(recorded.get("body", "")),
            )

        return fetch

    def execute(self, job: ToolJob):  # noqa: ANN201
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
                if allow_live:  # pragma: no cover - network
                    try:
                        _assert_target_public(host)
                    except (EgressBlocked, OSError):
                        failed = True
                        continue                           # fail-closed for this target
                    def fetch(method, path, headers, _h=host, _p=port):  # noqa: ANN001,ANN202
                        return _fetch_live(_h, _p, method, path, headers)
                else:
                    fetch = self._offline_fetch(snapshot, host)

                for template in templates():
                    if emitted >= _MAX_DETECTIONS:
                        break
                    for detection in run_template(template, host=host, port=port, fetch=fetch):
                        emitted += 1
                        yield RawEvidence(
                            tool=self.key, execution_id=job.job_id, target=host,
                            kind="web_check",
                            data={"host": host, "port": port, "path": detection.path,
                                  "template_id": template.id, "status": detection.status,
                                  "snippet": detection.snippet,
                                  "matched_at": detection.matched_at,
                                  "matcher": detection.matcher_name,
                                  "extracted": {k: list(v)
                                                for k, v in detection.extracted.items()}},
                            provenance={"mode": mode, "source": self.key,
                                        "template": template.source},
                            occurred_at="")
            yield self._scan_evidence(job, host, status="failed" if failed else "ok")

    def normalize(self, evidence: RawEvidence) -> RawFinding | None:
        """One finding per detection (a `web_check` evidence item); scans derive nothing."""
        if evidence.kind != "web_check":
            return None
        data = evidence.data or {}
        template = template_by_id(str(data.get("template_id")))
        if template is None:
            return None
        host, port, path = data.get("host"), data.get("port"), data.get("path")
        classification = template.classification
        description = template.description or f"{template.name} detected on {host}:{port}{path}."
        if template.remediation:
            description = f"{description.rstrip()}\n\nRemediation: {template.remediation}"

        return RawFinding(
            engine=EngineKey.WEB_CHECKS,
            title=template.name,
            category="misconfig",
            description=description,
            base_severity=template.severity,
            confidence="high",
            cwe_id=classification.cwe_ids[0] if classification.cwe_ids else "CWE-200",
            cve_ids=list(classification.cve_ids),
            cvss_base=classification.cvss_score,
            location={"endpoint": host, "port": port, "path": path,
                      "rule": f"web-check-{template.id}"},
            evidence={"status": data.get("status"), "snippet": data.get("snippet"),
                      "template_id": template.id, "matched_at": data.get("matched_at"),
                      "matcher": data.get("matcher"), "extracted": data.get("extracted") or {}},
            references={"reference": list(template.reference)} if template.reference else {},
        )
