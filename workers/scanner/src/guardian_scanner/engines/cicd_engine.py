"""CI/CD & supply-chain security engine — the pipeline is production too (Phase A).

A build pipeline holds the keys to everything it ships: the registry credentials, the signing key,
the cloud deploy role. So an attacker who can make the pipeline run their code does not need to
breach production — the pipeline *is* the breach, and it hands over the secrets on the way. GitHub
Actions is where most of this happens now, and the attacks are not theoretical: script injection
through a pull-request title, a `pull_request_target` workflow that checks out and runs the
attacker's fork with the base repo's secrets in scope, a third-party action pinned to a mutable tag
that is quietly re-pointed at malicious code (the tj-actions/changed-files compromise, 2025). None
of Guardian's engines look here — SAST reads application source, IaC reads cloud declarations,
secrets reads text — so the workflow files that decide who runs code with the crown jewels went
unread.

This engine reads `.github/workflows/*.yml` and flags those classes directly. It is a complete
built-in detector with no external binary and no network — it parses YAML the customer already gave
us — so it is never degraded. (A future optional backend, e.g. OpenSSF Scorecard's local checks,
would augment it the way checkov augments IaC, without ever being a precondition.)
"""

from __future__ import annotations

import re
from collections.abc import Iterable
from pathlib import Path

import yaml
from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding
from guardian_core.redaction import scrub

from guardian_scanner.engines.base import EngineHealth, ScanContext

log = get_logger("guardian.engine.cicd")

_MAX_FINDINGS = 1_000
_MAX_FILE_BYTES = 1_000_000

# Contexts an outside attacker controls the value of. Interpolated straight into a `run:` shell
# script they become the script — this is the canonical GitHub Actions RCE (CWE-94). The documented
# mitigation is to route them through an intermediate `env:` variable and reference `$VAR`, so a
# dangerous context is flagged ONLY inside a run body, never in an env assignment.
_INJECTABLE = (
    "github.event.issue.title", "github.event.issue.body",
    "github.event.pull_request.title", "github.event.pull_request.body",
    "github.event.pull_request.head.ref", "github.event.pull_request.head.label",
    "github.event.pull_request.head.repo.default_branch",
    "github.event.pull_request.head.repo.description",
    "github.event.pull_request.head.repo.homepage",
    "github.event.comment.body", "github.event.review.body",
    "github.event.review_comment.body",
    "github.event.discussion.title", "github.event.discussion.body",
    "github.event.commits", "github.event.head_commit.message",
    "github.event.head_commit.author.email", "github.event.head_commit.author.name",
    "github.event.pages", "github.event.workflow_run.head_branch",
    "github.head_ref",
)
# The attacker-controlled head of a pull request, used as a checkout `ref` under
# pull_request_target.
_UNTRUSTED_REF = ("github.event.pull_request.head", "github.head_ref",
                  "github.event.pull_request.head.sha", "github.event.pull_request.head.ref")

_EXPR = re.compile(r"\$\{\{\s*(.+?)\s*\}\}", re.DOTALL)
_SHA40 = re.compile(r"^[0-9a-f]{40}$")
# curl|bash and friends: remote code piped straight into a shell, with no integrity check (CWE-494).
_PIPE_TO_SHELL = re.compile(
    r"(?:curl|wget)\b[^\n|]*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"
    r"|(?:iwr|invoke-webrequest|curl)\b[^\n|]*\|\s*iex\b",
    re.IGNORECASE)
_PUBLIC_TRIGGERS = {"pull_request", "pull_request_target"}


class CicdEngine:
    """Detects CI/CD & supply-chain risks in GitHub Actions workflows. Implements ScanEngine."""

    key = EngineKey.CICD
    name = "Guardian CI/CD & Supply-Chain Security"
    version = "1.0.0"
    requires_authorization = False  # passive: reads workflow files, no network, no credentials

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo"}

    def health(self) -> EngineHealth:
        # Self-contained: it reads YAML the customer provided. No binary to be missing, so unlike
        # the tool-augmented engines it is never degraded.
        return EngineHealth(ok=True, detail="builtin GitHub Actions workflow analysis")

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_workflow("<inline>", ctx.inline_content)
            return
        if not ctx.workspace_path:
            # A silent empty return completes cleanly, and WP-E2 reads a clean completion as licence
            # to resolve this engine's existing findings — an unscanned repo would quietly close
            # every pipeline finding it had.
            raise CicdInputError(
                "no workspace and no inline content, so no workflow file was read. An absence of "
                "input is not an absence of a poisoned pipeline."
            )
        root = Path(ctx.workspace_path)
        if not root.exists():
            raise CicdInputError(
                f"the workspace path {ctx.workspace_path!r} does not exist, so no workflow was read"
            )
        emitted = 0
        for wf in self._iter_workflows(root):
            try:
                text = wf.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            rel = str(wf.relative_to(root))
            for finding in self._scan_workflow(rel, text):
                if emitted >= _MAX_FINDINGS:
                    return
                emitted += 1
                yield finding

    def _iter_workflows(self, root: Path) -> Iterable[Path]:
        wf_dir = root / ".github" / "workflows"
        if not wf_dir.is_dir():
            return
        for path in sorted(wf_dir.iterdir()):
            if path.is_file() and path.suffix.lower() in {".yml", ".yaml"}:
                try:
                    if path.stat().st_size <= _MAX_FILE_BYTES:
                        yield path
                except OSError:
                    continue

    def _scan_workflow(self, path: str, text: str) -> Iterable[RawFinding]:
        try:
            data = yaml.safe_load(text)
        except yaml.YAMLError as exc:
            # A workflow we cannot parse is a workflow we did not check. Not a scan failure, but not
            # silent either — an unparsed file must not look like a clean one.
            log.warning("cicd_workflow_unparsed", path=path[:200],
                        error=f"{type(exc).__name__}"[:120])
            return
        if not isinstance(data, dict):
            return
        raw_lines = text.splitlines()
        triggers = _triggers(data)
        jobs = data.get("jobs")
        if not isinstance(jobs, dict):
            jobs = {}

        # Top-level over-privileged token.
        yield from self._permissions_findings(path, "<workflow>", data, raw_lines)

        for job_name, job in jobs.items():
            if not isinstance(job, dict):
                continue
            jname = str(job_name)
            yield from self._permissions_findings(path, jname, job, raw_lines)
            yield from self._self_hosted_finding(path, jname, job, triggers, raw_lines)
            steps = job.get("steps")
            if not isinstance(steps, list):
                continue
            has_pr_target = "pull_request_target" in triggers
            for step in steps:
                if not isinstance(step, dict):
                    continue
                yield from self._injection_findings(path, jname, step, raw_lines)
                yield from self._pipe_to_shell_findings(path, jname, step, raw_lines)
                yield from self._unpinned_action_finding(path, jname, step, raw_lines)
                if has_pr_target:
                    yield from self._pr_target_checkout_finding(path, jname, step, raw_lines)

    # --- individual detectors -------------------------------------------------------------------

    def _injection_findings(self, path, job, step, raw_lines):  # noqa: ANN001
        run = step.get("run")
        if not isinstance(run, str):
            return
        for m in _EXPR.finditer(run):
            expr = m.group(1)
            hit = next((c for c in _INJECTABLE if c in expr), None)
            if hit is None:
                continue
            snippet = scrub(m.group(0))[0]
            f = self._finding(
                rule="CICD-INJECTION", path=path, job=job,
                step=_step_name(step), line=_find_line(raw_lines, m.group(0)),
                severity=Severity.CRITICAL, confidence="high", category="cicd-injection",
                cwe="CWE-94", title="CI/CD script injection via untrusted context",
                description=(
                    f"A workflow `run:` step interpolates the attacker-controllable context "
                    f"`{hit}` directly into a shell script ({snippet}). Anyone who can set that "
                    "value — a pull-request title, an issue body, a branch name — can inject shell "
                    "commands that run in the pipeline with its tokens and secrets. Route the "
                    "value through an intermediate `env:` variable and reference it as a quoted "
                    "`\"$VAR\"` instead of expanding `${{ ... }}` inside the script."
                ),
                references={
                    "cwe": "https://cwe.mitre.org/data/definitions/94.html",
                    "guide": ("https://securitylab.github.com/resources/"
                              "github-actions-untrusted-input/"),
                },
            )
            if f is not None:
                yield f

    def _pipe_to_shell_findings(self, path, job, step, raw_lines):  # noqa: ANN001
        run = step.get("run")
        if not isinstance(run, str):
            return
        m = _PIPE_TO_SHELL.search(run)
        if m is None:
            return
        snippet = scrub(m.group(0))[0][:200]
        f = self._finding(
            rule="CICD-CURL-BASH", path=path, job=job, step=_step_name(step),
            line=_find_line(raw_lines, m.group(0)[:60]),
            severity=Severity.MEDIUM, confidence="medium", category="cicd-supply-chain",
            cwe="CWE-494", title="CI/CD downloads and executes remote code without verification",
            description=(
                f"A workflow step pipes a downloaded script straight into a shell ({snippet}). "
                "The remote content is executed with no integrity check, so whoever controls that "
                "URL — or anyone who can MITM or take over the host — runs code in the pipeline. "
                "Pin the download to a known digest and verify it before executing, or install "
                "from a trusted package source."
            ),
            references={"cwe": "https://cwe.mitre.org/data/definitions/494.html"},
        )
        if f is not None:
            yield f

    def _unpinned_action_finding(self, path, job, step, raw_lines):  # noqa: ANN001
        uses = step.get("uses")
        if not isinstance(uses, str) or "@" not in uses:
            return
        ref = uses.rsplit("@", 1)[1].strip()
        target = uses.rsplit("@", 1)[0].strip()
        if target.startswith("./") or target.startswith("docker://"):
            return  # local composite action / image digest — not a mutable third-party tag
        if _SHA40.match(ref):
            return  # already pinned to an immutable commit
        owner = target.split("/", 1)[0].lower()
        first_party = owner in {"actions", "github"}
        sev = Severity.LOW if first_party else Severity.MEDIUM
        f = self._finding(
            rule="CICD-UNPINNED-ACTION", path=path, job=job, step=_step_name(step),
            line=_find_line(raw_lines, uses),
            severity=sev, confidence="high", category="cicd-supply-chain",
            cwe="CWE-1357", title=f"Unpinned action dependency: {target}",
            description=(
                f"The workflow uses `{uses}`, pinned to the mutable tag/branch `{ref}` rather than "
                "a full 40-character commit SHA. Whoever controls that action can re-point the tag "
                "at new code, which then runs in the pipeline with its tokens — the mechanism of "
                "the tj-actions/changed-files compromise. Pin third-party actions to a commit "
                "SHA and update deliberately."
                + ("" if not first_party else " (First-party action: lower risk, but SHA-pinning "
                   "is still the hardening baseline.)")
            ),
            references={"cwe": "https://cwe.mitre.org/data/definitions/1357.html"},
        )
        if f is not None:
            yield f

    def _permissions_findings(self, path, scope, block, raw_lines):  # noqa: ANN001
        perms = block.get("permissions")
        if perms == "write-all" or (isinstance(perms, str) and perms.strip() == "write-all"):
            f = self._finding(
                rule="CICD-WRITE-ALL", path=path, job=scope, step=None,
                line=_find_line(raw_lines, "write-all"),
                severity=Severity.MEDIUM, confidence="high", category="cicd-permissions",
                cwe="CWE-272", title="CI/CD grants the workflow token write-all permissions",
                description=(
                    f"The `{scope}` scope sets `permissions: write-all`, giving the GITHUB_TOKEN "
                    "write access to every scope — contents, packages, deployments, actions and "
                    "more. If any step is compromised (a poisoned dependency, an injected "
                    "command), that token can push code, publish packages and alter releases. "
                    "Grant only the specific permissions each job needs and default the rest to "
                    "read or none."
                ),
                references={
                    "cwe": "https://cwe.mitre.org/data/definitions/272.html",
                    "docs": ("https://docs.github.com/actions/security-guides/"
                             "automatic-token-authentication"),
                },
            )
            if f is not None:
                yield f

    def _self_hosted_finding(self, path, job, block, triggers, raw_lines):  # noqa: ANN001
        runs_on = block.get("runs-on")
        labels = ([runs_on] if isinstance(runs_on, str)
                  else runs_on if isinstance(runs_on, list) else [])
        if not any("self-hosted" in str(x).lower() for x in labels):
            return
        if not (triggers & _PUBLIC_TRIGGERS):
            return
        f = self._finding(
            rule="CICD-SELFHOSTED-PUBLIC", path=path, job=job, step=None,
            line=_find_line(raw_lines, "self-hosted"),
            severity=Severity.HIGH, confidence="medium", category="cicd-supply-chain",
            cwe="CWE-668", title="Self-hosted runner reachable from a public trigger",
            description=(
                f"Job `{job}` runs on a self-hosted runner and the workflow is triggered by "
                f"{', '.join(sorted(triggers & _PUBLIC_TRIGGERS))}. A fork's pull request can then "
                "execute code on infrastructure you own, which — unlike GitHub's ephemeral "
                "runners — persists state between jobs and often sits inside your network. "
                "Restrict the runner to trusted events, require approval for fork PRs, or use "
                "ephemeral isolated runners."
            ),
            references={"cwe": "https://cwe.mitre.org/data/definitions/668.html"},
        )
        if f is not None:
            yield f

    def _pr_target_checkout_finding(self, path, job, step, raw_lines):  # noqa: ANN001
        uses = step.get("uses")
        if not (isinstance(uses, str) and uses.split("@", 1)[0].strip().lower()
                .endswith("actions/checkout")):
            return
        with_ = step.get("with")
        ref = str(with_.get("ref", "")) if isinstance(with_, dict) else ""
        if not any(u in ref for u in _UNTRUSTED_REF):
            return  # default checkout under pull_request_target takes the base — the safer case
        f = self._finding(
            rule="CICD-PR-TARGET-CHECKOUT", path=path, job=job, step=_step_name(step),
            line=_find_line(raw_lines, ref) or _find_line(raw_lines, "pull_request_target"),
            severity=Severity.CRITICAL, confidence="high", category="cicd-supply-chain",
            cwe="CWE-269", title="pull_request_target checks out and runs untrusted PR code",
            description=(
                f"This workflow runs on `pull_request_target` — which executes in the base "
                f"repository's context with its secrets — and job `{job}` checks out the "
                f"attacker's pull-request head (`ref: {scrub(ref)[0]}`). Building or running that "
                "code exposes the repository secrets to a fork's pull request, a full secret-"
                "exfiltration and supply-chain path. Use `pull_request` for untrusted code, or "
                "check out the head only in a job that holds no secrets and no write permissions."
            ),
            references={
                "cwe": "https://cwe.mitre.org/data/definitions/269.html",
                "guide": ("https://securitylab.github.com/resources/"
                          "github-actions-preventing-pwn-requests/"),
            },
        )
        if f is not None:
            yield f

    # --- shared construction --------------------------------------------------------------------

    def _finding(self, *, rule, path, job, step, line, severity, confidence, category, cwe, title,
                 description, references):  # noqa: ANN001
        return RawFinding(
            engine=EngineKey.CICD,
            title=title[:300],
            category=category,
            description=description,
            base_severity=severity,
            confidence=confidence,
            cwe_id=cwe,
            location={"path": path, "job": job, "step": step, "line": line, "rule": rule},
            evidence={"detector": "builtin-cicd", "rule": rule, "workflow": path, "job": job},
            references=references,
        )


class CicdInputError(RuntimeError):
    """There was no workflow to read (readiness audit, Phase 4)."""


def _triggers(data: dict) -> set[str]:
    # YAML 1.1 parses the bare key `on` as the boolean True, so a workflow's triggers arrive under
    # the key True, not "on". Read both.
    raw = data.get("on")
    if raw is None:
        raw = data.get(True)
    if isinstance(raw, str):
        return {raw}
    if isinstance(raw, list):
        return {str(x) for x in raw}
    if isinstance(raw, dict):
        return {str(k) for k in raw}
    return set()


def _step_name(step: dict) -> str | None:
    name = step.get("name") or step.get("uses") or step.get("id")
    return str(name)[:120] if name else None


def _find_line(raw_lines: list[str], needle: str) -> int | None:
    """Best-effort 1-based line of a distinctive substring. Line numbers are lost by safe_load, so
    this re-locates the offending text in the raw file; None when it cannot be pinned exactly."""
    if not needle:
        return None
    needle = needle.strip()
    for i, line in enumerate(raw_lines, start=1):
        if needle in line:
            return i
    return None
