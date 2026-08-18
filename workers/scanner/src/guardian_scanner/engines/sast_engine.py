"""SAST engine — static detection of insecure code (WP-D4).

Three layers, each answering a question the one below it cannot:

1. **Taint analysis (Python).** Does attacker-controlled data reach a dangerous operation, and was
   it neutralized for *that* class of vulnerability on the way? A confirmed flow carries the path it
   took, so a reviewer can check the claim instead of trusting it.
2. **Pattern rules (all supported languages), over masked source.** Dangerous constructs that are
   wrong regardless of where the data came from — `shell=True`, disabled TLS verification, MD5 for
   passwords. Comments and string literals are blanked out first, so a docstring that mentions
   `eval()` is no longer reported as code injection.
3. **semgrep, when present.** Thousands of community rules, merged rather than reimplemented
   (ADR-005). The engine never requires it, and says so in `health()` when it is missing, because a
   scanner running at a fraction of its coverage and reporting success is worse than one that fails.

All detection lives in the plugin; the core knows nothing about these rules.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell
from collections.abc import Iterable
from dataclasses import dataclass
from pathlib import Path

from guardian_core.enums import EngineKey, Severity
from guardian_core.evidence import code_evidence
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext
from guardian_scanner.sast.masking import mask_non_code, suppressed_lines
from guardian_scanner.sast.taint import TaintFinding, analyze_python


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe: str
    owasp: str
    suffixes: tuple[str, ...]  # empty = all supported code files
    remediation: str = ""
    # Some constructs are a defect in production and the correct construct in a test. `assert` is
    # the clearest case: as a runtime authorization gate it disappears under `python -O`; in a test
    # it is the whole point. Firing there produced 36 of this engine's first 40 findings against
    # Guardian's own repository, every one of them noise.
    skip_in_tests: bool = False


_PY = (".py", ".pyi")
_JS = (".js", ".ts", ".tsx", ".jsx")
_JAVA = (".java",)
_GO = (".go",)
_PHP = (".php",)
_RUBY = (".rb",)
_CS = (".cs",)

_RULES: tuple[Rule, ...] = (
    # ── Python ───────────────────────────────────────────────────────────────────────────────────
    Rule("py-eval", "Use of eval()", re.compile(r"\beval\s*\("),
         Severity.MEDIUM, "CWE-95", "A03:2021", _PY,
         "Parse the value; eval on anything not a literal is code execution."),
    Rule("py-exec", "Use of exec()", re.compile(r"\bexec\s*\("),
         Severity.MEDIUM, "CWE-95", "A03:2021", _PY, ""),
    Rule("py-shell-true", "subprocess with shell=True",
         re.compile(r"shell\s*=\s*True"), Severity.HIGH, "CWE-78", "A03:2021", _PY,
         "Pass argv as a list; a shell is only needed for shell syntax."),
    Rule("py-os-system", "os.system() call", re.compile(r"\bos\.system\s*\("),
         Severity.HIGH, "CWE-78", "A03:2021", _PY, ""),
    Rule("py-yaml-load", "Unsafe yaml.load()",
         re.compile(r"yaml\.(unsafe_load|full_load)\s*\(|yaml\.load\s*\((?![^)]*Safe)"),
         Severity.HIGH, "CWE-502", "A08:2021", _PY, "Use yaml.safe_load."),
    Rule("py-pickle", "Unsafe pickle deserialization", re.compile(r"\bpickle\.loads?\s*\("),
         Severity.MEDIUM, "CWE-502", "A08:2021", _PY,
         "Pickle executes code on load; use JSON for anything crossing a trust boundary."),
    Rule("py-weak-hash", "Weak hash (md5/sha1)", re.compile(r"hashlib\.(md5|sha1)\s*\("),
         Severity.MEDIUM, "CWE-327", "A02:2021", _PY,
         "Use SHA-256, or bcrypt/argon2 for passwords."),
    Rule("py-tls-verify-off", "TLS verification disabled", re.compile(r"verify\s*=\s*False"),
         Severity.HIGH, "CWE-295", "A07:2021", _PY,
         "A disabled certificate check makes the connection interceptable by anyone on the path."),
    Rule("py-ssl-unverified", "Unverified SSL context",
         re.compile(r"_create_unverified_context|CERT_NONE"),
         Severity.HIGH, "CWE-295", "A07:2021", _PY, ""),
    Rule("py-sql-fstring", "SQL built by string interpolation",
         re.compile(r"execute\s*\(\s*(?:f['\"]|['\"].*%\s*%?\s*[a-zA-Z_(])"),
         Severity.HIGH, "CWE-89", "A03:2021", _PY, "Use bound parameters."),
    Rule("py-weak-random", "Cryptographic value from a predictable PRNG",
         re.compile(r"\brandom\.(random|randint|choice|randrange|sample|shuffle)\s*\("),
         Severity.LOW, "CWE-338", "A02:2021", _PY,
         "Use `secrets` for tokens, passwords and keys; `random` is reproducible by design."),
    Rule("py-assert-auth", "Security check written as an assert",
         re.compile(r"^\s*assert\s+.*(auth|permission|is_admin|token|role)", re.IGNORECASE),
         Severity.MEDIUM, "CWE-617", "A01:2021", _PY,
         "Assertions are removed under `python -O`, deleting the check with them.",
         skip_in_tests=True),
    Rule("py-bind-all", "Service bound to every interface",
         re.compile(r"['\"]0\.0\.0\.0['\"]"), Severity.LOW, "CWE-1327", "A05:2021", _PY, ""),
    Rule("py-flask-debug", "Flask debug mode enabled",
         re.compile(r"\.run\s*\([^)]*debug\s*=\s*True"), Severity.HIGH, "CWE-489", "A05:2021", _PY,
         "The Werkzeug debugger is a remote shell if it is reachable."),
    Rule("py-jwt-noverify", "JWT signature verification disabled",
         re.compile(r"verify_signature['\"]?\s*:\s*False|verify\s*=\s*False.*jwt|jwt\.decode\([^)]*verify\s*=\s*False"),
         Severity.CRITICAL, "CWE-347", "A02:2021", _PY,
         "An unverified JWT is an attacker-authored JWT."),
    Rule("py-tempfile-mktemp", "Insecure temporary file",
         re.compile(r"tempfile\.mktemp\s*\("), Severity.MEDIUM, "CWE-377", "A01:2021", _PY,
         "mktemp is a race by construction; use NamedTemporaryFile or mkstemp."),
    Rule("py-xml-entities", "XML parsed with entity expansion enabled",
         re.compile(r"\b(xml\.etree|minidom|pulldom|sax|lxml\.etree)\b.*\bparse"),
         Severity.MEDIUM, "CWE-611", "A05:2021", _PY, "Use defusedxml for untrusted documents."),

    # ── JavaScript / TypeScript ──────────────────────────────────────────────────────────────────
    Rule("js-eval", "Use of eval()", re.compile(r"\beval\s*\("),
         Severity.MEDIUM, "CWE-95", "A03:2021", _JS, ""),
    Rule("js-function-ctor", "Code built with the Function constructor",
         re.compile(r"\bnew\s+Function\s*\("), Severity.MEDIUM, "CWE-95", "A03:2021", _JS, ""),
    Rule("js-child-exec", "child_process.exec()",
         re.compile(r"child_process\.exec\s*\(|\bexecSync\s*\("),
         Severity.HIGH, "CWE-78", "A03:2021", _JS, "Use execFile/spawn with an argument array."),
    Rule("js-inner-html", "Assignment to innerHTML", re.compile(r"\.innerHTML\s*="),
         Severity.MEDIUM, "CWE-79", "A03:2021", _JS,
         "Use textContent, or sanitize with DOMPurify."),
    Rule("js-danger-html", "React dangerouslySetInnerHTML",
         re.compile(r"dangerouslySetInnerHTML"), Severity.MEDIUM, "CWE-79", "A03:2021", _JS, ""),
    Rule("js-document-write", "document.write()", re.compile(r"document\.write(ln)?\s*\("),
         Severity.MEDIUM, "CWE-79", "A03:2021", _JS, ""),
    Rule("js-tls-off", "Node TLS certificate validation disabled",
         re.compile(r"rejectUnauthorized\s*:\s*false|NODE_TLS_REJECT_UNAUTHORIZED['\"]?\]?\s*=\s*['\"]?0"),
         Severity.HIGH, "CWE-295", "A07:2021", _JS, ""),
    Rule("js-weak-random", "Math.random() used for a security value",
         re.compile(r"Math\.random\s*\(\s*\).*(token|secret|key|password|nonce|otp)",
                    re.IGNORECASE),
         Severity.MEDIUM, "CWE-338", "A02:2021", _JS,
         "Use crypto.randomBytes / crypto.randomUUID."),
    Rule("js-jwt-none", "JWT algorithm 'none'",
         re.compile(r"algorithm['\"]?\s*:\s*['\"]none['\"]", re.IGNORECASE),
         Severity.CRITICAL, "CWE-347", "A02:2021", _JS, ""),

    # ── Java ─────────────────────────────────────────────────────────────────────────────────────
    Rule("java-runtime-exec", "Runtime.exec()", re.compile(r"Runtime\.getRuntime\(\)\.exec\s*\("),
         Severity.HIGH, "CWE-78", "A03:2021", _JAVA, ""),
    Rule("java-sql-concat", "SQL built by concatenation",
         re.compile(r"(createStatement|executeQuery|executeUpdate)\s*\([^)]*\+"),
         Severity.HIGH, "CWE-89", "A03:2021", _JAVA,
         "Use PreparedStatement with bound parameters."),
    Rule("java-deser", "Java native deserialization",
         re.compile(r"new\s+ObjectInputStream\s*\(|\.readObject\s*\(\s*\)"),
         Severity.HIGH, "CWE-502", "A08:2021", _JAVA, ""),
    Rule("java-trust-all", "TrustManager that accepts every certificate",
         re.compile(r"checkServerTrusted\s*\([^)]*\)\s*\{\s*\}|TrustAllCerts|ALLOW_ALL_HOSTNAME_VERIFIER"),
         Severity.HIGH, "CWE-295", "A07:2021", _JAVA, ""),
    Rule("java-weak-crypto", "Weak cipher or hash",
         re.compile(r"getInstance\s*\(\s*['\"](DES|RC4|MD5|SHA-?1|AES/ECB)"),
         Severity.MEDIUM, "CWE-327", "A02:2021", _JAVA, ""),
    Rule("java-xxe", "XML parser without external-entity protection",
         re.compile(r"DocumentBuilderFactory\.newInstance|SAXParserFactory\.newInstance"),
         Severity.MEDIUM, "CWE-611", "A05:2021", _JAVA,
         "setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true)"),

    # ── Go ───────────────────────────────────────────────────────────────────────────────────────
    Rule("go-exec-shell", "Command run through a shell",
         re.compile(r"exec\.Command\s*\(\s*['\"](sh|bash|cmd)['\"]"),
         Severity.HIGH, "CWE-78", "A03:2021", _GO, ""),
    Rule("go-sql-concat", "SQL built with Sprintf/concatenation",
         re.compile(r"(Query|Exec|QueryRow)\s*\(\s*(fmt\.Sprintf|[^,)]*\+)"),
         Severity.HIGH, "CWE-89", "A03:2021", _GO, "Use placeholders and pass arguments."),
    Rule("go-tls-skip", "TLS verification disabled",
         re.compile(r"InsecureSkipVerify\s*:\s*true"),
         Severity.HIGH, "CWE-295", "A07:2021", _GO, ""),
    Rule("go-weak-random", "math/rand used for a security value",
         re.compile(r"\brand\.(Int|Intn|Float64|Read)\s*\("),
         Severity.LOW, "CWE-338", "A02:2021", _GO, "Use crypto/rand."),

    # ── PHP ──────────────────────────────────────────────────────────────────────────────────────
    Rule("php-exec", "Shell execution",
         re.compile(r"\b(system|shell_exec|passthru|popen|proc_open)\s*\("),
         Severity.HIGH, "CWE-78", "A03:2021", _PHP, ""),
    Rule("php-eval", "eval()", re.compile(r"\beval\s*\("),
         Severity.HIGH, "CWE-95", "A03:2021", _PHP, ""),
    Rule("php-unserialize", "unserialize() on input",
         re.compile(r"\bunserialize\s*\("), Severity.HIGH, "CWE-502", "A08:2021", _PHP, ""),
    Rule("php-include-var", "Dynamic include",
         re.compile(r"\b(include|require)(_once)?\s*\(?\s*\$"),
         Severity.HIGH, "CWE-98", "A03:2021", _PHP, ""),

    # ── Ruby / C# ────────────────────────────────────────────────────────────────────────────────
    Rule("rb-eval", "eval / instance_eval", re.compile(r"\b(eval|instance_eval|class_eval)\s*\("),
         Severity.MEDIUM, "CWE-95", "A03:2021", _RUBY, ""),
    Rule("rb-yaml-load", "YAML.load on untrusted input", re.compile(r"YAML\.load\s*\("),
         Severity.HIGH, "CWE-502", "A08:2021", _RUBY, "Use YAML.safe_load."),
    Rule("cs-sql-concat", "SQL built by concatenation",
         re.compile(r"SqlCommand\s*\(\s*['\"][^'\"]*['\"]\s*\+"),
         Severity.HIGH, "CWE-89", "A03:2021", _CS, ""),
    Rule("cs-tls-off", "Certificate validation callback always true",
         re.compile(r"ServerCertificateValidationCallback\s*(\+)?=\s*.*true"),
         Severity.HIGH, "CWE-295", "A07:2021", _CS, ""),
)

_SKIP_DIRS = {
    ".git", "node_modules", "venv", ".venv", "dist", "build", "__pycache__", ".mypy_cache",
    "vendor", ".tox", "site-packages", ".next", "target",
}
_ALL_SUFFIXES = _PY + _JS + _JAVA + _GO + _PHP + _RUBY + _CS
_MAX_FILE_BYTES = 1_000_000
_MAX_FILES = 20_000

# A vulnerable pattern in a test is usually the test's subject, not the product's flaw. It is still
# reported — test code ships in some repositories and leaks into images — but it must not outrank a
# real finding in the customer's queue.
_TEST_MARKERS = ("/tests/", "/test/", "/spec/", "_test.", "test_", ".spec.", ".test.")


class SastEngine:
    key = EngineKey.SAST
    name = "Guardian SAST (taint analysis + pattern rules + optional semgrep)"
    version = "2.0.0"
    requires_authorization = False

    def supports(self, asset_kind: str) -> bool:
        return asset_kind in {"repo", "k8s_manifest", "container_image"}

    def health(self) -> EngineHealth:
        """Taint analysis and the pattern rules are dependency-free, so the engine always runs.
        Without semgrep it runs without the community ruleset — a real capability difference that
        must be visible rather than inferred from a shorter report."""
        has_semgrep = bool(shutil.which("semgrep"))
        return EngineHealth(
            ok=True,
            detail=(
                f"taint analysis + {len(_RULES)} pattern rules + semgrep"
                if has_semgrep
                else f"taint analysis + {len(_RULES)} pattern rules — semgrep absent, "
                     "community ruleset unavailable"
            ),
            degraded=not has_semgrep,
            missing=() if has_semgrep else ("semgrep",),
        )

    # ── entry point ──────────────────────────────────────────────────────────────────────────────
    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            yield from self._scan_file("<inline>", ctx.inline_content, ".py")
            return
        if not ctx.workspace_path:
            return
        root = Path(ctx.workspace_path)
        if not root.exists():
            return
        for path in self._iter_files(root):
            try:
                text = path.read_text(encoding="utf-8", errors="ignore")
            except OSError:
                continue
            yield from self._scan_file(str(path.relative_to(root)), text, path.suffix.lower())
        yield from self._run_semgrep_if_available(root)

    def _iter_files(self, root: Path) -> Iterable[Path]:
        seen = 0
        for path in root.rglob("*"):
            if seen >= _MAX_FILES:
                return
            if not path.is_file() or path.suffix.lower() not in _ALL_SUFFIXES:
                continue
            if any(part in _SKIP_DIRS for part in path.parts):
                continue
            try:
                if path.stat().st_size > _MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            seen += 1
            yield path

    # ── per-file analysis ────────────────────────────────────────────────────────────────────────
    def _scan_file(self, path: str, text: str, suffix: str) -> Iterable[RawFinding]:
        suppressed = suppressed_lines(text)
        is_test = _looks_like_test(path)

        taint_lines: set[tuple[str, int]] = set()
        if suffix in _PY:
            for flow in analyze_python(text, path):
                if flow.line in suppressed:
                    continue
                taint_lines.add((flow.sink.cwe, flow.line))
                yield _taint_finding(flow, is_test)

        masked = mask_non_code(text, suffix)
        masked_lines = masked.splitlines()
        original_lines = text.splitlines()
        applicable = [
            r for r in _RULES if suffix in r.suffixes and not (is_test and r.skip_in_tests)
        ]
        if not applicable:
            return
        for lineno, masked_line in enumerate(masked_lines, start=1):
            if lineno in suppressed or not masked_line.strip() or len(masked_line) > 4000:
                continue
            for rule in applicable:
                if not rule.pattern.search(masked_line):
                    continue
                # A proven flow at this line already says everything the pattern would, with a
                # trace attached. Emitting both is the same issue twice in the customer's queue.
                if (rule.cwe, lineno) in taint_lines:
                    continue
                original = original_lines[lineno - 1] if lineno <= len(original_lines) else ""
                yield _pattern_finding(rule, path, lineno, original.strip(), is_test)

    # ── semgrep ──────────────────────────────────────────────────────────────────────────────────
    def _run_semgrep_if_available(self, root: Path) -> Iterable[RawFinding]:
        """Best-effort wrap of semgrep when installed. No-op otherwise (keeps CI self-contained)."""
        if not shutil.which("semgrep"):
            return
        try:
            proc = subprocess.run(  # noqa: S603,S607 - fixed argv, no shell
                ["semgrep", "--config", "auto", "--json", "--quiet", str(root)],  # noqa: S607
                capture_output=True,
                timeout=600,
                check=False,
            )
            data = json.loads(proc.stdout or "{}")
        except (subprocess.SubprocessError, OSError, ValueError):
            return
        for res in data.get("results", []):
            extra = res.get("extra", {})
            start = res.get("start", {})
            rel = res.get("path", "")
            yield RawFinding(
                engine=EngineKey.SAST,
                title=extra.get("message", "Semgrep finding")[:300],
                category="insecure-code",
                description=extra.get("message", ""),
                base_severity=_semgrep_sev(extra.get("severity", "WARNING")),
                confidence="medium",
                location={"path": rel, "line": start.get("line"), "rule": res.get("check_id")},
                evidence=code_evidence(
                    path=rel,
                    line=start.get("line", 0),
                    redacted_excerpt=(extra.get("lines", "") or "")[:200],
                    rule=res.get("check_id"),
                ),
                references={"semgrep": res.get("check_id", "")},
            )


# ── finding construction ──────────────────────────────────────────────────────────────────────────
def _looks_like_test(path: str) -> bool:
    normalized = "/" + path.replace("\\", "/").lstrip("/")
    lowered = normalized.lower()
    name = lowered.rsplit("/", 1)[-1]
    return any(marker in lowered for marker in _TEST_MARKERS[:3]) or any(
        marker in name for marker in _TEST_MARKERS[3:]
    )


def _demote(severity: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order[max(0, order.index(severity) - 1)]


def _cwe_url(cwe: str) -> str:
    return f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html"


def _taint_finding(flow: TaintFinding, is_test: bool) -> RawFinding:
    severity = _demote(flow.severity) if is_test else flow.severity
    trace = [step.as_dict() for step in flow.trace]
    origin = {
        "request": "an HTTP request",
        "route-parameter": "a route handler parameter",
        "stdin": "standard input",
        "argv": "the command line",
        "parameter": "a function parameter",
    }.get(flow.source_kind, flow.source_kind)

    description = (
        f"{flow.sink.title}. Data from {origin} reaches this call in "
        f"{len(trace)} step(s) without being neutralized for {flow.sink.cwe}."
    )
    if flow.interprocedural:
        description += " The flow crosses a function boundary within this file."
    if flow.sink.remediation:
        description += f" {flow.sink.remediation}"

    evidence = code_evidence(
        path=flow.path, line=flow.line, redacted_excerpt=flow.code, rule=flow.sink.id
    )
    # The trace is the difference between a claim and a demonstration, so it travels with the
    # finding rather than being recomputed (or not) by whoever reads the report.
    evidence["detail"]["dataflow"] = trace
    evidence["detail"]["source"] = origin
    evidence["detail"]["analysis"] = "taint"

    return RawFinding(
        engine=EngineKey.SAST,
        title=flow.sink.title,
        category="injection",
        description=description,
        base_severity=severity,
        confidence=flow.confidence,
        cwe_id=flow.sink.cwe,
        owasp_ref=flow.sink.owasp,
        location={"path": flow.path, "line": flow.line, "rule": flow.sink.id},
        evidence=evidence,
        references={"cwe": _cwe_url(flow.sink.cwe)},
    )


def _pattern_finding(rule: Rule, path: str, lineno: int, line: str, is_test: bool) -> RawFinding:
    excerpt = line if len(line) <= 200 else line[:200] + "…"
    severity = _demote(rule.severity) if is_test else rule.severity
    description = f"{rule.title} detected. This pattern maps to {rule.cwe}."
    if rule.remediation:
        description += f" {rule.remediation}"
    if is_test:
        description += " Reported at reduced severity: the file looks like test code."

    evidence = code_evidence(path=path, line=lineno, redacted_excerpt=excerpt, rule=rule.id)
    evidence["detail"]["analysis"] = "pattern"

    return RawFinding(
        engine=EngineKey.SAST,
        title=rule.title,
        category="insecure-code",
        description=description,
        base_severity=severity,
        # A pattern match says the construct is present, not that it is reachable by an attacker.
        confidence="low" if is_test else "medium",
        cwe_id=rule.cwe,
        owasp_ref=rule.owasp,
        location={"path": path, "line": lineno, "rule": rule.id},
        evidence=evidence,
        references={"cwe": _cwe_url(rule.cwe)},
    )


def _semgrep_sev(sev: str) -> Severity:
    return {"ERROR": Severity.HIGH, "WARNING": Severity.MEDIUM, "INFO": Severity.LOW}.get(
        sev.upper(), Severity.MEDIUM
    )
