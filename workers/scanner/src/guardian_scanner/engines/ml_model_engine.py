"""ML-model supply-chain engine — malicious code hidden in serialized model files (Phase A).

A model file is not data. A PyTorch checkpoint, a pickled scikit-learn estimator, a Keras `.h5`,
a TensorFlow `SavedModel` — each can carry operators that run the moment the file is loaded, before
a single inference. `torch.load`, `pickle.load`, `joblib.load` and `keras.models.load_model` will
execute an embedded `os.system`, `exec`, or a crafted `__reduce__` the instant they open the file.
A team that downloads a "pretrained" model from a hub and loads it has already run whatever was in
it. This is the AI/ML supply-chain gap the other engines cannot see: SCA reads lockfiles, secrets
reads text, SAST reads source — none of them open a `.pkl` and ask what it will *do*.

This engine wraps **modelscan** (Protect AI, Apache-2.0, APPROVED) — a static scanner for unsafe
operators across the pickle/PyTorch/TensorFlow/Keras/ONNX formats. It is the FIRST engine whose tool
is its *only* detector: unlike SecretsEngine, IacEngine and ScaEngine — each a maintained tool
wrapped on top of a complete built-in detector — there is no hand-written ML-model scanner behind
this one. That difference is the whole reason `health()` reports **degraded** when modelscan is
absent: with no built-in baseline, a missing binary means the model files were not examined at all,
and `verification.engine_outcome` must turn that run's silence into INCONCLUSIVE, never RESOLVED. A
malicious model that was never scanned must never render to a customer as "no malicious models".

Passive and offline: it opens files on disk, loads nothing, executes nothing, needs no credentials
and no network — so it is safe to run on any untrusted artifact.
"""

from __future__ import annotations

import json
import shutil
import subprocess  # noqa: S404 - fixed argv, no shell, bounded
import tempfile
from collections.abc import Iterable
from pathlib import Path

from guardian_common.logging import get_logger
from guardian_core.enums import EngineKey, Severity
from guardian_core.findings import RawFinding

from guardian_scanner.engines.base import EngineHealth, ScanContext

log = get_logger("guardian.engine.ml_model")

# Bounded so a repository full of large checkpoints degrades rather than hangs.
_MODELSCAN_TIMEOUT = 600
_MODELSCAN_MAX_FINDINGS = 1_000
# modelscan grades each unsafe operator on its own LOW/MEDIUM/HIGH/CRITICAL scale. Loading a model
# is code execution regardless, so an unrecognized grade is treated as HIGH rather than downgraded.
_MODELSCAN_SEVERITY = {
    "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW,
}


class MlModelInputError(RuntimeError):
    """There was no workspace to read, so no model file was examined (readiness audit, Phase 4)."""


class MlModelEngine:
    """Detects unsafe operators in serialized ML models via modelscan. Implements ScanEngine."""

    key = EngineKey.ML_MODEL
    name = "Guardian ML Model Scanner (modelscan)"
    version = "1.0.0"
    requires_authorization = False  # passive: opens files on disk, loads/executes nothing

    def supports(self, asset_kind: str) -> bool:
        # Model artifacts live in a repository workspace. (Inline single-file text scans carry no
        # binary model, so there is nothing for this engine to do there.)
        return asset_kind in {"repo"}

    def health(self) -> EngineHealth:
        # Unlike the tool-augmented engines, modelscan is the ONLY detector here — there is no
        # built-in fallback. So its absence is genuine degradation, not reduced coverage on top of
        # a working baseline: without it, model files are not scanned at all. Reporting `degraded`
        # is precisely what stops an empty result being read as "no malicious models" —
        # engine_outcome turns a degraded run's silence into INCONCLUSIVE, never RESOLVED.
        if shutil.which("modelscan"):
            return EngineHealth(ok=True, detail="modelscan present")
        return EngineHealth(
            ok=True,          # the engine still runs; it simply finds nothing without its tool
            degraded=True,
            missing=("modelscan",),
            detail="modelscan absent — ML model files were NOT scanned",
        )

    def run(self, ctx: ScanContext) -> Iterable[RawFinding]:
        if ctx.inline_content is not None:
            # A model is a binary artifact; there is no model in an inline text snippet.
            return
        if not ctx.workspace_path:
            # A silent empty return would complete cleanly, and WP-E2 reads a clean completion as
            # permission to resolve this engine's existing findings — so a misconfigured asset
            # would quietly close every ML-model finding it ever had.
            raise MlModelInputError(
                "no workspace to read, so no model file was examined. An absence of input is not "
                "an absence of a malicious model."
            )
        root = Path(ctx.workspace_path)
        if not root.exists():
            raise MlModelInputError(
                f"the workspace path {ctx.workspace_path!r} does not exist, so no model was "
                "examined"
            )
        yield from self._run_modelscan_if_available(root)

    def _run_modelscan_if_available(self, root: Path) -> Iterable[RawFinding]:
        """Run modelscan when installed. No-op otherwise — but `health()` has already reported the
        engine degraded, so an empty result from an absent tool is INCONCLUSIVE, not clean."""
        exe = shutil.which("modelscan")
        if not exe:
            return
        with tempfile.NamedTemporaryFile("r+", suffix=".json", delete=True) as report:
            argv = [exe, "-p", str(root), "-r", "json", "-o", report.name]
            try:
                subprocess.run(  # noqa: S603 - fixed argv, no shell, bounded
                    argv, capture_output=True, timeout=_MODELSCAN_TIMEOUT, check=False)
                report.seek(0)
                data = json.loads(report.read() or "{}")
            except (subprocess.SubprocessError, OSError, ValueError) as exc:
                # modelscan is installed but did not answer. There is no built-in fallback here, so
                # this run scanned nothing — it must not be silent: an empty result from a crashed
                # scanner looks exactly like a repository with no malicious models.
                log.warning("ml_model_modelscan_failed", error=f"{type(exc).__name__}: {exc}"[:200])
                return
        if not isinstance(data, dict):
            log.warning("ml_model_modelscan_unexpected_output", kind=type(data).__name__)
            return
        errors = data.get("errors") or []
        if errors:
            # A file modelscan errored on was NOT cleared. Record that some artifacts could not be
            # read so a partial scan is not mistaken for a clean one.
            log.warning("ml_model_modelscan_errors", count=len(errors) if isinstance(errors, list)
                        else 1)
        issues = data.get("issues") or []
        if not isinstance(issues, list):
            return
        seen: set[tuple[str, str, str, str]] = set()
        for item in issues[:_MODELSCAN_MAX_FINDINGS]:
            finding = self._modelscan_finding(item)
            if finding is None:
                continue
            loc = finding.location
            dedup = (str(loc.get("path", "")), str(loc.get("module", "")),
                     str(loc.get("operator", "")), str(loc.get("scanner", "")))
            if dedup in seen:
                continue
            seen.add(dedup)
            yield finding

    def _modelscan_finding(self, item: object) -> RawFinding | None:
        if not isinstance(item, dict):
            return None
        source = str(item.get("source") or "").strip()
        operator = str(item.get("operator") or "").strip()
        module = str(item.get("module") or "").strip()
        # A finding with neither a file nor an operator names nothing actionable.
        if not source or not (operator or module):
            return None
        scanner = str(item.get("scanner") or "").strip()
        sev = _MODELSCAN_SEVERITY.get(str(item.get("severity") or "").upper(), Severity.HIGH)
        call = ".".join(p for p in (module, operator) if p) or "an unsafe operator"
        detail = str(item.get("description") or f"Use of unsafe operator {call}").strip()[:300]
        description = (
            f"{detail}. This ML model file references {call}, which executes when the model is "
            "loaded (torch.load / pickle.load / joblib.load / keras load_model) — before any "
            "inference runs. Treat the file as untrusted code: do not load it, verify its "
            "provenance, and re-obtain the model from a trusted source."
        )
        return RawFinding(
            engine=EngineKey.ML_MODEL,
            title=f"Malicious/unsafe ML model operator: {call}"[:300],
            category="ml-model-malware",
            description=description,
            base_severity=sev,
            confidence="high",   # modelscan names a concrete operator, not a heuristic guess
            cwe_id="CWE-502",    # Deserialization of Untrusted Data
            location={"path": source, "operator": operator, "module": module, "scanner": scanner},
            evidence={
                "detector": "modelscan",
                "scanner": scanner,
                "operator": operator,
                "module": module,
                "file": source,
                "summary": detail,
            },
            references={
                "cwe": "https://cwe.mitre.org/data/definitions/502.html",
                "modelscan": f"https://github.com/protectai/modelscan ({scanner})"
                if scanner else "https://github.com/protectai/modelscan",
            },
        )
