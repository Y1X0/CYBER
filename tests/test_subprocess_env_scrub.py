"""Execution subprocess environment scrubbing (P1-α) — no secret reaches a spawned external binary.

The tool plane holds GUARDIAN_BROKER_SEAL_KEY (P1-A). A spawned binary (nmap/nmap_service) previously
inherited the worker's full environment, so a compromised binary could read the seal key (and any
other GUARDIAN_* secret) from /proc/self/environ. run_nmap now passes an explicit allowlist env; these
tests prove the child gets ONLY PATH + locale, never a secret, while nmap still resolves and runs.
"""

from __future__ import annotations

import sys

from guardian_scanner.tools.nmap_runner import _CHILD_ENV_ALLOWLIST, _child_env, run_nmap

_SECRETS = {
    "GUARDIAN_BROKER_SEAL_KEY": "seal-secret-value",
    "GUARDIAN_JWT_SECRET": "jwt-secret-value",
    "GUARDIAN_ENCRYPTION_KEY": "kms-master-value",
    "GUARDIAN_REDIS_URL": "rediss://user:pw@redis:6379/0",
    "GUARDIAN_DATABASE_URL": "postgresql+psycopg://guardian:pw@db:5432/guardian",
    "GUARDIAN_JOB_SIGNING_PRIVATE_KEY": "cHJpdmF0ZQ==",
}


# ── the allowlist ────────────────────────────────────────────────────────────────────────────────
def test_child_env_excludes_all_secrets(monkeypatch):
    for k, v in _SECRETS.items():
        monkeypatch.setenv(k, v)
    monkeypatch.setenv("PATH", "/usr/sbin:/usr/bin:/bin")
    env = _child_env()
    for k in _SECRETS:
        assert k not in env                       # no secret var carried
    assert not any(k.startswith("GUARDIAN_") for k in env)   # no GUARDIAN_* at all
    assert env["PATH"] == "/usr/sbin:/usr/bin:/bin"          # PATH preserved so the binary resolves


def test_child_env_passes_locale_and_defaults_path(monkeypatch):
    for k in (*_SECRETS, "PATH", "LANG", "LC_ALL", "LC_CTYPE", "TZ"):
        monkeypatch.delenv(k, raising=False)
    monkeypatch.setenv("LANG", "C.UTF-8")
    env = _child_env()
    assert env["LANG"] == "C.UTF-8"               # locale passed through
    assert env["PATH"]                            # never empty even if unset in the parent
    assert set(env) <= set(_CHILD_ENV_ALLOWLIST)  # nothing beyond the allowlist


# ── the REAL spawned process: prove /proc/self/environ carries no secret ─────────────────────────
def test_real_subprocess_environment_has_no_secrets(monkeypatch):
    for k, v in _SECRETS.items():
        monkeypatch.setenv(k, v)
    # A stand-in "binary" that dumps its own environment to stdout (what run_nmap captures as xml).
    dump = "import os,sys; sys.stdout.write('\\n'.join(f'{k}={v}' for k,v in os.environ.items()))"
    res = run_nmap([sys.executable, "-c", dump], wall_seconds=15)
    assert res.status == "ok", res
    out = res.xml.decode()

    for k, v in _SECRETS.items():
        assert k not in out and v not in out      # neither the name nor the VALUE leaked
    assert "GUARDIAN_" not in out                 # no GUARDIAN_* variable at all
    assert "PATH=" in out                         # the binary still gets a usable PATH


def test_scrub_does_not_break_binary_execution():
    # A trivial binary still runs and returns output under the scrubbed env (nmap functionality proxy).
    res = run_nmap([sys.executable, "-c", "print('<nmaprun/>')"], wall_seconds=15)
    assert res.status == "ok" and b"<nmaprun/>" in res.xml
