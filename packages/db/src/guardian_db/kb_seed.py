"""Offline knowledge-base seed: CWE weaknesses, sample advisories, and defensive KB entries.

This is the platform's *learning surface*. The analyst does not fine-tune on stored data — the model
is frozen — so "the platform gets smarter" means one concrete thing: this knowledge base grows, and
`guardian_ai.rag.retriever.retrieve_for_finding` pulls the matching entries in as grounding every
time the AI explains a finding. A richer KB → more accurate, better-grounded explanations, and a
shared vocabulary the detection engines and the analyst both reason over.

Two hard rules keep this an asset and not a liability:
  * **Knowledge, never weapons.** Entries describe how a weakness class works, how Guardian detects
    it, its impact, and how to remediate it — defensively. No working exploit payloads, no
    step-by-step attack recipes. Storing weaponized code would make this very table a liability if
    it ever leaked, and it does not improve detection anyway.
  * **Grounded and mapped.** Every entry carries its standards (CWE / OWASP) and tags (the finding
    `category` it grounds), because that is exactly what the retriever matches on.

Production augments this via the feed-sync task (NVD / OSV / GHSA / EPSS / KEV); this seed is what
makes the analyst useful offline, in CI, and on a fresh deploy before any feed has run.
"""

from __future__ import annotations

from sqlalchemy.orm import Session

from guardian_db.models import KbEntry, Vulnerability, Weakness

# CWE weaknesses the built-in engines and the new (CI/CD, ML-model) engines emit. (id, name,
# description) — the description is surfaced to the analyst as the authoritative definition of the
# weakness, so it stays factual and standards-aligned.
_CWE_SEED = [
    ("CWE-79", "Improper Neutralization of Input During Web Page Generation (XSS)",
     "Untrusted input is placed into web output without neutralization, so a browser executes it "
     "as script in another user's session."),
    ("CWE-89", "SQL Injection",
     "Untrusted input is used to build a SQL command without parameterization, letting an attacker "
     "change the query's meaning."),
    ("CWE-78", "OS Command Injection",
     "Untrusted input reaches an operating-system shell command, allowing arbitrary command "
     "execution on the host."),
    ("CWE-94", "Improper Control of Generation of Code (Code Injection)",
     "Untrusted input is incorporated into code that is then executed — in an application, a "
     "template, or a CI/CD workflow step."),
    ("CWE-95", "Eval Injection",
     "Untrusted input is passed to a dynamic evaluation primitive (eval/exec), executing "
     "attacker-controlled code."),
    ("CWE-22", "Improper Limitation of a Pathname to a Restricted Directory (Path Traversal)",
     "Untrusted input builds a file path without containment, letting an attacker read or write "
     "files outside the intended directory."),
    ("CWE-918", "Server-Side Request Forgery (SSRF)",
     "The server can be induced to make requests to an attacker-chosen destination, reaching "
     "internal services and cloud metadata endpoints."),
    ("CWE-611", "Improper Restriction of XML External Entity Reference (XXE)",
     "An XML parser resolves external entities, enabling file disclosure and SSRF."),
    ("CWE-327", "Use of a Broken or Risky Cryptographic Algorithm",
     "A weak or outdated algorithm/mode is used, so confidentiality or integrity guarantees do not "
     "hold in practice."),
    ("CWE-295", "Improper Certificate Validation",
     "TLS certificate validation is disabled or incomplete, allowing a man-in-the-middle to "
     "impersonate the endpoint."),
    ("CWE-502", "Deserialization of Untrusted Data",
     "Untrusted serialized data (a pickle, a model file, a Java object) is deserialized, which can "
     "execute code on load."),
    ("CWE-798", "Use of Hard-coded Credentials",
     "A credential sits in source or configuration, where anyone who can read the repository "
     "or its history can use it."),
    ("CWE-1357", "Reliance on Insufficiently Trustworthy Component",
     "A dependency (e.g. a CI/CD action pinned to a mutable tag) can be changed under you, running "
     "new code with your privileges."),
    ("CWE-269", "Improper Privilege Management",
     "A principal is granted more privilege than it needs, widening the blast radius of any "
     "compromise."),
    ("CWE-272", "Least Privilege Violation",
     "A process or token holds broad permissions it does not require, e.g. a write-all CI token."),
    ("CWE-494", "Download of Code Without Integrity Check",
     "Code is fetched and executed without verifying its integrity, trusting whoever controls the "
     "source or the network path."),
    ("CWE-668", "Exposure of Resource to Wrong Sphere",
     "A resource is reachable from a sphere that should not have access, such as a self-hosted "
     "runner reachable from a public trigger."),
    ("CWE-284", "Improper Access Control",
     "Access to a resource is not correctly restricted, letting an actor act outside intended "
     "permissions."),
    ("CWE-306", "Missing Authentication for Critical Function",
     "A sensitive function can be reached without authenticating, so anyone who can reach it can "
     "invoke it."),
]

# Sample advisories with affected package ranges (ecosystem lowercased to match the SCA engine).
_VULN_SEED = [
    {
        "external_id": "CVE-2020-14343",
        "source": "osv",
        "summary": "PyYAML full_load / FullLoader arbitrary code execution via crafted YAML.",
        "cwe_ids": ["CWE-502"],
        "cvss_base": 9.8,
        "epss_score": 0.42,
        "kev": False,
        "affected": [{"ecosystem": "pypi", "package": "pyyaml", "versions": ["5.3", "5.3.1"]}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2020-14343"],
    },
    {
        "external_id": "CVE-2019-11324",
        "source": "osv",
        "summary": "urllib3 certificate validation weakness with conflicting configurations.",
        "cwe_ids": ["CWE-295"],
        "cvss_base": 7.5,
        "epss_score": 0.15,
        "kev": False,
        "affected": [{"ecosystem": "pypi", "package": "urllib3", "versions": ["1.24"]}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2019-11324"],
    },
    {
        "external_id": "CVE-2021-23337",
        "source": "osv",
        "summary": "lodash command injection via template.",
        "cwe_ids": ["CWE-78"],
        "cvss_base": 7.2,
        "epss_score": 0.08,
        "kev": True,
        "affected": [{"ecosystem": "npm", "package": "lodash", "versions": ["4.17.20"]}],
        "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-23337"],
    },
]


def _kb(kind, title, body, *, cwe=None, owasp=None, tags):  # noqa: ANN001
    standards: dict = {}
    if cwe:
        standards["cwe"] = cwe
    if owasp:
        standards["owasp"] = owasp
    return {"kind": kind, "title": title, "body": body, "standards": standards, "tags": tags}


# Defensive knowledge entries. Each is written to be RETRIEVED for a finding — its `standards.cwe`
# and `tags` (the finding category) are what the retriever matches on. Bodies are detection +
# impact + remediation, never exploit payloads.
_KB_SEED = [
    _kb("weakness", "SQL injection: detection and remediation",
        "Guardian flags SQL built by concatenating or formatting untrusted input into a query "
        "string. Impact: an attacker can read or modify data the query's account can reach, and "
        "often bypass authentication. Remediation: use parameterized queries / prepared statements "
        "or an ORM's bound parameters; never build SQL by string concatenation; apply least "
        "privilege to the database account.",
        cwe="CWE-89", owasp="A03:2021", tags=["injection", "insecure-code"]),
    _kb("weakness", "Cross-site scripting (XSS): detection and remediation",
        "Guardian flags untrusted input reflected or stored into HTML/JS without contextual output "
        "encoding. Impact: script runs in a victim's browser session — session theft, credential "
        "capture, actions as the victim. Remediation: contextual output encoding, a strict Content "
        "Security Policy, framework auto-escaping, and treating all user input as untrusted.",
        cwe="CWE-79", owasp="A03:2021", tags=["injection", "insecure-code"]),
    _kb("weakness", "OS command injection: detection and remediation",
        "Guardian flags untrusted input reaching a shell command. Impact: arbitrary command "
        "execution with the process's privileges. Remediation: avoid the shell entirely — pass "
        "arguments as an argv list to the exec API, validate against an allow-list, and never "
        "interpolate input into a shell string.",
        cwe="CWE-78", owasp="A03:2021", tags=["injection", "insecure-code"]),
    _kb("weakness", "Code and eval injection: detection and remediation",
        "Guardian flags untrusted input put into dynamically evaluated code (eval/exec) or "
        "generated code. Impact: full code execution in the process. Remediation: remove dynamic "
        "evaluation of input; use safe parsers and data-only formats; if unavoidable, "
        "sandbox it and restrict the callable surface.",
        cwe="CWE-94", owasp="A03:2021", tags=["injection", "insecure-code"]),
    _kb("weakness", "Path traversal: detection and remediation",
        "Guardian flags untrusted input used to build a filesystem path. Impact: read or write of "
        "files outside the intended directory (config, secrets, source). Remediation: resolve the "
        "path and verify it stays inside the allowed base dir; reject '..' and absolute paths; "
        "prefer opaque identifiers mapped server-side to real paths.",
        cwe="CWE-22", tags=["injection", "insecure-code"]),
    _kb("weakness", "Server-side request forgery (SSRF): detection and remediation",
        "Guardian flags server-side requests whose destination is influenced by untrusted input. "
        "Impact: reach internal services and cloud metadata endpoints (credential theft in cloud "
        "environments). Remediation: allow-list destinations, block link-local/metadata ranges, "
        "disable unused URL schemes and redirects, and isolate egress.",
        cwe="CWE-918", owasp="A10:2021", tags=["injection", "api-authorization"]),
    _kb("weakness", "XML external entity (XXE): detection and remediation",
        "Guardian flags XML parsing that resolves external entities. Impact: local file disclosure "
        "and SSRF from crafted XML. Remediation: disable external entity and DTD processing in the "
        "XML parser (the secure default in most modern libraries).",
        cwe="CWE-611", tags=["injection", "insecure-code"]),
    _kb("weakness", "Insecure deserialization: detection and remediation",
        "Guardian flags deserialization of untrusted data (pickle, marshalled objects, unsafe "
        "YAML). Impact: code execution the moment the data is loaded. Remediation: do not "
        "deserialize untrusted input with code-capable formats; use data-only formats (JSON) with "
        "schema validation; if unavoidable, verify integrity/signatures before loading.",
        cwe="CWE-502", tags=["insecure-code", "vuln-dep"]),
    _kb("weakness", "Malicious machine-learning model files: detection and remediation",
        "Guardian's ML-model engine (modelscan) flags unsafe operators in serialized models "
        "(pickle / PyTorch / TensorFlow / Keras / ONNX). Impact: loading the model with "
        "torch.load / pickle.load / joblib.load executes embedded code before any inference. "
        "Remediation: treat model files as untrusted code — verify provenance, obtain models from "
        "trusted registries, and prefer non-executable formats such as Safetensors or ONNX.",
        cwe="CWE-502", tags=["ml-model-malware"]),
    _kb("remediation", "Remediating hardcoded secrets",
        "Move secrets to a secrets manager, rotate exposed credentials, and add pre-commit secret "
        "scanning. A secret committed even once must be rotated: it remains in the git history and "
        "is retrievable by anyone who can clone, so deleting the file is not sufficient.",
        cwe="CWE-798", owasp="A07:2021", tags=["secret", "secrets", "credentials"]),
    _kb("weakness", "Vulnerable and outdated dependencies: detection and remediation",
        "Guardian's SCA engines (built-in plus osv-scanner) match declared dependencies against "
        "known-vulnerability feeds. Impact: a known CVE in a dependency is exploitable in your "
        "product. Remediation: upgrade to a fixed version, prioritise by exploitability (KEV/EPSS) "
        "and reachability, and keep a maintained SBOM.",
        owasp="A06:2021", tags=["vuln-dep"]),
    _kb("weakness", "CI/CD script injection: detection and remediation",
        "Guardian's CI/CD engine flags a workflow `run:` step that interpolates an "
        "attacker-controllable context (a pull-request title, an issue body, a branch name) "
        "directly into a shell script. Impact: command execution in the pipeline, with its tokens "
        "and secrets. Remediation: pass the value through an intermediate environment variable and "
        "reference it as a quoted \"$VAR\" instead of expanding it inside the script.",
        cwe="CWE-94", tags=["cicd-injection"]),
    _kb("weakness", "CI/CD supply chain — unpinned actions and poisoned pipelines",
        "Guardian flags third-party CI/CD actions pinned to a mutable tag/branch rather than a "
        "commit SHA, and pull_request_target workflows that check out untrusted PR code. Impact: "
        "whoever controls the action or the fork can run code with your pipeline's privileges (the "
        "tj-actions/changed-files pattern). Remediation: pin actions to a commit SHA, and never "
        "build untrusted PR code in a job that holds secrets or write permissions.",
        cwe="CWE-1357", tags=["cicd-supply-chain"]),
    _kb("remediation", "Least-privilege CI/CD tokens",
        "Guardian flags a workflow token granted write-all permissions. Impact: any compromised "
        "step can push code, publish packages, and alter releases. Remediation: grant only the "
        "specific permissions each job needs and default the rest to read or none.",
        cwe="CWE-272", tags=["cicd-permissions"]),
    _kb("weakness", "Broken access control and authorization: detection and remediation",
        "Guardian flags missing or inconsistent authorization on sensitive functions and objects. "
        "Impact: users act outside their intended permissions — read others' data, escalate, or "
        "invoke admin functions. Remediation: enforce authorization server-side on every request, "
        "deny by default, and check object ownership, not just authentication.",
        cwe="CWE-284", owasp="A01:2021", tags=["api-authorization"]),
    _kb("weakness", "Weak cryptography and certificate validation",
        "Guardian flags broken/risky algorithms and disabled TLS certificate validation. Impact: "
        "confidentiality and integrity guarantees do not hold; a man-in-the-middle can read or "
        "alter traffic. Remediation: use current algorithms and modes, keep certificate validation "
        "enabled, and never set verify=False / rejectUnauthorized:false in production.",
        cwe="CWE-327", tags=["insecure-code"]),
    _kb("remediation", "Infrastructure-as-code and cloud misconfiguration",
        "Guardian's IaC, CSPM, Kubernetes and container engines flag insecure declarations and "
        "settings (public storage, open security groups, privileged pods, unencrypted data). "
        "Impact: exposure or weakened isolation, often before anything is even attacked. "
        "Remediation: fix the declaration at the source (Terraform/manifest), enforce encryption "
        "and least privilege, and re-scan to confirm the drift is closed.",
        tags=["iac-misconfig", "cloud-misconfig", "k8s-misconfig", "container-misconfig",
              "web-misconfig"]),
]


def seed_knowledge_base(session: Session) -> dict[str, int]:
    """Idempotently load the offline KB. Returns counts of newly inserted rows."""
    counts = {"weaknesses": 0, "vulnerabilities": 0, "kb_entries": 0}

    for ext_id, name, description in _CWE_SEED:
        existing = session.query(Weakness).filter(Weakness.external_id == ext_id).first()
        if existing is None:
            session.add(Weakness(external_id=ext_id, name=name, description=description))
            counts["weaknesses"] += 1
        elif description and not existing.description:
            # Backfill a description onto a row seeded before this entry carried one, so the analyst
            # gets the grounding without a manual migration.
            existing.description = description

    for v in _VULN_SEED:
        if (
            not session.query(Vulnerability)
            .filter(Vulnerability.external_id == v["external_id"])
            .first()
        ):
            session.add(Vulnerability(**v))
            counts["vulnerabilities"] += 1

    for k in _KB_SEED:
        if not session.query(KbEntry).filter(KbEntry.title == k["title"]).first():
            session.add(KbEntry(**k))
            counts["kb_entries"] += 1

    return counts
