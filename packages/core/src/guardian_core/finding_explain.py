"""Plain-language security results — the single source of truth for what a finding means.

Turns a finding's technical identity (CWE, category, evidence) into three sentences a non-expert
can act on: what this means, why it matters, what to do. It is used everywhere a person reads a
finding — the console dossier (via the API), the PDF/HTML report, and the remediation ticket — so
the same finding always carries the same explanation, with no drift between screen and artefact.

It invents no fact about the specific finding: the specifics (endpoint, file, component) come from
the finding's own evidence. The wording is deterministic and keyed by CWE, then category, then the
finding's own description, then severity — never by an LLM, so a report reads the same every time.

The frontend keeps a byte-identical copy (`findingExplain.ts`) only as a fallback for older API
responses; in production the console renders this module's output, delivered in the finding dossier.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass(frozen=True)
class Explanation:
    what_it_means: str
    why_it_matters: str
    what_to_do: str
    where: str = ""

    def to_dict(self) -> dict:
        return {"what_it_means": self.what_it_means, "why_it_matters": self.why_it_matters,
                "what_to_do": self.what_to_do, "where": self.where}


# Keyed by CWE id. Concise, plain, specific to the weakness — not the individual finding.
_CWE: dict[str, tuple[str, str, str]] = {
    "CWE-306": (
        "Something that should require sign-in can be reached without any credentials.",
        "Anyone on the internet could use functionality that was meant to be protected.",
        "Require authentication on this route and confirm the check is enforced on the server, not "
        "just hidden in the interface."),
    "CWE-862": (
        "An action is missing an authorization check.",
        "A signed-in user could do something they should not be allowed to do.",
        "Check the user's permission in the handler before performing the action."),
    "CWE-285": (
        "An administrative or privileged action answered a user who should not have access.",
        "A normal user may be able to perform admin-level operations.",
        "Verify the caller's role inside the handler. Route-level separation is not enough."),
    "CWE-639": (
        "One user could read or change another user's records by changing an identifier.",
        "Private data belonging to other customers may be exposed or altered.",
        "Check that the signed-in user owns or is entitled to the specific record before returning "
        "or modifying it."),
    "CWE-798": (
        "A password, key or token is written directly into the code or app package.",
        "Anyone who can read the code or unpack the app gets a working credential.",
        "Remove the secret, rotate it immediately, and load it from a secret manager or the device "
        "keystore at runtime."),
    "CWE-319": (
        "Information travels over an unencrypted connection (plain HTTP).",
        "Anyone on the network path can read or tamper with the traffic, including credentials.",
        "Use HTTPS/TLS everywhere and disable the plaintext option."),
    "CWE-89": (
        "User input reaches a database query without being safely separated from the query.",
        "An attacker could read, change or delete data in your database.",
        "Use parameterized queries (prepared statements); never build SQL by concatenating input."),
    "CWE-79": (
        "User input is placed into a web page without being neutralised.",
        "An attacker could run scripts in other users' browsers to steal sessions or data.",
        "Escape output for its context and add a Content-Security-Policy."),
    "CWE-94": (
        "Untrusted input can influence code that the system then executes.",
        "An attacker may be able to run their own commands or code.",
        "Never pass untrusted input into an interpreter; validate and use safe APIs."),
    "CWE-213": (
        "A response returns more fields than a client needs, including sensitive ones.",
        "Data such as credentials or personal fields may leak to anyone who calls the API.",
        "Return an explicit allowlist of fields and never serialize the whole record."),
    "CWE-770": (
        "There is no limit on how much a caller can request or how often.",
        "The service can be overwhelmed, or large data sets scraped, by a single caller.",
        "Add pagination with a bounded default and enforce rate limits."),
    "CWE-522": (
        "Credentials are protected weakly (for example reversible or easily guessed).",
        "Credentials could be recovered or reused by an attacker.",
        "Use short-lived bearer tokens over TLS and rotate credentials regularly."),
    "CWE-598": (
        "A secret (like an API key) is sent in the URL.",
        "URLs are logged by servers, proxies and browser history, so the key leaks.",
        "Send secrets in a header (or Authorization), never in the query string."),
    "CWE-1220": (
        "Authentication is described in the contract but never actually applied.",
        "The API appears protected but may be running open.",
        "Apply the security requirement globally or per operation, and test it."),
    "CWE-295": (
        "TLS certificate or hostname validation is disabled or bypassed.",
        "An attacker in the middle could impersonate the server and read traffic.",
        "Validate certificates and hostnames properly; never trust all certificates."),
    "CWE-327": (
        "A weak or broken cryptographic algorithm is in use.",
        "Data protected with it can be decrypted or forged more easily than expected.",
        "Use a modern algorithm (for example AES-GCM) and current key sizes."),
    "CWE-328": (
        "A weak hash function (such as MD5 or SHA-1) is used for security.",
        "Values can be forged or collisions found, undermining integrity checks.",
        "Use SHA-256 or stronger for security-relevant hashing."),
    "CWE-489": (
        "The build is a debug/development build, not a hardened release build.",
        "A debugger can attach and read memory, data and secrets from the running app.",
        "Ship a release build with debugging disabled."),
    "CWE-530": (
        "The app allows its data to be backed up and extracted.",
        "App data can be pulled off the device and inspected.",
        "Disable backup for sensitive apps, or exclude sensitive data from backups."),
    "CWE-926": (
        "An app component is exposed so other apps on the device can invoke it.",
        "Another app could reach functionality or data that should be private.",
        "Set the component to not-exported, or require a signature-level permission."),
    "CWE-250": (
        "Something runs with more privilege than it needs.",
        "If it is compromised, the attacker inherits that extra power.",
        "Apply least privilege: grant only the specific rights required."),
    "CWE-284": (
        "Access to a resource or interface is not properly restricted.",
        "Unauthorized users or devices may reach something they should not.",
        "Restrict access to trusted networks/users and disable what is not needed."),
    "CWE-1104": (
        "Software that no longer receives security updates is in use (end-of-life).",
        "New vulnerabilities in it will never be patched.",
        "Upgrade to a supported version."),
    "CWE-262": (
        "Password-based sign-in is allowed where it should be restricted.",
        "It exposes the service to password guessing.",
        "Prefer key-based authentication and disable password login."),
    "CWE-693": (
        "A protective control (such as a security header) is missing.",
        "An attack that the control would have blocked can now succeed.",
        "Add the missing control (for example a Content-Security-Policy header)."),
    "CWE-359": (
        "The app handles sensitive personal information.",
        "It carries privacy and compliance obligations if mishandled.",
        "Confirm each use is necessary, disclosed, and the data is protected at rest and in "
        "transit."),
    "CWE-703": (
        "An error or unexpected condition is not handled clearly.",
        "It can leak internal details or leave the system in an unexpected state.",
        "Handle the case explicitly and document the expected responses."),
    "CWE-477": (
        "A deprecated component or API is in use.",
        "It no longer receives fixes and may carry known weaknesses.",
        "Migrate to the supported replacement."),
    "CWE-200": (
        "The system exposes information that should be kept internal.",
        "It hands an attacker details that make other attacks easier.",
        "Remove the exposure and restrict who can reach it."),
    "CWE-939": (
        "A custom URL scheme can trigger app actions from outside.",
        "Another app could invoke it with crafted input as an unauthenticated entry point.",
        "Validate all incoming parameters and prefer verified links for sensitive actions."),
    "CWE-1059": (
        "A documentation or inventory expectation is not met.",
        "Gaps make the system harder to secure and audit reliably.",
        "Bring the documentation or inventory in line with what is actually running."),
    "CWE-538": (
        "A file that should be private is readable over the web.",
        "It may reveal credentials, source, or configuration.",
        "Remove the file from the web root and rotate anything it exposed."),
    "CWE-1357": (
        "A dependency is used without pinning it to a known-good version.",
        "A malicious or broken update could be pulled in automatically.",
        "Pin dependencies to a specific, reviewed version or digest."),
}

_CATEGORY: dict[str, tuple[str, str, str]] = {
    "vuln-dep": (
        "A third-party dependency has a known vulnerability.",
        "The known weakness is present in your software through this package.",
        "Upgrade the package to a fixed version, or remove it if unused."),
    "secret": (
        "A credential appears to be committed into the code or package.",
        "Anyone who can read it gains a working credential.",
        "Rotate the credential now and move it out of the code into a secret store."),
    "api-authorization": (
        "An authorization check is missing or not enforced on this API.",
        "A user may reach data or actions they should not.",
        "Enforce ownership and role checks on the server for every request."),
    "api-inventory": (
        "An endpoint exists that is not in the documented API.",
        "Undocumented endpoints are the ones defenders forget and attackers find.",
        "Confirm it is intended, document it, or remove it."),
}

_SEVERITY_MATTERS = {
    "critical": "This is critical: it is likely exploitable and high-impact, and should be fixed "
                "first.",
    "high": "This is high severity: it presents a serious risk and should be prioritised.",
    "medium": "This is medium severity: worth fixing in the normal course of work.",
    "low": "This is low severity: a smaller risk, but still worth addressing.",
    "info": "This is informational: not a vulnerability by itself, but useful to know.",
}


def _attr(finding: object, name: str, default: str = "") -> str:
    value = getattr(finding, name, None)
    if value is None and isinstance(finding, dict):
        value = finding.get(name)
    return str(value) if value is not None else default


def _evidence(finding: object) -> dict:
    e = getattr(finding, "evidence", None)
    if e is None and isinstance(finding, dict):
        e = finding.get("evidence")
    return e if isinstance(e, dict) else {}


def _first_sentences(text: str, max_sentences: int = 2) -> str:
    parts = re.split(r"(?<=[.!?])\s+", re.sub(r"\s+", " ", text).strip())
    return " ".join(parts[:max_sentences])


def _where(finding: object) -> str:
    e = _evidence(finding)

    def s(key: str) -> str:
        v = e.get(key)
        return str(v) if isinstance(v, (str, int)) and str(v) else ""

    endpoint = s("endpoint") or s("url")
    if endpoint:
        return f"Endpoint {endpoint}"
    file = s("file") or s("path")
    if file:
        line = s("line")
        return f"File {file}:{line}" if line else f"File {file}"
    host = s("host") or s("gateway")
    if host:
        port = s("port")
        return f"Host {host}:{port}" if port else f"Host {host}"
    pkg = s("package") or s("component")
    if pkg:
        version = s("version")
        return f"Component {pkg}@{version}" if version else f"Component {pkg}"
    return ""


def explain_finding(finding: object) -> Explanation:
    """Plain-language explanation for a finding (ORM object or dict). Deterministic and offline."""
    cwe_id = _attr(finding, "cwe_id") or None
    category = _attr(finding, "category") or None
    severity = _attr(finding, "severity", "medium").lower()
    title = _attr(finding, "title")
    desc = _attr(finding, "description")

    cwe = _CWE.get(cwe_id) if cwe_id else None
    cat = _CATEGORY.get(category) if category else None

    rem_match = re.search(r"remediation:", desc, re.IGNORECASE)
    if rem_match:
        desc_body = desc[:rem_match.start()].strip()
        desc_remediation = desc[rem_match.end():].strip()
    else:
        desc_body, desc_remediation = desc.strip(), ""

    what_it_means = (cwe[0] if cwe else cat[0] if cat
                     else (_first_sentences(desc_body) if desc_body
                           else f"{title}. See the technical details below."))
    why_it_matters = (cwe[1] if cwe else cat[1] if cat
                      else _SEVERITY_MATTERS.get(severity, _SEVERITY_MATTERS["medium"]))
    what_to_do = (cwe[2] if cwe else cat[2] if cat else desc_remediation
                  or "Review the technical details and evidence below, then apply the fix "
                     "appropriate to your environment.")

    return Explanation(what_it_means=what_it_means, why_it_matters=why_it_matters,
                       what_to_do=what_to_do, where=_where(finding))
