// Plain-language security results.
//
// Turns a finding's technical identity (CWE, category, evidence) into three sentences a non-expert
// can act on: what this means, why it matters, what to do. Purely presentational and frontend-only —
// it never changes what the backend found, only how it is explained. The technical facts stay on the
// page for the advanced reader; this is the layer above them.
//
// Sources, in order of preference: a curated map keyed by CWE (the weaknesses the engines actually
// emit); then the finding's own description and any "Remediation:" it carries; then a sensible
// generic explanation derived from the category and severity. Nothing here invents a fact about the
// specific finding — the specifics (endpoint, file, evidence) come from the finding itself.

import { Finding } from "./api";

export interface Explanation {
  whatItMeans: string;
  whyItMatters: string;
  whatToDo: string;
  where: string;        // a human "Location" line, composed (never a bare duplicate of evidence)
}

interface CweText { means: string; matters: string; todo: string; }

// Keyed by CWE id. Concise, plain, and specific to the weakness — not the individual finding.
const CWE: Record<string, CweText> = {
  "CWE-306": {
    means: "Something that should require sign-in can be reached without any credentials.",
    matters: "Anyone on the internet could use functionality that was meant to be protected.",
    todo: "Require authentication on this route and confirm the check is enforced on the server, "
      + "not just hidden in the interface.",
  },
  "CWE-862": {
    means: "An action is missing an authorization check.",
    matters: "A signed-in user could do something they should not be allowed to do.",
    todo: "Check the user's permission in the handler before performing the action.",
  },
  "CWE-285": {
    means: "An administrative or privileged action answered a user who should not have access.",
    matters: "A normal user may be able to perform admin-level operations.",
    todo: "Verify the caller's role inside the handler. Route-level separation is not enough.",
  },
  "CWE-639": {
    means: "One user could read or change another user's records by changing an identifier.",
    matters: "Private data belonging to other customers may be exposed or altered.",
    todo: "Check that the signed-in user owns or is entitled to the specific record before "
      + "returning or modifying it.",
  },
  "CWE-798": {
    means: "A password, key or token is written directly into the code or app package.",
    matters: "Anyone who can read the code or unpack the app gets a working credential.",
    todo: "Remove the secret, rotate it immediately, and load it from a secret manager or the "
      + "device keystore at runtime.",
  },
  "CWE-319": {
    means: "Information travels over an unencrypted connection (plain HTTP).",
    matters: "Anyone on the network path can read or tamper with the traffic, including credentials.",
    todo: "Use HTTPS/TLS everywhere and disable the plaintext option.",
  },
  "CWE-89": {
    means: "User input reaches a database query without being safely separated from the query.",
    matters: "An attacker could read, change or delete data in your database.",
    todo: "Use parameterized queries (prepared statements); never build SQL by concatenating input.",
  },
  "CWE-79": {
    means: "User input is placed into a web page without being neutralised.",
    matters: "An attacker could run scripts in other users' browsers to steal sessions or data.",
    todo: "Escape output for its context and add a Content-Security-Policy.",
  },
  "CWE-94": {
    means: "Untrusted input can influence code that the system then executes.",
    matters: "An attacker may be able to run their own commands or code.",
    todo: "Never pass untrusted input into an interpreter; validate and use safe APIs.",
  },
  "CWE-213": {
    means: "A response returns more fields than a client needs, including sensitive ones.",
    matters: "Data such as credentials or personal fields may leak to anyone who calls the API.",
    todo: "Return an explicit allowlist of fields and never serialize the whole record.",
  },
  "CWE-770": {
    means: "There is no limit on how much a caller can request or how often.",
    matters: "The service can be overwhelmed, or large data sets scraped, by a single caller.",
    todo: "Add pagination with a bounded default and enforce rate limits.",
  },
  "CWE-522": {
    means: "Credentials are protected weakly (for example reversible or easily guessed).",
    matters: "Credentials could be recovered or reused by an attacker.",
    todo: "Use short-lived bearer tokens over TLS and rotate credentials regularly.",
  },
  "CWE-598": {
    means: "A secret (like an API key) is sent in the URL.",
    matters: "URLs are logged by servers, proxies and browser history, so the key leaks.",
    todo: "Send secrets in a header (or Authorization), never in the query string.",
  },
  "CWE-1220": {
    means: "Authentication is described in the contract but never actually applied.",
    matters: "The API appears protected but may be running open.",
    todo: "Apply the security requirement globally or per operation, and test it.",
  },
  "CWE-295": {
    means: "TLS certificate or hostname validation is disabled or bypassed.",
    matters: "An attacker in the middle could impersonate the server and read traffic.",
    todo: "Validate certificates and hostnames properly; never trust all certificates.",
  },
  "CWE-327": {
    means: "A weak or broken cryptographic algorithm is in use.",
    matters: "Data protected with it can be decrypted or forged more easily than expected.",
    todo: "Use a modern algorithm (for example AES-GCM) and current key sizes.",
  },
  "CWE-328": {
    means: "A weak hash function (such as MD5 or SHA-1) is used for security.",
    matters: "Values can be forged or collisions found, undermining integrity checks.",
    todo: "Use SHA-256 or stronger for security-relevant hashing.",
  },
  "CWE-489": {
    means: "The build is a debug/development build, not a hardened release build.",
    matters: "A debugger can attach and read memory, data and secrets from the running app.",
    todo: "Ship a release build with debugging disabled.",
  },
  "CWE-530": {
    means: "The app allows its data to be backed up and extracted.",
    matters: "App data can be pulled off the device and inspected.",
    todo: "Disable backup for sensitive apps, or exclude sensitive data from backups.",
  },
  "CWE-926": {
    means: "An app component is exposed so other apps on the device can invoke it.",
    matters: "Another app could reach functionality or data that should be private.",
    todo: "Set the component to not-exported, or require a signature-level permission.",
  },
  "CWE-250": {
    means: "Something runs with more privilege than it needs.",
    matters: "If it is compromised, the attacker inherits that extra power.",
    todo: "Apply least privilege: grant only the specific rights required.",
  },
  "CWE-284": {
    means: "Access to a resource or interface is not properly restricted.",
    matters: "Unauthorized users or devices may reach something they should not.",
    todo: "Restrict access to trusted networks/users and disable what is not needed.",
  },
  "CWE-1104": {
    means: "Software that no longer receives security updates is in use (end-of-life).",
    matters: "New vulnerabilities in it will never be patched.",
    todo: "Upgrade to a supported version.",
  },
  "CWE-262": {
    means: "Password-based sign-in is allowed where it should be restricted.",
    matters: "It exposes the service to password guessing.",
    todo: "Prefer key-based authentication and disable password login.",
  },
  "CWE-693": {
    means: "A protective control (such as a security header) is missing.",
    matters: "An attack that the control would have blocked can now succeed.",
    todo: "Add the missing control (for example a Content-Security-Policy header).",
  },
  "CWE-359": {
    means: "The app handles sensitive personal information.",
    matters: "It carries privacy and compliance obligations if mishandled.",
    todo: "Confirm each use is necessary, disclosed, and the data is protected at rest and in transit.",
  },
  "CWE-703": {
    means: "An error or unexpected condition is not handled clearly.",
    matters: "It can leak internal details or leave the system in an unexpected state.",
    todo: "Handle the case explicitly and document the expected responses.",
  },
  "CWE-477": {
    means: "A deprecated component or API is in use.",
    matters: "It no longer receives fixes and may carry known weaknesses.",
    todo: "Migrate to the supported replacement.",
  },
  "CWE-200": {
    means: "The system exposes information that should be kept internal.",
    matters: "It hands an attacker details that make other attacks easier.",
    todo: "Remove the exposure and restrict who can reach it.",
  },
  "CWE-939": {
    means: "A custom URL scheme can trigger app actions from outside.",
    matters: "Another app could invoke it with crafted input as an unauthenticated entry point.",
    todo: "Validate all incoming parameters and prefer verified links for sensitive actions.",
  },
  "CWE-1059": {
    means: "A documentation or inventory expectation is not met.",
    matters: "Gaps make the system harder to secure and audit reliably.",
    todo: "Bring the documentation or inventory in line with what is actually running.",
  },
  "CWE-538": {
    means: "A file that should be private is readable over the web.",
    matters: "It may reveal credentials, source, or configuration.",
    todo: "Remove the file from the web root and rotate anything it exposed.",
  },
  "CWE-1357": {
    means: "A dependency is used without pinning it to a known-good version.",
    matters: "A malicious or broken update could be pulled in automatically.",
    todo: "Pin dependencies to a specific, reviewed version or digest.",
  },
};

// Category-level fallback when there is no CWE mapping.
const CATEGORY: Record<string, CweText> = {
  "vuln-dep": {
    means: "A third-party dependency has a known vulnerability.",
    matters: "The known weakness is present in your software through this package.",
    todo: "Upgrade the package to a fixed version, or remove it if unused.",
  },
  secret: {
    means: "A credential appears to be committed into the code or package.",
    matters: "Anyone who can read it gains a working credential.",
    todo: "Rotate the credential now and move it out of the code into a secret store.",
  },
  "api-authorization": {
    means: "An authorization check is missing or not enforced on this API.",
    matters: "A user may reach data or actions they should not.",
    todo: "Enforce ownership and role checks on the server for every request.",
  },
  "api-inventory": {
    means: "An endpoint exists that is not in the documented API.",
    matters: "Undocumented endpoints are the ones defenders forget and attackers find.",
    todo: "Confirm it is intended, document it, or remove it.",
  },
};

const SEVERITY_MATTERS: Record<string, string> = {
  critical: "This is critical: it is likely exploitable and high-impact, and should be fixed first.",
  high: "This is high severity: it presents a serious risk and should be prioritised.",
  medium: "This is medium severity: worth fixing in the normal course of work.",
  low: "This is low severity: a smaller risk, but still worth addressing.",
  info: "This is informational: not a vulnerability by itself, but useful to know.",
};

function firstSentences(text: string, max = 2): string {
  const parts = text.replace(/\s+/g, " ").trim().split(/(?<=[.!?])\s+/);
  return parts.slice(0, max).join(" ");
}

/** A composed, human "Location" value from the finding's own evidence — never a bare duplicate of
 *  a single evidence field, so it cannot collide with the evidence table shown elsewhere. */
function whereFrom(f: Finding): string {
  const e = (f.evidence ?? {}) as Record<string, unknown>;
  const s = (k: string) => (typeof e[k] === "string" ? e[k] as string : "");
  const endpoint = s("endpoint") || s("url");
  if (endpoint) return `Endpoint ${endpoint}`;
  const file = s("file") || s("path");
  if (file) { const line = s("line"); return `File ${file}${line ? `:${line}` : ""}`; }
  const host = s("host") || s("gateway");
  if (host) { const port = s("port") || (typeof e.port === "number" ? String(e.port) : "");
    return `Host ${host}${port ? `:${port}` : ""}`; }
  const pkg = s("package") || s("component");
  if (pkg) { const v = s("version"); return `Component ${pkg}${v ? `@${v}` : ""}`; }
  return "";
}

export function explainFinding(f: Finding): Explanation {
  const cwe = f.cwe_id ? CWE[f.cwe_id] : undefined;
  const cat = f.category ? CATEGORY[f.category] : undefined;
  const desc = (f as Finding & { description?: string }).description ?? "";

  // "Remediation:" is a convention several engines use inside the description.
  const remIdx = desc.search(/remediation:/i);
  const descBody = remIdx >= 0 ? desc.slice(0, remIdx).trim() : desc.trim();
  const descRemediation = remIdx >= 0 ? desc.slice(remIdx).replace(/remediation:/i, "").trim() : "";

  const whatItMeans = cwe?.means || cat?.means
    || (descBody ? firstSentences(descBody) : `${f.title}. See the technical details below.`);

  const whyItMatters = cwe?.matters || cat?.matters
    || SEVERITY_MATTERS[f.severity] || SEVERITY_MATTERS.medium;

  const whatToDo = cwe?.todo || cat?.todo || descRemediation
    || "Review the technical details and evidence below, then apply the fix appropriate to your "
       + "environment.";

  return { whatItMeans, whyItMatters, whatToDo, where: whereFrom(f) };
}
