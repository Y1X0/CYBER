# Security Policy

Security Guardian is a defensive security platform; we hold ourselves to the standards we help others
meet. This policy covers **coordinated vulnerability disclosure** for the platform itself.

> Note: the project is currently in the **architecture & design phase** — no application code has been
> written yet. This policy is published now so the process exists before the first line of code.

## Reporting a vulnerability

- **Do not** open a public issue for security vulnerabilities.
- Report privately via **GitHub Security Advisories** ("Report a vulnerability" on the Security tab)
  once enabled, or the contact address published in the repository once implementation begins.
- Please include: affected component, version/commit, reproduction steps, impact, and any PoC.

## Our commitment

- We acknowledge reports promptly and keep you updated through triage and fix.
- We practice **coordinated disclosure**: a fix is prepared before public details are released.
- We credit reporters (with consent).

## Scope

**In scope (once code exists):** the platform's own services, APIs, workers, dashboard, and
infrastructure-as-code in this repository.

**Out of scope:** third-party OSS scanners invoked by the platform (report those upstream); findings
*produced by* the platform about *your* systems (that is expected output, not a platform vulnerability);
and any testing against assets you are not authorized to assess.

## Responsible use

This platform performs **authorized, defensive** security testing only. Use it exclusively against
systems you own or have written permission to assess. See the responsible-use policy in the
[README](README.md) and the [Security Model](docs/architecture/06-security-model.md).
