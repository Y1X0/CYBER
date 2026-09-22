# API CORS misconfiguration & response header hygiene

The API engine's principal-free surface probe (`apisec/discovery.py`, reached through
`ApiEngine.run` whenever a base URL exists) sends **one benign GET per reachable spec endpoint**
carrying a throwaway `Origin` header, and reads two things off that single already-fetched response:
the CORS policy, and the transport/response security headers. It adds **no new principal, no
state-changing method, and no request beyond the one Origin probe per endpoint** — GET only, inside
the same request budget as the rest of the probe.

The grading logic lives in `apisec/checks.py` as the pure functions `evaluate_cors` and
`evaluate_response_hygiene`, tested directly (`tests/test_apisec.py`); the wiring and finding
emission live in `apisec/discovery.py`, tested with a fake fetch (`tests/test_api_discovery.py`).

## CORS misconfiguration

The probe sends `Origin: https://guardian-apisec-cors-probe.invalid` — a reserved `.invalid` origin
(RFC 2606) no server has any reason to trust. Grading keys on the response's
`Access-Control-Allow-Origin` (ACAO) and `Access-Control-Allow-Credentials` (ACAC), and reflection is
**confirmed by the endpoint echoing that exact probe origin back**, never inferred from a wildcard.

| Response | Finding | Severity | Why |
|---|---|---|---|
| ACAO reflects the probe origin **and** ACAC: true | `api-cors-credentialed` | **HIGH** | Any site can read this endpoint's authenticated responses in a victim's session |
| `ACAO: *` **and** ACAC: true | `api-cors-credentialed` | **HIGH** | Spec-invalid, but stacks that honour it expose credentialed responses to every origin |
| ACAO reflects the probe origin, ACAC absent/false | `api-cors-open` | MEDIUM | Cross-origin reads of this endpoint's data, no credentials |
| `ACAO: null` | `api-cors-open` | MEDIUM | Satisfied by any sandboxed, null-origin document (`data:` URI, sandboxed iframe) |
| `ACAO: *`, no credentials | *(not reported)* | — | A public wildcard with no credentials is usually intended; flagging it is noise |
| ACAO echoes a **real allowlisted** origin (not the probe) | *(not reported)* | — | Correct behaviour — the server rejected our arbitrary origin |

The two HIGH combinations are the only HIGH cases: the credentialed ones. Everything else is MEDIUM
or nothing. CWE-942 (permissive cross-domain policy), OWASP API8:2023 (Security Misconfiguration).

## Response transport / header hygiene

Passive over the **same response the CORS probe already fetched** — it issues no request of its own,
and only inspects responses that actually exist (2xx; a 404 or a refusal is skipped). Each check is
deliberately low-FP:

| Check | Fires when | Severity | Rule |
|---|---|---|---|
| HSTS | HTTPS response with no `Strict-Transport-Security` | MEDIUM | `api-missing-hsts` (CWE-319) |
| Cacheable private data | Response carries recognizable private fields (matched by field **name** only) and has no `Cache-Control: no-store` | MEDIUM | `api-cache-sensitive` (CWE-525) |
| MIME sniffing | Response has no `X-Content-Type-Options: nosniff` | LOW | `api-missing-content-type-options` (CWE-693) |

HSTS and the MIME-sniffing gap are properties of the running service, not of one route, so each is
reported **once per scan** (the first reachable endpoint that shows it). The private-cache check is
data-specific but is likewise reported once to stay quiet. As with excessive-exposure, the cache
check matches on the field **name** only and never records a value.

## Overlap with the website scanner — scoped, not duplicated

Product Area 1's web-checks (`dast/checks.py`) already grade CORS on a **web asset's base origin**,
and there is no standalone header-hygiene check there to duplicate. These API checks are scoped to
the **API's own spec endpoints** and run under the API engine (`asset_kind == "api"`), a different
asset kind from the web engine (`asset_kind == "web"`). The two never run on the same asset, so
there is no double-reporting; the API context is exactly the gap the capability audit flagged.

## Guarantees

- **Principal-safe / GET-only.** One benign GET per endpoint with a throwaway `Origin`; never a
  credential, never a state-changing method, never identifier enumeration. Bounded by the shared
  request budget, rate limit and deadline, and capped at a fixed number of CORS probes per scan.
- **Reflection is proven, not assumed.** A finding requires the endpoint to echo our arbitrary probe
  origin (or an explicit `*`/`null`); a real allowlist that rejects it is never flagged.
- **Low false-positive by construction.** Only credentialed CORS is HIGH; a plain public wildcard is
  not reported at all; header checks fire only on real (2xx) responses, and the cache check only when
  the body carries a recognizable private field.
- **Deterministic.** Same response → same findings, in a fixed order, independent of iteration order
  (URL dedup, once-per-scan hygiene reporting).
- **Coverage is honest.** These run inside the existing surface probe; when no base URL is
  configured the engine already emits its coverage finding, so silence is never mistaken for clean.
