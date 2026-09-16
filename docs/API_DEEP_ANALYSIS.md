# Deep OpenAPI / API security analysis

**Status: IMPLEMENTED — additive to the existing `api` engine.** No new engine, no new asset kind,
no new finding model, no migration. Upload an `openapi.json` / `swagger.yaml` (asset config
`openapi_spec`, or inline content) on an `api` asset and the engine now reads the contract deeply
and, when authorized, compares it to the running service.

## What already existed (preserved, not rebuilt)

The `api` engine (`EngineKey.API`) already did: OpenAPI 3 + Swagger 2 ingestion (JSON/YAML), a `Spec`
model (servers, security schemes, operations, parameters, object-id and privileged detection, `$ref`
resolution), first-order contract review (no auth scheme, plaintext server, operation without
security, unvalidated parameter, no documented 429), and **live, principal-gated** BOLA / BFLA /
missing-auth / excessive-exposure testing (GET/HEAD only). All of this is untouched.

## What was added

### 1. Deep static spec-security analysis — `apisec/spec_audit.py` (pure, offline)

Reads the contract closely, no network:

| Check | Severity | CWE / OWASP |
|---|---|---|
| API key sent in the URL query string | MEDIUM | CWE-598 / API8 |
| HTTP Basic authentication scheme | LOW | CWE-522 / API2 |
| OAuth2 **implicit** flow declared | MEDIUM | CWE-522 / API2 |
| OAuth/OIDC endpoint over cleartext `http://` | HIGH | CWE-319 / API2 |
| Declared security schemes **never applied** (all unreferenced) | HIGH | CWE-1220 / API2 |
| Individual unused security scheme | LOW | CWE-1220 / API2 |
| Operation opts out of global auth (`security: []`) | HIGH | CWE-306 / API2 |
| Secured operation documents no 401/403 response | LOW | CWE-703 / API2 |
| Response schema exposes a sensitive field (by name) | MEDIUM | CWE-213 / API3 |
| Collection endpoint without pagination controls | LOW | CWE-770 / API4 |
| Placeholder / templated server URL | INFO | CWE-1059 / API8 |

Excessive-exposure detection walks the response schemas (resolving `$ref`, `allOf`/`oneOf`/`anyOf`,
array `items`, `additionalProperties`) with depth and cycle guards, and reports **field names only**
— never a value.

### 2. Spec-vs-reality probing — `apisec/discovery.py` (safe, GET-only, authorized)

Two checks the static review cannot make because they compare the contract to the live service:

- **Undocumented / shadow endpoints** (CWE-1059 / **API9 improper inventory**): a small curated
  wordlist of endpoints that commonly exist but are absent from the spec — framework actuators,
  metrics, admin/debug/console surfaces, and exposed API documentation (`openapi.json`,
  `swagger.json`, `api-docs`, …). A reachable one the document never declared is flagged; a
  protected one (401/403) is reported at lower severity but still as undocumented inventory.
- **Authentication the spec promised but the service does not enforce** (CWE-306 / **API2**): for an
  operation the document marks as secured, an **unauthenticated** GET that returns 2xx means the
  required credential is not actually checked. This needs **no principals** — it is the absence of
  auth, not another user's data — so it complements the principal-gated BOLA/BFLA tester rather than
  duplicating it. A concrete URL is built only from the operation's own path-parameter `example`
  values; an identifier is never invented.

## Security model (unchanged)

- **GET only.** No probe ever uses a state-changing method. No credential stuffing, no enumeration,
  no destructive action.
- **Bounded.** A fixed request budget (`api_probe_requests`, default 40), a per-request rate limit
  (`api_rate`), and an overall deadline (`api_deadline`). A pathological spec cannot cause unbounded
  probing.
- **Authorized.** The `api` engine is `requires_authorization = True` and is in `ACTIVE_ENGINES`, so
  the safe-scanning gate governs whether any request is sent at all — probing only runs for an asset
  the operator is authorized to assess. The static audit sends nothing and always runs.
- **No secret leakage.** The unauth probe sends no credentials; findings quote status codes and
  paths, never response bodies or field values.

## Pipeline

Every finding above is a normal `RawFinding` on `EngineKey.API` → deterministic risk → evidence →
AI analyst → report → audit. There is no separate API finding store or report path.

## Known limitations

- Undocumented-endpoint detection is a **curated safe wordlist**, not a brute-force fuzzer — by
  design (safe, bounded, low-noise). It finds the common shadow surfaces, not every possible path.
- Spec-vs-reality auth probing covers **GET** operations whose URL can be built from documented
  `example` values (or which have no path parameters); it never fabricates identifiers.
- Request-body/parameter schema *input-validation* depth beyond the existing "parameter without
  schema" check is not performed here.
