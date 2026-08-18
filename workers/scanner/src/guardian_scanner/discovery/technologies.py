"""What software is behind a web service (WP-B3).

A hostname and a 200 tell a customer nothing. "WordPress 6.1.1 with jQuery 3.4.1 behind Cloudflare"
tells them what to patch, what the attack surface is, and — through the CPE — exactly which
advisories apply. This module is that translation, and it is the second producer (after service
banners in WP-B2) of the CPE strings WP-C3 looks CVEs up by.

Evidence is graded, because the signals genuinely differ in strength:

* a `Server:` or `X-Powered-By:` header that names a product **and** a version is close to
  authoritative — the server said it about itself;
* a session cookie name (`laravel_session`, `PHPSESSID`) identifies the stack reliably but never
  the version;
* an HTML marker or a script path is the weakest, because a page can mention `/wp-content/` for
  reasons other than running WordPress.

A technology is only ever reported with a version the evidence actually contained. Inferring
"WordPress" and then guessing "6.x" would produce a CPE that matches advisories for software the
customer may not be running, and a fabricated critical is worse than a missing one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_BODY_BYTES = 300_000
MAX_TECHNOLOGIES = 60


@dataclass
class Technology:
    name: str
    category: str
    version: str = ""
    confidence: int = 50
    evidence: str = ""          # what matched, so a human can check the claim
    cpe: str = ""

    def key(self) -> str:
        return self.name.lower()


@dataclass(frozen=True)
class Signature:
    name: str
    category: str               # server | language | framework | cms | cdn | waf | js | analytics
    # (header name, pattern). A named group `version` supplies the version when present.
    headers: tuple[tuple[str, re.Pattern[str]], ...] = ()
    cookies: tuple[re.Pattern[str], ...] = ()
    html: tuple[re.Pattern[str], ...] = ()
    meta_generator: tuple[re.Pattern[str], ...] = ()
    implies: tuple[str, ...] = ()
    cpe_vendor: str = ""
    cpe_product: str = ""
    # Some markers are strong evidence of the product and say nothing about the release.
    version_from_evidence: bool = True


def _p(pattern: str) -> re.Pattern[str]:
    return re.compile(pattern, re.IGNORECASE)


# Dotted-numeric only, deliberately. A looser pattern captures `3.6.0.min` out of
# `jquery-3.6.0.min.js`, and it captures the distribution suffix out of `PHP/8.1.2-1ubuntu2.14` —
# neither of which is a version any CVE feed is indexed by. CPE records upstream releases, so the
# upstream release is what gets captured.
_VERSION = r"(?P<version>\d+(?:\.\d+)*)"

SIGNATURES: tuple[Signature, ...] = (
    # ── web servers ──────────────────────────────────────────────────────────────────────────────
    Signature("nginx", "server", headers=(("server", _p(rf"^nginx(?:/{_VERSION})?")),),
              cpe_vendor="nginx", cpe_product="nginx"),
    Signature("Apache", "server", headers=(("server", _p(rf"^apache(?:/{_VERSION})?")),),
              cpe_vendor="apache", cpe_product="http_server"),
    Signature("Microsoft IIS", "server",
              headers=(("server", _p(rf"^microsoft-iis(?:/{_VERSION})?")),),
              cpe_vendor="microsoft", cpe_product="internet_information_services"),
    Signature("LiteSpeed", "server", headers=(("server", _p(rf"^litespeed(?:/{_VERSION})?")),),
              cpe_vendor="litespeedtech", cpe_product="litespeed_web_server"),
    Signature("OpenResty", "server", headers=(("server", _p(rf"^openresty(?:/{_VERSION})?")),),
              cpe_vendor="openresty", cpe_product="openresty"),
    Signature("Caddy", "server", headers=(("server", _p(rf"^caddy(?:/{_VERSION})?")),),
              cpe_vendor="caddyserver", cpe_product="caddy"),
    Signature("Apache Tomcat", "server",
              headers=(("server", _p(rf"^apache-coyote(?:/{_VERSION})?")),),
              cpe_vendor="apache", cpe_product="tomcat"),
    Signature("Jetty", "server", headers=(("server", _p(rf"^jetty(?:\({_VERSION}\))?")),),
              cpe_vendor="eclipse", cpe_product="jetty"),
    Signature("gunicorn", "server", headers=(("server", _p(rf"^gunicorn(?:/{_VERSION})?")),),
              cpe_vendor="gunicorn", cpe_product="gunicorn"),
    Signature("Werkzeug", "server", headers=(("server", _p(rf"^werkzeug(?:/{_VERSION})?")),),
              cpe_vendor="palletsprojects", cpe_product="werkzeug"),
    Signature("Envoy", "server", headers=(("server", _p("^envoy")),),
              cpe_vendor="envoyproxy", cpe_product="envoy"),

    # ── languages and runtimes ───────────────────────────────────────────────────────────────────
    Signature("PHP", "language",
              headers=(("x-powered-by", _p(rf"^php(?:/{_VERSION})?")),),
              cookies=(_p(r"\bPHPSESSID="),),
              cpe_vendor="php", cpe_product="php"),
    Signature("ASP.NET", "framework",
              headers=(("x-powered-by", _p("^asp\\.net")),
                       ("x-aspnet-version", _p(rf"^{_VERSION}"))),
              cookies=(_p(r"\bASP\.NET_SessionId="),),
              cpe_vendor="microsoft", cpe_product="asp.net"),
    Signature("Node.js", "language", headers=(("x-powered-by", _p("^node")),),
              cpe_vendor="nodejs", cpe_product="node.js"),

    # ── frameworks ───────────────────────────────────────────────────────────────────────────────
    Signature("Express", "framework", headers=(("x-powered-by", _p("^express")),),
              implies=("Node.js",), cpe_vendor="openjsf", cpe_product="express"),
    Signature("Django", "framework", cookies=(_p(r"\bcsrftoken="),),
              html=(_p(r'name=["\']csrfmiddlewaretoken["\']'),),
              cpe_vendor="djangoproject", cpe_product="django", version_from_evidence=False),
    Signature("Ruby on Rails", "framework",
              headers=(("x-runtime", _p(r"^[\d.]+$")),),
              cookies=(_p(r"\b_session_id="),),
              cpe_vendor="rubyonrails", cpe_product="rails", version_from_evidence=False),
    Signature("Laravel", "framework", cookies=(_p(r"\blaravel_session="), _p(r"\bXSRF-TOKEN=")),
              implies=("PHP",), cpe_vendor="laravel", cpe_product="laravel",
              version_from_evidence=False),
    Signature("Next.js", "framework",
              headers=(("x-powered-by", _p(rf"^next\.js(?:\s+{_VERSION})?")),),
              html=(_p(r"/_next/static/"),),
              cpe_vendor="vercel", cpe_product="next.js"),
    Signature("Spring", "framework", cookies=(_p(r"\bJSESSIONID="),),
              version_from_evidence=False),
    Signature("Flask", "framework", cookies=(_p(r"\bsession=eyJ"),),
              implies=("Werkzeug",), version_from_evidence=False),

    # ── content management ───────────────────────────────────────────────────────────────────────
    Signature("WordPress", "cms",
              meta_generator=(_p(rf"^wordpress(?:\s+{_VERSION})?"),),
              html=(_p(r"/wp-content/"), _p(r"/wp-includes/")),
              implies=("PHP",), cpe_vendor="wordpress", cpe_product="wordpress"),
    Signature("Drupal", "cms",
              headers=(("x-generator", _p(rf"^drupal(?:\s+{_VERSION})?")),),
              meta_generator=(_p(rf"^drupal(?:\s+{_VERSION})?"),),
              html=(_p(r"Drupal\.settings"), _p(r"/sites/default/files/")),
              implies=("PHP",), cpe_vendor="drupal", cpe_product="drupal"),
    Signature("Joomla", "cms",
              meta_generator=(_p(rf"^joomla!?(?:\s+{_VERSION})?"),),
              html=(_p(r"/media/jui/"), _p(r"/components/com_")),
              implies=("PHP",), cpe_vendor="joomla", cpe_product="joomla\\!"),
    Signature("Magento", "cms", cookies=(_p(r"\bX-Magento-Vary="),),
              html=(_p(r"Mage\.Cookies"), _p(r"/static/version\d+/frontend/")),
              implies=("PHP",), cpe_vendor="magento", cpe_product="magento",
              version_from_evidence=False),
    Signature("Shopify", "cms", headers=(("x-shopid", _p(r"^\d+")),),
              version_from_evidence=False),
    Signature("Ghost", "cms", meta_generator=(_p(rf"^ghost(?:\s+{_VERSION})?"),)),

    # ── operational software worth knowing is on the internet ────────────────────────────────────
    Signature("Jenkins", "devops", headers=(("x-jenkins", _p(rf"^{_VERSION}")),),
              cpe_vendor="jenkins", cpe_product="jenkins"),
    Signature("GitLab", "devops", headers=(("x-gitlab-feature-category", _p(r".")),),
              cookies=(_p(r"\b_gitlab_session="),), cpe_vendor="gitlab", cpe_product="gitlab",
              version_from_evidence=False),
    Signature("Grafana", "devops", cookies=(_p(r"\bgrafana_session="),),
              html=(_p(r"grafana-app"),), cpe_vendor="grafana", cpe_product="grafana",
              version_from_evidence=False),
    Signature("Kibana", "devops",
              headers=(("kbn-name", _p(r".")), ("kbn-version", _p(rf"^{_VERSION}"))),
              cpe_vendor="elastic", cpe_product="kibana"),
    Signature("Atlassian Confluence", "devops",
              headers=(("x-confluence-request-time", _p(r".")),),
              cpe_vendor="atlassian", cpe_product="confluence", version_from_evidence=False),
    Signature("Atlassian Jira", "devops", headers=(("x-ausername", _p(r".")),),
              cpe_vendor="atlassian", cpe_product="jira", version_from_evidence=False),

    # ── edge, CDN and WAF ────────────────────────────────────────────────────────────────────────
    Signature("Cloudflare", "cdn", headers=(("cf-ray", _p(r".")), ("server", _p("^cloudflare"))),
              version_from_evidence=False),
    Signature("Amazon CloudFront", "cdn",
              headers=(("x-amz-cf-id", _p(r".")), ("via", _p("cloudfront"))),
              version_from_evidence=False),
    Signature("Fastly", "cdn", headers=(("x-served-by", _p(r"^cache-")), ("x-fastly", _p(r"."))),
              version_from_evidence=False),
    Signature("Akamai", "cdn", headers=(("x-akamai-transformed", _p(r".")),),
              version_from_evidence=False),
    Signature("Varnish", "cdn", headers=(("x-varnish", _p(r".")),),
              cpe_vendor="varnish-cache", cpe_product="varnish_cache",
              version_from_evidence=False),
    Signature("Sucuri WAF", "waf", headers=(("x-sucuri-id", _p(r".")),),
              version_from_evidence=False),
    Signature("Imperva", "waf", headers=(("x-iinfo", _p(r".")),), version_from_evidence=False),
    Signature("AWS WAF", "waf", headers=(("x-amzn-waf-action", _p(r".")),),
              version_from_evidence=False),

    # ── client-side ──────────────────────────────────────────────────────────────────────────────
    Signature("jQuery", "js", html=(_p(rf"jquery[-.]{_VERSION}(?:\.min)?\.js"),),
              cpe_vendor="jquery", cpe_product="jquery"),
    Signature("Bootstrap", "js", html=(_p(rf"bootstrap[-.]{_VERSION}(?:\.min)?\.(?:js|css)"),),
              cpe_vendor="getbootstrap", cpe_product="bootstrap"),
    Signature("React", "js", html=(_p(r"__REACT_DEVTOOLS_GLOBAL_HOOK__"), _p(r"data-reactroot")),
              version_from_evidence=False),
    Signature("Vue.js", "js", html=(_p(r"data-v-[0-9a-f]{8}"), _p(r"__VUE_DEVTOOLS")),
              version_from_evidence=False),
    Signature("Angular", "js", html=(_p(rf'ng-version=["\']{_VERSION}'),),
              cpe_vendor="angular", cpe_product="angular"),
    Signature("Google Analytics", "analytics",
              html=(_p(r"google-analytics\.com/analytics\.js"), _p(r"gtag\('config'")),
              version_from_evidence=False),
    Signature("Google Tag Manager", "analytics", html=(_p(r"googletagmanager\.com/gtm\.js"),),
              version_from_evidence=False),
)

_META_GENERATOR = re.compile(
    r"""<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)["']""", re.IGNORECASE
)
_TITLE = re.compile(r"<title[^>]*>(.*?)</title>", re.IGNORECASE | re.DOTALL)


def cpe_for(signature: Signature, version: str) -> str:
    if not signature.cpe_vendor or not signature.cpe_product:
        return ""
    return (f"cpe:2.3:a:{signature.cpe_vendor}:{signature.cpe_product}:"
            f"{version or '*'}:*:*:*:*:*:*:*")


def page_title(body: str) -> str:
    found = _TITLE.search(body or "")
    if found is None:
        return ""
    return re.sub(r"\s+", " ", found.group(1)).strip()[:200]


def meta_generator(body: str) -> str:
    found = _META_GENERATOR.search(body or "")
    return found.group(1).strip() if found else ""


def fingerprint(
    headers: dict[str, str], body: str = "", cookies: str = ""
) -> list[Technology]:
    """Identify the stack behind one HTTP response.

    `headers` are lower-cased names to values. `cookies` is the raw `Set-Cookie` text (there may be
    several, so it is passed joined rather than parsed into one dict — a cookie's *name* is the
    signal and the last header would otherwise win).
    """
    lowered = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    body = (body or "")[:MAX_BODY_BYTES]
    generator = meta_generator(body)
    found: dict[str, Technology] = {}

    for signature in SIGNATURES:
        technology = _match(signature, lowered, body, cookies or "", generator)
        if technology is None:
            continue
        existing = found.get(technology.key())
        if existing is None or _stronger(technology, existing):
            found[technology.key()] = technology

    # An implication is a fact about the stack, not an observation, so it is recorded at lower
    # confidence and never with a version.
    for signature in SIGNATURES:
        if signature.name.lower() not in found:
            continue
        for implied in signature.implies:
            key = implied.lower()
            if key in found:
                continue
            parent = next((s for s in SIGNATURES if s.name == implied), None)
            if parent is None:
                continue
            found[key] = Technology(
                name=implied, category=parent.category, confidence=60,
                evidence=f"implied by {signature.name}",
            )

    ordered = sorted(found.values(), key=lambda t: (-t.confidence, t.category, t.name))
    return ordered[:MAX_TECHNOLOGIES]


def _stronger(candidate: Technology, current: Technology) -> bool:
    if bool(candidate.version) != bool(current.version):
        return bool(candidate.version)
    return candidate.confidence > current.confidence


def _match(
    signature: Signature, headers: dict[str, str], body: str, cookies: str, generator: str
) -> Technology | None:
    # Headers first: the server naming itself is the strongest evidence available.
    for name, pattern in signature.headers:
        value = headers.get(name)
        if not value:
            continue
        hit = pattern.search(value)
        if hit is None:
            continue
        version = _version_of(hit) if signature.version_from_evidence else ""
        return Technology(
            name=signature.name, category=signature.category, version=version,
            confidence=95 if version else 90,
            evidence=f"{name}: {value[:80]}",
            cpe=cpe_for(signature, version),
        )

    for pattern in signature.meta_generator:
        hit = pattern.search(generator)
        if hit is None:
            continue
        version = _version_of(hit) if signature.version_from_evidence else ""
        return Technology(
            name=signature.name, category=signature.category, version=version,
            confidence=95 if version else 85,
            evidence=f"meta generator: {generator[:80]}",
            cpe=cpe_for(signature, version),
        )

    for pattern in signature.cookies:
        hit = pattern.search(cookies)
        if hit is None:
            continue
        # A cookie name identifies the stack and never the release.
        return Technology(
            name=signature.name, category=signature.category, confidence=85,
            evidence=f"cookie: {hit.group(0)[:60]}",
            cpe=cpe_for(signature, ""),
        )

    for pattern in signature.html:
        hit = pattern.search(body)
        if hit is None:
            continue
        version = _version_of(hit) if signature.version_from_evidence else ""
        return Technology(
            name=signature.name, category=signature.category, version=version,
            # The weakest signal: a page can mention `/wp-content/` without running WordPress.
            confidence=80 if version else 70,
            evidence=f"body: {hit.group(0)[:60]}",
            cpe=cpe_for(signature, version),
        )
    return None


def _version_of(match: re.Match[str]) -> str:
    """The `version` group, or "" when this pattern has none. Never a guess."""
    return (match.groupdict().get("version") or "").strip()
