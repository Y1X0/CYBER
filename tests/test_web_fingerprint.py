"""HTTP probing and technology fingerprinting (WP-B3).

A hostname and a 200 are not a product. "WordPress 6.1.1 with jQuery 3.4.1 behind Cloudflare" is —
it names what to patch, and through the CPE it names exactly which advisories apply, which is what
WP-C3 consumes.

Two properties are asserted throughout and matter more than coverage of any one technology:

* **A version is only ever reported when the evidence contained one.** Inferring "WordPress" from
  `/wp-content/` and then guessing a release would produce a CPE matching advisories for software
  the customer may not run.
* **Evidence is graded.** A `Server:` header is the server naming itself; a cookie name identifies
  the stack but never the release; an HTML marker is the weakest, because a page can mention
  `/wp-content/` without running WordPress.

The last section drives a real HTTP server over a real socket, because the redirect and cookie
behaviour under test is the client's, not ours.
"""

from __future__ import annotations

import http.server
import threading

import pytest
from guardian_scanner.discovery.technologies import cpe_for, fingerprint, meta_generator, page_title
from guardian_scanner.discovery.webprobe import analyze


def techs(headers=None, body="", cookies=""):
    return {t.name: t for t in fingerprint(headers or {}, body, cookies)}


# ── headers: the strongest evidence ───────────────────────────────────────────────────────────────
def test_a_server_header_yields_product_and_version():
    found = techs({"Server": "nginx/1.24.0"})["nginx"]
    assert found.version == "1.24.0"
    assert found.category == "server"
    assert found.confidence == 95
    assert found.cpe == "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*"
    assert "nginx/1.24.0" in found.evidence


def test_a_server_header_without_a_version_claims_none():
    found = techs({"Server": "nginx"})["nginx"]
    assert found.version == ""
    assert found.cpe == "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*"
    assert found.confidence == 90


@pytest.mark.parametrize(
    ("header", "value", "name", "version"),
    [
        ("Server", "Apache/2.4.52 (Ubuntu)", "Apache", "2.4.52"),
        ("Server", "Microsoft-IIS/10.0", "Microsoft IIS", "10.0"),
        ("Server", "LiteSpeed", "LiteSpeed", ""),
        ("Server", "openresty/1.21.4.1", "OpenResty", "1.21.4.1"),
        ("Server", "gunicorn/20.1.0", "gunicorn", "20.1.0"),
        # The distribution suffix is dropped: CPE indexes upstream releases.
        ("X-Powered-By", "PHP/8.1.2-1ubuntu2.14", "PHP", "8.1.2"),
        ("X-Powered-By", "Express", "Express", ""),
        ("X-Jenkins", "2.426.1", "Jenkins", "2.426.1"),
        ("kbn-version", "8.11.0", "Kibana", "8.11.0"),
    ],
)
def test_header_signatures(header, value, name, version):
    found = techs({header: value})
    assert name in found, f"{header}: {value} did not identify {name}"
    assert found[name].version == version


def test_a_cdn_is_identified_from_its_own_header():
    found = techs({"CF-RAY": "8412a0e1fbd1-LHR", "Server": "cloudflare"})
    assert "Cloudflare" in found
    assert found["Cloudflare"].category == "cdn"


def test_a_waf_is_identified():
    assert "Sucuri WAF" in techs({"X-Sucuri-ID": "abc123"})
    assert techs({"X-Sucuri-ID": "abc"})["Sucuri WAF"].category == "waf"


# ── meta generator ────────────────────────────────────────────────────────────────────────────────
def test_wordpress_generator_carries_its_version():
    body = '<html><head><meta name="generator" content="WordPress 6.1.1" /></head></html>'
    found = techs(body=body)["WordPress"]
    assert found.version == "6.1.1"
    assert found.cpe == "cpe:2.3:a:wordpress:wordpress:6.1.1:*:*:*:*:*:*:*"
    assert found.confidence == 95


def test_drupal_is_identified_from_its_header_or_its_generator():
    from_header = techs({"X-Generator": "Drupal 10 (https://www.drupal.org)"})["Drupal"]
    assert from_header.version == "10"
    body = '<meta name="generator" content="Drupal 9 (https://www.drupal.org)">'
    assert techs(body=body)["Drupal"].version == "9"


def test_meta_generator_is_extracted():
    assert meta_generator('<meta name="generator" content="Joomla! 4.2">') == "Joomla! 4.2"
    assert meta_generator("<html></html>") == ""


# ── cookies: the stack, never the release ─────────────────────────────────────────────────────────
def test_a_session_cookie_identifies_the_framework_without_a_version():
    found = techs(cookies="laravel_session=abc; path=/; httponly")["Laravel"]
    assert found.version == ""
    assert found.confidence == 85
    assert "laravel_session" in found.evidence


def test_django_and_rails_and_php_from_cookies():
    assert "Django" in techs(cookies="csrftoken=abc")
    assert "Ruby on Rails" in techs(cookies="_session_id=abc")
    assert "PHP" in techs(cookies="PHPSESSID=abc")


def test_a_cookie_never_produces_a_version_even_when_the_value_looks_like_one():
    found = techs(cookies="PHPSESSID=8.1.2")["PHP"]
    assert found.version == ""


# ── HTML markers: the weakest signal ──────────────────────────────────────────────────────────────
def test_an_html_marker_identifies_but_at_lower_confidence():
    header_based = techs({"Server": "nginx/1.24.0"})["nginx"]
    body_based = techs(body='<link href="/wp-content/themes/x/style.css">')["WordPress"]
    assert body_based.confidence < header_based.confidence
    assert body_based.version == ""
    assert body_based.cpe == "cpe:2.3:a:wordpress:wordpress:*:*:*:*:*:*:*:*"


def test_a_versioned_script_path_yields_the_library_version():
    found = techs(body='<script src="/js/jquery-3.4.1.min.js"></script>')["jQuery"]
    assert found.version == "3.4.1"
    assert found.cpe == "cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*"


def test_angular_version_attribute():
    assert techs(body='<app-root ng-version="15.2.9">')["Angular"].version == "15.2.9"


def test_a_marker_without_a_version_produces_a_wildcard_cpe_not_a_guess():
    found = techs(body="<div data-reactroot></div>")["React"]
    assert found.version == ""


# ── implications ──────────────────────────────────────────────────────────────────────────────────
def test_an_implied_technology_is_marked_as_inferred():
    """WordPress implies PHP. That is a fact about the stack, not something we observed."""
    found = techs(body='<meta name="generator" content="WordPress 6.1.1">')
    assert "PHP" in found
    assert found["PHP"].evidence == "implied by WordPress"
    assert found["PHP"].confidence < found["WordPress"].confidence
    assert found["PHP"].version == ""


def test_an_observed_technology_is_not_overwritten_by_an_implication():
    found = techs({"X-Powered-By": "PHP/8.1.2"},
                  body='<meta name="generator" content="WordPress 6.1.1">')
    assert found["PHP"].version == "8.1.2"
    assert "implied" not in found["PHP"].evidence


# ── CPE discipline ────────────────────────────────────────────────────────────────────────────────
def test_a_technology_with_no_known_cpe_mapping_gets_none():
    """An invented CPE matches nothing in a feed, which downstream reads as "no vulnerabilities"."""
    found = techs({"X-Sucuri-ID": "abc"})["Sucuri WAF"]
    assert found.cpe == ""


def test_cpe_uses_the_real_vendor():
    from guardian_scanner.discovery.technologies import SIGNATURES

    apache = next(s for s in SIGNATURES if s.name == "Apache")
    assert cpe_for(apache, "2.4.52") == "cpe:2.3:a:apache:http_server:2.4.52:*:*:*:*:*:*:*"


# ── a whole response ──────────────────────────────────────────────────────────────────────────────
WORDPRESS = """<!DOCTYPE html><html><head>
<meta name="generator" content="WordPress 6.1.1" />
<title>  Example   Blog </title>
<script src="/wp-includes/js/jquery/jquery-3.6.0.min.js"></script>
</head><body>/wp-content/uploads/</body></html>"""


def test_a_realistic_response_produces_a_full_inventory():
    observation = analyze(
        "https://blog.example.com/",
        200,
        {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1.2",
         "CF-RAY": "8412a0e1fbd1-LHR", "Content-Type": "text/html"},
        WORDPRESS,
        set_cookies=["wordpress_logged_in=abc; path=/"],
    )
    names = {t.name: t for t in observation.technologies}
    assert names["WordPress"].version == "6.1.1"
    assert names["nginx"].version == "1.24.0"
    assert names["PHP"].version == "8.1.2"
    assert names["jQuery"].version == "3.6.0"
    assert "Cloudflare" in names
    assert observation.title == "Example Blog"
    assert observation.status == 200


def test_the_attributes_expose_cpes_for_vulnerability_matching():
    observation = analyze("https://x.example.com/", 200, {"Server": "nginx/1.24.0"}, WORDPRESS)
    attributes = observation.as_attributes()
    assert "cpe:2.3:a:nginx:nginx:1.24.0:*:*:*:*:*:*:*" in attributes["cpes"]
    assert "cpe:2.3:a:wordpress:wordpress:6.1.1:*:*:*:*:*:*:*" in attributes["cpes"]


def test_page_title_is_normalized_and_bounded():
    assert page_title("<title>\n  Hello   World \n</title>") == "Hello World"
    assert page_title("<html></html>") == ""
    assert len(page_title(f"<title>{'x' * 500}</title>")) <= 200


# ── security posture that discovery observes ──────────────────────────────────────────────────────
def test_missing_security_headers_are_recorded():
    observation = analyze("https://x.example.com/", 200,
                          {"Strict-Transport-Security": "max-age=63072000"}, "")
    assert "strict-transport-security" in observation.security_headers_present
    assert "content-security-policy" in observation.security_headers_missing
    assert "strict-transport-security" not in observation.security_headers_missing


def test_insecure_cookie_flags_are_recorded():
    observation = analyze(
        "https://x.example.com/", 200, {}, "",
        set_cookies=["sid=abc; Path=/", "ok=1; Path=/; HttpOnly; Secure; SameSite=Lax"],
    )
    assert len(observation.insecure_cookies) == 1
    assert observation.insecure_cookies[0].startswith("sid")
    assert "HttpOnly" in observation.insecure_cookies[0]
    assert "Secure" in observation.insecure_cookies[0]


def test_secure_is_not_demanded_of_a_plaintext_service():
    """Over HTTP the transport is the finding, not the flag. Reporting a missing `Secure` there
    points at the wrong problem."""
    observation = analyze("http://x.example.com/", 200, {}, "",
                          set_cookies=["sid=abc; Path=/; HttpOnly; SameSite=Lax"])
    assert observation.insecure_cookies == []


# ── a real server, over a real socket ─────────────────────────────────────────────────────────────
class _Site(http.server.BaseHTTPRequestHandler):
    ROUTES = {
        "/": (301, "", {"Location": "/home"}),
        "/home": (200, WORDPRESS, {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1.2",
                                   "Set-Cookie": "wordpress_sec=abc; Path=/"}),
        "/offsite": (302, "", {"Location": "https://evil.example.net/"}),
    }

    def do_GET(self):  # noqa: N802 - BaseHTTPRequestHandler's interface
        status, body, headers = self.ROUTES.get(self.path, (404, "missing", {}))
        payload = body.encode()
        # send_response_only, not send_response: the latter adds its own `Server:` header, which
        # would sit alongside the fixture's and make the test assert on the wrong one.
        self.send_response_only(status)
        for key, value in headers.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        return


@pytest.fixture(scope="module")
def site():
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Site)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield server.server_address[1]
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def _fetch(port: int, path: str):
    """Drive the analysis over a real request, without the production public-address guard —
    the guard refuses loopback by design and is asserted separately."""
    import httpx

    chain: list[str] = []
    left_scope = False
    url = f"http://127.0.0.1:{port}{path}"
    current = url
    with httpx.Client(follow_redirects=False, timeout=5) as client:
        for _hop in range(6):
            response = client.get(current)
            chain.append(current)
            if 300 <= response.status_code < 400 and "location" in response.headers:
                target = str(response.url.join(response.headers["location"]))
                if "127.0.0.1" not in target:
                    left_scope = True
                    chain.append(target)
                    break
                current = target
                continue
            break
    return analyze(url, response.status_code, dict(response.headers), response.text,
                   set_cookies=response.headers.get_list("set-cookie"),
                   redirect_chain=chain, left_scope=left_scope)


def test_a_real_response_is_fingerprinted_end_to_end(site):
    observation = _fetch(site, "/home")
    names = {t.name for t in observation.technologies}
    assert {"nginx", "PHP", "WordPress", "jQuery"} <= names
    assert observation.status == 200
    assert observation.title == "Example Blog"
    assert observation.insecure_cookies  # the fixture sets a cookie with no flags


def test_an_in_scope_redirect_is_followed_and_recorded(site):
    observation = _fetch(site, "/")
    assert len(observation.redirect_chain) == 2
    assert observation.final_url.endswith("/home")
    assert observation.left_scope is False
    assert observation.status == 200


def test_a_redirect_off_the_authorized_host_is_recorded_but_not_followed(site):
    """Following a response-chosen host is how a scanner gets aimed at somebody else."""
    observation = _fetch(site, "/offsite")
    assert observation.left_scope is True
    assert observation.redirect_chain[-1].startswith("https://evil.example.net")
    assert observation.as_attributes()["redirect_left_scope"] is True


def test_the_live_probe_refuses_a_non_public_host():
    import inspect

    from guardian_scanner.discovery import webprobe

    source = inspect.getsource(webprobe.probe)
    assert "_is_public_address(host)" in source
    assert source.index("_is_public_address(host)") < source.index("client.get(current)")


def test_an_unreachable_service_is_an_error_not_a_clean_result():
    from guardian_scanner.discovery.webprobe import probe

    observation = probe("http://127.0.0.1:1/", timeout=1.0)
    assert observation.reachable is False
    assert observation.error
    assert observation.as_attributes()["probe_error"]


# ── the discovery provider carries the inventory onto the asset ───────────────────────────────────
def test_a_recorded_http_response_lands_on_the_service_asset():
    """The snapshot path runs the same analysis the live path does, so what CI proves is what
    production produces."""
    from guardian_core.discovery import DiscoveryContext
    from guardian_scanner.discovery.providers.service_scan_provider import ServiceScanProvider

    snapshot = {"93.184.216.34": {"443": {
        "tls": {"version": "TLSv1.3"},
        "http": {
            "status": 200,
            "headers": {"Server": "nginx/1.24.0", "X-Powered-By": "PHP/8.1.2"},
            "body": WORDPRESS,
            "set_cookies": ["sid=abc; Path=/"],
        },
    }}}
    ctx = DiscoveryContext(tenant_id="t", run_id="r", authorized=True,
                           authorized_targets=["93.184.216.34"],
                           settings={"service_scan": snapshot})
    services = [a for a in ServiceScanProvider().collect(ctx) if a.node_type.value == "service"]
    attributes = services[0].attributes
    names = {t["name"]: t for t in attributes["technologies"]}
    assert names["WordPress"]["version"] == "6.1.1"
    assert names["nginx"]["version"] == "1.24.0"
    assert "cpe:2.3:a:wordpress:wordpress:6.1.1:*:*:*:*:*:*:*" in attributes["cpes"]
    assert attributes["title"] == "Example Blog"
    assert "content-security-policy" in attributes["security_headers_missing"]
    assert attributes["insecure_cookies"]


def test_a_non_web_service_gets_no_web_attributes():
    from guardian_core.discovery import DiscoveryContext
    from guardian_scanner.discovery.providers.service_scan_provider import ServiceScanProvider

    snapshot = {"93.184.216.34": {"22": {"banner": "SSH-2.0-OpenSSH_9.0"}}}
    ctx = DiscoveryContext(tenant_id="t", run_id="r", authorized=True,
                           authorized_targets=["93.184.216.34"],
                           settings={"service_scan": snapshot})
    services = [a for a in ServiceScanProvider().collect(ctx) if a.node_type.value == "service"]
    assert "technologies" not in services[0].attributes
    assert services[0].attributes["cpe"] == "cpe:2.3:a:openbsd:openssh:9.0:*:*:*:*:*:*:*"
