"""The crawl and the scan loop (WP-D2).

An active scanner is a program that sends attack traffic at a customer's application, so what it
refuses to do matters more than what it does. These tests are mostly about refusals: nothing leaves
the authorized host, nothing state-changing is requested, no POST form is submitted, and the loop
stops at its budget instead of turning a scan into a flood.

The transport is injected, so all of it runs without a socket.
"""

from __future__ import annotations

from guardian_scanner.dast import crawl as cr
from guardian_scanner.dast.scanner import ActiveScanner, Budget, Response, with_param

HOSTS = frozenset({"app.example.com"})
HTML = {"content-type": "text/html"}


def _site(pages: dict, *, record: list | None = None):
    """A fake application: path → (status, headers, body)."""

    def fetch(url: str, headers: dict | None = None) -> Response:
        if record is not None:
            record.append(url)
        parsed = cr.urlparse(url)
        key = parsed.path
        status, hdrs, body = pages.get(key, (404, HTML, "<html>not found</html>"))
        if callable(body):
            body = body(parsed.query, headers or {})
        if callable(hdrs):
            hdrs = hdrs(parsed.query, headers or {})
        return Response(status=status, headers=hdrs, body=body, url=url)

    return fetch


# ── scope ─────────────────────────────────────────────────────────────────────────────────────────
def test_the_authorized_host_and_its_subdomains_are_in_scope():
    assert cr.same_scope("https://app.example.com/x", HOSTS) is True
    assert cr.same_scope("https://api.app.example.com/x", HOSTS) is True


def test_everything_else_is_out_of_scope():
    for url in ("https://example.com/", "https://notapp.example.com/",
                "https://app.example.com.evil.net/", "file:///etc/passwd",
                "http://169.254.169.254/latest/meta-data/"):
        assert cr.same_scope(url, HOSTS) is False


def test_an_off_host_link_is_recorded_rather_than_followed():
    """A scanner that silently drops out-of-scope links looks exactly like one that found nothing
    there. The report has to be able to say what was not tested."""
    pages = {"/": (200, HTML, '<a href="https://elsewhere.example/">out</a>')}

    def fetch(url):  # noqa: ANN001, ANN202
        response = _site(pages)(url)
        return response.status, response.headers, response.body

    result = cr.crawl(["https://app.example.com/"], fetch=fetch, authorized_hosts=HOSTS)
    assert any("elsewhere.example" in url for url in result.out_of_scope)


def test_a_request_outside_scope_is_refused_at_the_last_moment(monkeypatch):
    """The check lives in the one function that can send a packet, so a URL built by a payload, a
    form action or a redirect cannot bypass the crawler's check."""
    sent: list[str] = []
    scanner = ActiveScanner(fetch=_site({}, record=sent), authorized_hosts=HOSTS,
                            rate_per_second=0)
    assert scanner._request("https://evil.example/") is None
    assert sent == []
    assert any("out-of-scope" in e for e in scanner.result.errors)


# ── what the crawler refuses to fetch ─────────────────────────────────────────────────────────────
def test_state_changing_paths_are_never_requested():
    """A crawler that follows `/logout` logs itself out halfway through the scan; one that follows
    `/delete/42` on an app without CSRF protection has just deleted something."""
    body = ('<a href="/logout">out</a><a href="/account/delete/42">x</a>'
            '<a href="/reset">r</a><a href="/reports?id=1">ok</a>')
    fetched: list[str] = []
    pages = {"/": (200, HTML, body), "/reports": (200, HTML, "ok")}

    def fetch(url):  # noqa: ANN001, ANN202
        fetched.append(cr.urlparse(url).path)
        status, hdrs, page = pages.get(cr.urlparse(url).path, (404, HTML, ""))
        return status, hdrs, page

    result = cr.crawl(["https://app.example.com/"], fetch=fetch, authorized_hosts=HOSTS)

    assert "/logout" not in fetched
    assert "/account/delete/42" not in fetched
    assert "/reset" not in fetched
    assert "/reports" in fetched
    assert len(result.skipped_dangerous) == 3


def test_static_assets_are_not_crawled():
    body = '<a href="/app.js">js</a><a href="/logo.png">img</a><a href="/page?x=1">page</a>'
    fetched: list[str] = []

    def fetch(url):  # noqa: ANN001, ANN202
        fetched.append(cr.urlparse(url).path)
        return 200, HTML, body if cr.urlparse(url).path == "/" else "leaf"

    cr.crawl(["https://app.example.com/"], fetch=fetch, authorized_hosts=HOSTS)
    assert "/app.js" not in fetched
    assert "/logo.png" not in fetched
    assert "/page" in fetched


def test_a_page_that_cannot_be_read_is_recorded_not_swallowed():
    def fetch(url):  # noqa: ANN001, ANN202
        raise TimeoutError("read timed out")

    result = cr.crawl(["https://app.example.com/"], fetch=fetch, authorized_hosts=HOSTS)
    assert result.errors and "TimeoutError" in result.errors[0]
    assert result.pages_fetched == 0


# ── parameter discovery ───────────────────────────────────────────────────────────────────────────
def test_query_parameters_become_injection_points():
    target = cr.target_for("https://app.example.com/search?q=shoes&page=2")
    assert {p.name for p in target.params} == {"q", "page"}
    assert target.testable is True


def test_a_get_form_becomes_a_target_with_its_fields():
    body = ('<form action="/search" method="get">'
            '<input name="q" value="term"><input type="submit" value="Go"></form>')
    _, forms = cr.extract("https://app.example.com/", body)
    assert forms[0].url == "https://app.example.com/search"
    assert [p.name for p in forms[0].params] == ["q"]
    assert forms[0].testable is True


def test_a_post_form_is_inventoried_and_never_submitted():
    """Submitting an unknown POST is how a scanner creates users, sends email, or charges a card."""
    body = '<form action="/transfer" method="post"><input name="amount"></form>'
    _, forms = cr.extract("https://app.example.com/", body)
    assert forms[0].method == "POST"
    assert forms[0].testable is False

    sent: list[str] = []
    scanner = ActiveScanner(fetch=_site({}, record=sent), authorized_hosts=HOSTS, rate_per_second=0)
    scanner.result.crawl = cr.CrawlResult(targets=forms)
    for target in forms:
        assert target.testable is False
    assert not any("/transfer?" in url for url in sent)


def test_a_form_submission_carries_every_field_not_just_the_one_under_test():
    """Most applications answer a half-submitted form with a validation page that never reaches the
    code being tested."""
    target = cr.Target(
        url="https://app.example.com/search", method="GET",
        params=(cr.Param("q", "term", "form"), cr.Param("lang", "en", "form")),
    )
    scanner = ActiveScanner(fetch=_site({}), authorized_hosts=HOSTS, rate_per_second=0)
    url = scanner._url_for(target, target.params[0], "PAYLOAD")
    assert "lang=en" in url
    assert "q=PAYLOAD" in url


def test_javascript_and_mailto_links_are_ignored():
    body = '<a href="javascript:void(0)">x</a><a href="mailto:a@b.c">m</a><a href="/ok">ok</a>'
    links, _ = cr.extract("https://app.example.com/", body)
    assert links == ["https://app.example.com/ok"]


# ── url handling ──────────────────────────────────────────────────────────────────────────────────
def test_urls_that_mean_the_same_thing_normalize_to_one():
    assert cr.normalize("https://app.example.com:443/a?b=2&a=1#frag") == \
        cr.normalize("https://APP.example.com/a?a=1&b=2")


def test_replacing_a_parameter_leaves_the_others_alone():
    url = with_param("https://app.example.com/s?q=x&page=3", "q", "PAYLOAD")
    assert "page=3" in url
    assert "q=PAYLOAD" in url
    assert url.count("q=") == 1


# ── budget ────────────────────────────────────────────────────────────────────────────────────────
def test_the_request_budget_is_a_hard_stop():
    budget = Budget(max_requests=3, rate_per_second=0, deadline_seconds=999,
                    clock=lambda: 0.0, sleep=lambda _s: None)
    assert [budget.take() for _ in range(5)] == [True, True, True, False, False]
    assert budget.exhausted is True


def test_the_deadline_is_a_hard_stop():
    now = [0.0]
    budget = Budget(max_requests=999, rate_per_second=0, deadline_seconds=10,
                    clock=lambda: now[0], sleep=lambda _s: None)
    assert budget.take() is True
    now[0] = 11.0
    assert budget.take() is False
    assert budget.expired is True


def test_the_rate_limit_waits_between_requests():
    waited: list[float] = []
    now = [0.0]

    def clock():
        return now[0]

    def sleep(seconds):  # noqa: ANN001
        waited.append(seconds)
        now[0] += seconds

    budget = Budget(max_requests=10, rate_per_second=4.0, deadline_seconds=999,
                    clock=clock, sleep=sleep)
    budget.take()
    budget.take()
    assert waited and abs(waited[0] - 0.25) < 1e-9


def test_a_scan_that_stops_early_says_so():
    """An unbounded application must not produce a scan that looks complete."""
    pages = {"/": (200, HTML, "".join(f'<a href="/p{i}?id={i}">p</a>' for i in range(50)))}
    scanner = ActiveScanner(fetch=_site(pages), authorized_hosts=HOSTS, max_requests=6,
                            rate_per_second=0)
    result = scanner.scan(["https://app.example.com/"], max_pages=40)

    assert result.budget_exhausted or (result.crawl and result.crawl.truncated)
    assert result.degraded is True


# ── end to end against a fake vulnerable app ──────────────────────────────────────────────────────
def _vulnerable_app():
    """One reflected-XSS endpoint, one SQL-error endpoint, and one safe endpoint."""

    def index(_query, _headers):
        return ('<html><body><a href="/search?q=shoes">search</a>'
                '<a href="/item?id=1">item</a><a href="/safe?q=1">safe</a></body></html>')

    def search(query, _headers):
        value = dict(cr.parse_qsl(query)).get("q", "")
        return f"<html><body>Results for {value}</body></html>"  # unescaped → vulnerable

    def item(query, _headers):
        value = dict(cr.parse_qsl(query)).get("id", "")
        if "'" in value:
            return "<html><body>sqlite3.OperationalError: unrecognized token: \"'\"</body></html>"
        return f"<html><body>Item {value}</body></html>"

    def safe(query, _headers):
        import html as h
        value = dict(cr.parse_qsl(query)).get("q", "")
        return f"<html><body>Results for {h.escape(value)}</body></html>"

    return {
        "/": (200, HTML, index),
        "/search": (200, HTML, search),
        "/item": (200, HTML, item),
        "/safe": (200, HTML, safe),
    }


def test_the_scanner_finds_the_planted_flaws_and_nothing_on_the_safe_endpoint():
    scanner = ActiveScanner(fetch=_site(_vulnerable_app()), authorized_hosts=HOSTS,
                            rate_per_second=0, max_requests=500)
    result = scanner.scan(["https://app.example.com/"], max_pages=20)

    fired = {(issue.check_id, issue.url.rsplit("/", 1)[-1].split("?")[0])
             for issue in result.issues}
    assert ("xss-reflected", "search") in fired
    assert ("sqli-error", "item") in fired
    assert not any(url == "safe" for _, url in fired)


def test_every_request_the_scanner_made_was_inside_scope():
    sent: list[str] = []
    scanner = ActiveScanner(fetch=_site(_vulnerable_app(), record=sent), authorized_hosts=HOSTS,
                            rate_per_second=0, max_requests=500)
    scanner.scan(["https://app.example.com/"], max_pages=20)

    assert sent
    assert all(cr.same_scope(url, HOSTS) for url in sent)


def test_the_scan_carries_its_own_coverage_numbers():
    scanner = ActiveScanner(fetch=_site(_vulnerable_app()), authorized_hosts=HOSTS,
                            rate_per_second=0, max_requests=500)
    result = scanner.scan(["https://app.example.com/"], max_pages=20)

    assert result.requests_made > 0
    assert result.parameters_tested >= 3
    assert result.targets_tested >= 3
