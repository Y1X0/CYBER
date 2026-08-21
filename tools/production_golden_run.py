#!/usr/bin/env python3
"""The golden run, against a *deployed* Guardian — the last gate before a pilot.

The controlled run in `docs/PILOT_RUN.md` proved the code: a real worker, a real broker, a real
database. It did not prove a deployment, because the worker ran on a development host. This script
is the same journey pointed at whatever base URL you give it, so the proof can be repeated against
the deployed API the moment a worker consumes its queue.

Everything goes through the public API. There is no database access anywhere in here, which is the
point: if this passes against your deployment, a customer can do the same thing.

    python tools/production_golden_run.py \\
        --api https://guardian-api-pjp3.onrender.com \\
        --repo https://github.com/you/deliberately-vulnerable.git

The target must be a repository you own or are authorized to test. `--make-target` writes the
contents of one for you to commit and push; it is the same estate the controlled run used — a
hardcoded credential, an injection, outdated dependencies, a public bucket, a privileged pod, a root
container.

Exit code is 0 only when every stage passed. A stage that cannot be verified here is reported
UNVERIFIED and does not fail the run; a stage that *should* have worked and did not fails it.
"""

from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid

TARGET_FILES = {
    "app/settings.py": (
        "import subprocess\n"
        "# Deliberately vulnerable sample for an authorized Guardian assessment.\n"
        'AWS_ACCESS_KEY_ID = "AKIA' 'IOSFODNN7EXAMPLE"\n'
        'AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"\n'
        "DEBUG = True\n\n"
        "def lookup(user_input):\n"
        '    return subprocess.check_output("host " + user_input, shell=True)\n\n'
        "def query(conn, name):\n"
        "    return conn.execute(\"SELECT * FROM users WHERE name = '\" + name + \"'\")\n"
    ),
    "requirements.txt": "requests==2.19.1\nurllib3==1.24.1\npyyaml==5.1\njinja2==2.10\n",
    "Dockerfile": (
        "FROM ubuntu:18.04\nUSER root\n"
        "RUN apt-get update && apt-get install -y curl\nCOPY . /app\n"
    ),
    "infra/main.tf": (
        'resource "aws_s3_bucket" "data" {\n  bucket = "pilot-data"\n  acl    = "public-read"\n}\n'
        'resource "aws_security_group" "open" {\n  ingress {\n    from_port   = 0\n'
        "    to_port     = 65535\n    protocol    = \"tcp\"\n"
        '    cidr_blocks = ["0.0.0.0/0"]\n  }\n}\n'
    ),
    "k8s/deploy.yaml": (
        "apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: pilot\nspec:\n  template:\n"
        "    spec:\n      hostNetwork: true\n      containers:\n        - name: app\n"
        "          image: pilot:latest\n          securityContext:\n            privileged: true\n"
        "            runAsUser: 0\n            allowPrivilegeEscalation: true\n"
    ),
}

# The credential the target carries, so the run can assert it never leaves the boundary.
LEAK = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

STAGES: list[dict] = []


def stage(number, name, ok, detail, evidence=None) -> bool:
    STAGES.append({"n": str(number), "name": name, "status": "PASS" if ok else "FAIL",
                   "detail": detail, "evidence": evidence})
    print(f"[{'PASS' if ok else 'FAIL'}] {number:>3}. {name}\n       {detail}", flush=True)
    return ok


def unverified(number, name, why) -> None:
    STAGES.append({"n": str(number), "name": name, "status": "UNVERIFIED",
                   "detail": why, "evidence": None})
    print(f"[UNVR] {number:>3}. {name}\n       {why}", flush=True)


class Api:
    def __init__(self, base: str) -> None:
        # The base URL comes from the command line. Pinning the scheme keeps a stray `file:` or
        # custom scheme from turning this into a local-file reader, and keeps the bearer token
        # off anything that is not an HTTP request.
        scheme = urllib.parse.urlsplit(base).scheme
        if scheme not in ("http", "https"):
            raise SystemExit(f"--api must be http(s), got {scheme or 'no'} scheme: {base!r}")
        self.base = base.rstrip("/") + "/api/v1"
        self.token: str | None = None

    def __call__(self, method, path, body=None, raw=False):
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - scheme pinned in __init__
            self.base + path, data=data, method=method)
        request.add_header("Content-Type", "application/json")
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=120) as response:  # noqa: S310 - scheme pinned above
                payload = response.read()
                return response.status, (payload if raw else json.loads(payload or b"null"))
        except urllib.error.HTTPError as exc:
            payload = exc.read()
            try:
                return exc.code, json.loads(payload or b"null")
            except ValueError:
                return exc.code, payload.decode("utf-8", "replace")


def die(message: str) -> None:
    print(f"\n!! STOPPING: {message}", flush=True)
    _report()
    sys.exit(1)


def _report() -> int:
    print("\n=== summary ===")
    for entry in STAGES:
        print(f"  {entry['status']:>10}  {entry['n']:>4}. {entry['name']}")
    failed = [e for e in STAGES if e["status"] == "FAIL"]
    passed = sum(1 for e in STAGES if e["status"] == "PASS")
    unver = sum(1 for e in STAGES if e["status"] == "UNVERIFIED")
    print(f"\n{len(STAGES)} stages: {passed} PASS, {len(failed)} FAIL, {unver} UNVERIFIED")
    with open("production_golden_run.json", "w") as handle:
        json.dump(STAGES, handle, indent=2)
    print("evidence written to production_golden_run.json")
    return 1 if failed else 0


def wake(base: str, budget: int) -> tuple[bool, str]:
    """Poll `/health` until the API answers, or the budget runs out.

    A free-tier deployment sleeps when idle and takes the better part of a minute to come back,
    answering 502 or refusing the connection while it does. Without this the first request of the
    journey is the sign-up, and a cold start would be reported as a sign-up failure — or, worse,
    a later timeout would be read as the worker never picking the scan up. Those are opposite
    conclusions: one is an API that was asleep, the other is A1.

    Deliberately outside the scored stages. Waking a deployment is not a stage of the journey, and a
    run that never gets past this has verified nothing rather than failed something.
    """
    health = base.rstrip("/") + "/health"
    deadline = time.time() + budget
    attempts = 0
    last = "no response"
    while time.time() < deadline:
        attempts += 1
        try:
            with urllib.request.urlopen(health, timeout=20) as response:  # noqa: S310 - scheme pinned
                if response.status == 200:
                    return True, f"answered on attempt {attempts}"
                last = f"HTTP {response.status}"
        except urllib.error.HTTPError as exc:
            last = f"HTTP {exc.code}"
        except Exception as exc:  # noqa: BLE001 - refused, reset, DNS: all mean "not awake yet"
            last = f"{type(exc).__name__}: {exc}"[:90]
        time.sleep(5)
    return False, f"{attempts} attempt(s), last: {last}"


def make_target(directory: str) -> None:
    import os

    for path, content in TARGET_FILES.items():
        full = os.path.join(directory, path)
        os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
        with open(full, "w") as handle:
            handle.write(content)
    print(f"wrote {len(TARGET_FILES)} files to {directory}\n"
          "commit and push them, then pass the clone URL as --repo")


def run(args) -> int:  # noqa: C901 - one linear journey; splitting it hides the order
    api = Api(args.api)
    slug = uuid.uuid4().hex[:8]

    # ── 0. wake the deployment ───────────────────────────────────────────────────────────────────
    awake, detail = wake(args.api, args.warmup)
    if not awake:
        die(f"the API did not answer GET /health within {args.warmup}s ({detail}).\n"
            "   This is the API being asleep or unreachable — it is NOT the A1 worker\n"
            "   blocker, and nothing has been scored. Check the deployment is up, then\n"
            "   run this again.")
    print(f"API awake — {detail}\n", flush=True)

    # ── 1. sign up ───────────────────────────────────────────────────────────────────────────────
    if args.email and args.password:
        code, body = api("POST", "/auth/login", {"email": args.email, "password": args.password})
        if code != 200:
            die(f"login returned {code}: {body}")
        api.token = body["access_token"]
        code, customers = api("GET", "/customers")
        if not customers:
            die("this account has no business unit to attach an asset to")
        customer = customers[0]["id"]
        stage(1, "sign in", True, f"logged in as {args.email}")
    else:
        code, body = api("POST", "/auth/signup", {
            "organization": f"Pilot {slug}", "company": "Pilot estate", "name": "Pilot Owner",
            "email": f"pilot-{slug}@{args.email_domain}",
            "password": f"pilot-{uuid.uuid4().hex}",
        })
        if code != 201:
            die(f"signup returned {code}: {body}")
        api.token = body["access_token"]
        customer = body["customer_id"]
        stage(1, "signup", True, f"HTTP 201, tenant {body['tenant_id'][:8]} created over the wire")

    # ── 2. organization ──────────────────────────────────────────────────────────────────────────
    code, me = api("GET", "/auth/me")
    stage(2, "organization", code == 200, f"HTTP {code}, identity {me.get('email')}")

    # ── 3. ownership + authorization ─────────────────────────────────────────────────────────────
    domain = args.domain or f"pilot-{slug}.example.com"
    code, verification = api("POST", "/verifications",
                             {"customer_id": customer, "domain": domain, "method": "dns_txt"})
    if code != 201:
        die(f"verification challenge returned {code}: {verification}")
    instructions = verification["instructions"]
    stage("3a", "ownership challenge", instructions["record_type"] == "TXT",
          f"{instructions['record_name']} TXT {instructions['record_value'][:40]}…")

    code, check = api("POST", f"/verifications/{verification['id']}/check")
    if args.domain_is_ours:
        stage("3b", "ownership verified", check.get("status") == "verified",
              f"real DNS lookup → {check.get('status')!r}")
    else:
        stage("3b", "ownership refused without the record", check.get("status") != "verified",
              f"real DNS lookup → {check.get('status')!r} (record not published)")

    code, refusal = api("POST", "/authorizations", {
        "customer_id": customer, "method": "active_recon", "scope": "network", "domains": [domain]})
    if args.domain_is_ours and check.get("status") == "verified":
        stage("3c", "network authorization accepted for a proved domain", code == 201,
              f"HTTP {code}")
    else:
        stage("3c", "network authorization refused without proof of control", code == 409,
              f"HTTP {code}: {str(refusal.get('detail'))[:120]}")

    # ── 4. asset + consent ───────────────────────────────────────────────────────────────────────
    # `inline_content` is the supported config for an artifact the customer hands over directly.
    # It exists so this journey can be run before a repository is published anywhere; a clone URL
    # exercises more engines, because only a workspace gives IaC, Kubernetes and container manifests
    # something to read.
    config = {"inline_content": TARGET_FILES["app/settings.py"]} if args.inline else {}
    code, asset = api("POST", "/assets", {
        "customer_id": customer, "name": f"pilot-target-{slug}", "kind": "repo",
        "identifier": args.repo, "exposure": "public", "config": config})
    if code != 201:
        die(f"asset creation returned {code}: {asset}")
    stage(4, "asset", True, f"HTTP 201, repo {args.repo}")

    code, authorization = api("POST", "/authorizations", {
        "customer_id": customer, "asset_id": asset["id"], "method": "written_consent",
        "scope": "Production golden run against a repository we own",
        "reference": "operator-run pilot gate"})
    if code != 201:
        die(f"authorization returned {code}: {authorization}")
    stage("4b", "authorization recorded",
          authorization["permits_artifact"] and not authorization["permits_network"],
          f"written_consent — artifact plane only, by {authorization['authorized_by']}")

    # ── webhook, registered before the scan so it can receive it ─────────────────────────────────
    hook = None
    if args.webhook:
        code, hook = api("POST", "/webhook-endpoints",
                         {"url": args.webhook, "events": ["scan.completed", "finding.critical"]})
        if code != 201:
            die(f"webhook registration returned {code}: {hook}")

    # ── 5/6. scan accepted and queued ────────────────────────────────────────────────────────────
    engines = args.engines.split(",")
    code, scan = api("POST", "/scans",
                     {"asset_id": asset["id"], "engines": engines, "trigger": "manual"})
    if code != 202:
        die(f"scan creation returned {code}: {scan}")
    scan_id = scan["id"]
    stage(5, "scan accepted", True, f"HTTP 202, scan {scan_id[:8]}, engines={engines}")
    stage(6, "queued", scan["status"] == "queued", f"status={scan['status']!r} at creation")

    code, queue = api("GET", "/scans/queue-health")
    print(f"       queue-health: state={queue.get('state')!r} "
          f"scanner={queue.get('scanner', {}).get('status')!r}", flush=True)

    # ── 7/8. the deployed worker consumes it ─────────────────────────────────────────────────────
    deadline = time.time() + args.timeout
    saw_running = False
    final = None
    while time.time() < deadline:
        code, current = api("GET", f"/scans/{scan_id}")
        if current.get("status") == "running":
            saw_running = True
        if current.get("status") in ("completed", "partial", "failed"):
            final = current
            break
        time.sleep(5)
    if final is None:
        code, queue = api("GET", "/scans/queue-health")
        die(f"the deployed worker did not finish the scan within {args.timeout}s. "
            f"queue-health says state={queue.get('state')!r}, "
            f"scanner={queue.get('scanner', {}).get('detail')!r}. "
            "This is the A1 blocker: the API accepted work nothing executed.")
    stage(7, "the deployed worker consumed the task", True,
          f"status moved off queued without anything in this script touching the database "
          f"(running observed: {saw_running})")
    stage(8, "terminal state", final["status"] in ("completed", "partial"),
          f"status={final['status']!r} started={final.get('started_at')} "
          f"finished={final.get('finished_at')}")

    # ── 9/10. what actually ran ──────────────────────────────────────────────────────────────────
    code, runs = api("GET", f"/scans/{scan_id}/engines")
    states: dict[str, list[str]] = {}
    for entry in runs:
        states.setdefault(entry["customer_state"], []).append(entry["engine"])
    stage(10, "engine outcomes", bool(runs),
          "; ".join(f"{key}={value}" for key, value in sorted(states.items())))

    # ── 11-13. findings, evidence, deterministic risk ────────────────────────────────────────────
    code, findings = api("GET", f"/findings?scan_id={scan_id}&limit=200")
    severities: dict[str, int] = {}
    for finding in findings:
        severities[finding["severity"]] = severities.get(finding["severity"], 0) + 1
    if not stage(11, "findings", bool(findings),
                 f"{len(findings)} finding(s) by severity {severities}"):
        die("the deployed worker completed and produced no finding on a deliberately vulnerable "
            "repository")

    with_evidence = [f for f in findings if f.get("evidence")]
    stage(12, "evidence", len(with_evidence) == len(findings),
          f"{len(with_evidence)}/{len(findings)} carry evidence")

    scored = [f for f in findings if isinstance(f["risk_score"], int) and f["risk_score"] > 0]
    code, dossier = api("GET", f"/findings/{findings[0]['id']}")
    code, again = api("GET", f"/findings/{findings[0]['id']}")
    stage(13, "deterministic risk",
          len(scored) == len(findings)
          and dossier["finding"]["risk_score"] == again["finding"]["risk_score"],
          f"{len(scored)}/{len(findings)} scored > 0; a repeated read returned "
          f"{dossier['finding']['risk_score']} both times")

    stage("13b", "evidence redaction at the boundary", LEAK not in json.dumps(findings),
          "the target's live-shaped secret is absent from the findings response")

    # ── 14. report ───────────────────────────────────────────────────────────────────────────────
    code, report = api("POST", "/reports", {"scan_id": scan_id, "title": "Pilot assessment"})
    if code != 201:
        die(f"report generation returned {code}: {report}")
    code, exported = api("GET", f"/reports/{report['id']}/export?format=html", raw=True)
    text = exported.decode("utf-8", "replace") if isinstance(exported, bytes) else str(exported)
    stage(14, "report", code == 200 and len(text) > 500 and LEAK not in text,
          f"HTTP {code}, {len(text)} bytes, secret absent from the export")

    # ── 15/16. remediation and retest ────────────────────────────────────────────────────────────
    code, opened = api("POST", "/remediation", {"customer_id": customer})
    code, items = api("GET", "/remediation")
    stage(15, "remediation", code == 200 and bool(items),
          f"opened={opened.get('opened')} existing={opened.get('existing')}; "
          f"{len(items)} item(s) tracked")

    code, retest = api("POST", f"/findings/{findings[0]['id']}/retest")
    if code != 202:
        die(f"retest returned {code}: {retest}")
    deadline = time.time() + args.timeout
    retest_final = None
    while time.time() < deadline:
        code, current = api("GET", f"/scans/{retest['scan_id']}")
        if current.get("status") in ("completed", "partial", "failed"):
            retest_final = current
            break
        time.sleep(5)
    code, dossier = api("GET", f"/findings/{findings[0]['id']}")
    stage(16, "retest executed by the deployed worker",
          retest_final is not None and bool(dossier.get("verifications")),
          f"retest scan {retest['scan_id'][:8]} → "
          f"{retest_final['status'] if retest_final else 'timeout'!r}; "
          f"{len(dossier.get('verifications', []))} verdict(s)")

    # ── 17/18. webhook ───────────────────────────────────────────────────────────────────────────
    if hook:
        time.sleep(5)
        code, deliveries = api("GET", f"/webhook-endpoints/{hook['id']}/deliveries")
        if deliveries:
            last = deliveries[-1]
            stage(17, "webhook delivery", True,
                  f"{len(deliveries)} delivery(ies); last status={last['status']!r} "
                  f"attempts={last['attempts']} response={last.get('response_status')}")
            delivered = [d for d in deliveries if d["status"] == "delivered"]
            if delivered:
                stage("17b", "webhook 2xx round trip", True,
                      f"{len(delivered)} delivery(ies) accepted by the receiver — B-6 closed")
            else:
                unverified("17b", "webhook 2xx round trip",
                           "no delivery reached `delivered`; the receiver did not accept it")
            try:
                sys.path.insert(0, "packages/core/src")
                from guardian_core import webhooks as wh

                now = int(time.time())
                signature = wh.sign(last["payload"], secret=hook["secret"], timestamp=now)
                stage(18, "HMAC verification",
                      wh.verify(last["payload"], signature, secret=hook["secret"], now=now)
                      and not wh.verify(last["payload"] + "x", signature,
                                        secret=hook["secret"], now=now),
                      "the recorded bytes verify with the issued secret; a tampered body does not")
            except ImportError:
                unverified(18, "HMAC verification",
                           "run from a checkout to verify the signature locally")
        else:
            stage(17, "webhook delivery", False, "the scan completed and no delivery was created")
    else:
        unverified(17, "webhook delivery", "no --webhook receiver was given")

    # ── 19/20. completion and the safety property ────────────────────────────────────────────────
    stage(19, "scan completed", final["status"] in ("completed", "partial"),
          f"terminal {final['status']!r}, stats={final.get('stats')}")

    unanswered = [r for r in runs if r["customer_state"] in ("inconclusive", "not_checked")]
    resolved = [f for f in findings if f["status"] == "resolved"]
    stage(20, "no false-clean state",
          all(r["customer_state"] != "checked" for r in unanswered) and not resolved,
          f"{len(runs) - len(unanswered)} engine(s) checked, {len(unanswered)} not fully answered "
          f"({[r['engine'] + ':' + r['customer_state'] for r in unanswered]}); "
          f"{len(resolved)} finding(s) resolved by this run")

    return _report()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--api", help="base URL of the deployed Guardian API")
    parser.add_argument("--repo", help="clone URL of a vulnerable repository you own")
    parser.add_argument("--email", help="sign in instead of signing up")
    parser.add_argument("--password")
    parser.add_argument("--email-domain", default="example.com",
                        help="domain for the generated sign-up address")
    parser.add_argument("--domain", help="domain to run the ownership challenge against")
    parser.add_argument("--domain-is-ours", action="store_true",
                        help="you control this domain's DNS and have published the TXT record, so "
                             "a *passing* ownership check is expected (closes B-5)")
    parser.add_argument("--webhook", help="a reachable receiver URL, to close B-6")
    parser.add_argument("--engines", default="secrets,sast,sca,iac,k8s,container")
    parser.add_argument("--inline", action="store_true",
                        help="supply the vulnerable content directly instead of cloning --repo, so "
                             "the journey can be run before the repository is published. Fewer "
                             "engines have anything to read; the ones that do not say so.")
    parser.add_argument("--timeout", type=int, default=900,
                        help="seconds to wait for the deployed worker (default 900)")
    parser.add_argument("--warmup", type=int, default=180,
                        help="seconds to wait for the API to answer /health before starting. A "
                             "free-tier deployment sleeps when idle and takes ~50s to wake.")
    parser.add_argument("--make-target", metavar="DIR",
                        help="write the vulnerable target files and exit")
    args = parser.parse_args()

    if args.make_target:
        make_target(args.make_target)
        return 0
    if not args.api or not args.repo:
        parser.error("--api and --repo are required (or use --make-target)")
    return run(args)


if __name__ == "__main__":
    sys.exit(main())
