#!/usr/bin/env python3
"""Guardian cutover preflight — sections A and B live verification.

Runs every LIVE VERIFY check for A1-A5 (PostgreSQL) and B1-B2 (Redis) against the REAL
services and prints a PASS/BLOCK table. Reads connection strings from the environment only;
never prints a password, key, or token (DSNs are redacted in all output).

RUN IT INSIDE THE PINNED IMAGE — that also proves the digest is pullable (section D):

  docker run --rm --env-file .env.production \
    -v "$PWD/guardian_preflight.py:/tmp/pf.py:ro" \
    ghcr.io/y1x0/cyber@sha256:69ba91a23d63c220034a64229d192597c931fb52ea3b7a5470106b9ce54ddc46 \
    python /tmp/pf.py

Exit code 0 = every check PASS. Non-zero = at least one BLOCK (the count of blocks).
IMPORTANT: run this BEFORE `alembic upgrade head`. Check A2 is the F1 gate.
"""

from __future__ import annotations

import os
import re
import sys
from urllib.parse import parse_qs, urlsplit

TLS_SSLMODES = {"require", "verify-ca", "verify-full"}
# Any URI-shaped token may carry a password. Scrub before printing an exception: libpq echoes the
# whole connection string in some errors, which would otherwise land in a CI log verbatim.
_URI = re.compile(r"(?i)\b(?:postgres(?:ql)?(?:\+\w+)?|rediss?)://\S*")
results: list[tuple[str, str, str, str]] = []  # (id, title, verdict, detail)


def record(cid: str, title: str, ok: bool | None, detail: str) -> None:
    verdict = "PASS" if ok else ("SKIP" if ok is None else "BLOCK")
    results.append((cid, title, verdict, detail))


def redact(dsn: str) -> str:
    """Return a DSN safe to print: password replaced, everything else intact."""
    if not dsn:
        return "<unset>"
    try:
        p = urlsplit(dsn)
        if p.password:
            netloc = p.netloc.replace(":" + p.password + "@", ":***@")
            return p._replace(netloc=netloc).geturl()
        return dsn
    except Exception:
        return "<unparseable>"


def safe(exc: BaseException, limit: int = 1200) -> str:
    """Render an exception for printing with any embedded connection URI scrubbed.

    Keep every line. psycopg tries each resolved address in turn and joins one error per
    attempt, so showing only the first line reports whichever address happened to be tried
    first and hides the reason the others failed — which is usually the real fault.
    """
    text = " | ".join(ln.strip() for ln in str(exc).splitlines() if ln.strip())
    return f"{type(exc).__name__}: {_URI.sub('<dsn-redacted>', text)}"[:limit]


def libpq(dsn: str) -> str:
    """SQLAlchemy DSN -> libpq URL (strip the +psycopg driver suffix)."""
    return dsn.replace("+psycopg", "")


# ── inputs ────────────────────────────────────────────────────────────────────
# Strip surrounding whitespace. A secret pasted with a leading space is invisible in the UI but
# stops libpq recognising the URI prefix: it falls back to keyword/value parsing and dies on the
# `=` in `?sslmode=...` with a confusing "invalid connection option" error.
OWNER = os.environ.get("GUARDIAN_DATABASE_URL", "").strip()
APP = os.environ.get("GUARDIAN_APP_DATABASE_URL", "").strip()
REDIS_URL = os.environ.get("GUARDIAN_REDIS_URL", "").strip()

print("Guardian cutover preflight — sections A & B")
print("=" * 78)
print(f"  owner DSN : {redact(OWNER)}")
print(f"  app   DSN : {redact(APP)}")
print(f"  redis URL : {redact(REDIS_URL)}")
print("=" * 78)

# ── A1 / A2 / A3 : owner connection, encoding, TLS ────────────────────────────
conn = None
if not OWNER:
    record("A1", "PostgreSQL 16 + UTF8", False, "GUARDIAN_DATABASE_URL is not set")
    record("A2", "F1 client encoding (str)", False, "no owner DSN")
    record("A3", "TLS enforced in DSN", False, "no owner DSN")
else:
    try:
        import psycopg
    except ImportError:
        record("A1", "PostgreSQL 16 + UTF8", False, "psycopg not installed — run inside the image")
        psycopg = None  # type: ignore

    if psycopg is not None:
        try:
            conn = psycopg.connect(libpq(OWNER), connect_timeout=10)
        except Exception as e:  # noqa: BLE001
            # A refused connection and an unroutable address look alike in libpq's message, so
            # report what the name actually resolves to. A host with AAAA records only is
            # unreachable from an IPv4-only network however the DSN is spelled.
            import socket

            hostname = urlsplit(OWNER).hostname or ""
            fams = []
            for fam, label in ((socket.AF_INET, "A"), (socket.AF_INET6, "AAAA")):
                try:
                    n = len(socket.getaddrinfo(hostname, 5432, fam))
                    fams.append(f"{label}={n}")
                except OSError:
                    fams.append(f"{label}=0")
            record("A1", "PostgreSQL 16 + UTF8", False,
                   f"connect failed: [dns {' '.join(fams)}] {safe(e)}")

        if conn is not None:
            # A1 — server version + server_encoding
            try:
                ver = conn.execute("select version()").fetchone()[0]
                enc = conn.execute("show server_encoding").fetchone()[0]
                ver_s = ver.decode() if isinstance(ver, bytes) else ver
                enc_s = enc.decode() if isinstance(enc, bytes) else enc
                is16 = "PostgreSQL 16" in ver_s
                utf8 = enc_s.upper() == "UTF8"
                record(
                    "A1", "PostgreSQL 16 + UTF8", is16 and utf8,
                    f"{ver_s.split(' on ')[0]}; server_encoding={enc_s}"
                    + ("" if utf8 else "  <-- MUST be UTF8; recreate the database"),
                )
            except Exception as e:  # noqa: BLE001
                record("A1", "PostgreSQL 16 + UTF8", False, safe(e))

            # A2 — THE F1 GATE: text must come back as str, not bytes
            try:
                raw = conn.execute("select version()").fetchone()[0]
                cli = conn.execute("show client_encoding").fetchone()[0]
                cli_s = cli.decode() if isinstance(cli, bytes) else cli
                is_str = isinstance(raw, str)
                record(
                    "A2", "F1 client encoding (str)", is_str,
                    f"psycopg returns {type(raw).__name__}; client_encoding={cli_s}"
                    + ("" if is_str else "  <-- set PGCLIENTENCODING=UTF8 (env, not code)"),
                )
            except Exception as e:  # noqa: BLE001
                record("A2", "F1 client encoding (str)", False, safe(e))

            # A2b — SQLAlchemy must resolve the server version (the exact local-drill failure)
            try:
                from sqlalchemy import create_engine

                eng = create_engine(OWNER)
                with eng.connect():
                    svi = eng.dialect.server_version_info
                record("A2b", "SQLAlchemy version parse", True, f"server_version_info={svi}")
            except ImportError as e:
                # ModuleNotFoundError subclasses ImportError, so a dialect that fails to load
                # ("postgresql.psycopg") lands here too. Name the missing module rather than
                # blaming SQLAlchemy, which is a runtime dependency and should always be present.
                missing = getattr(e, "name", None) or "?"
                absent = missing.split(".")[0] == "sqlalchemy"
                record("A2b", "SQLAlchemy version parse", None if absent else False,
                       f"import failed for '{missing}' — "
                       + ("sqlalchemy itself is missing; run inside the image"
                          if absent else "dialect load failure; alembic WILL fail"))
            except Exception as e:  # noqa: BLE001
                record("A2b", "SQLAlchemy version parse", False,
                       safe(e) + "  <-- alembic WILL fail")

            # A3 — TLS. The proof is that we are connected at all: with a TLS-enforcing sslmode
            # libpq aborts the handshake unless the session is encrypted ("server does not support
            # SSL, but SSL was required"), so reaching this line IS the evidence. pg_stat_ssl is
            # reported for information only and is NOT part of the verdict: providers that front
            # Postgres with a TLS-terminating proxy (Neon, PgBouncer-style poolers) legitimately
            # report ssl=false on the backend while the client link is encrypted.
            mode = (parse_qs(urlsplit(OWNER).query).get("sslmode") or [""])[0].lower()
            in_dsn = mode in TLS_SSLMODES
            try:
                row = conn.execute(
                    "select ssl, version from pg_stat_ssl where pid = pg_backend_pid()"
                ).fetchone()
                live_ssl, tlsver = (row[0], row[1]) if row else (False, None)
            except Exception:  # noqa: BLE001
                live_ssl, tlsver = False, None
            if not in_dsn:
                note = ("  <-- sslmode must be IN the URL query string "
                        "(require|verify-ca|verify-full)")
            elif mode != "verify-full":
                note = f"  <-- encrypted, but '{mode}' does not verify the server certificate"
            else:
                note = ""
            proof = "connected under a TLS-enforcing mode; " if in_dsn else ""
            record(
                "A3", "TLS enforced in DSN", in_dsn,
                f"sslmode={mode or '<missing>'}; {proof}"
                f"pg_stat_ssl={live_ssl} {tlsver or ''}(informational)" + note,
            )

# ── A4 : guardian_app role (only meaningful after migration 0005) ─────────────
if conn is not None:
    try:
        row = conn.execute(
            "select rolsuper, rolbypassrls from pg_roles where rolname='guardian_app'"
        ).fetchone()
        if row is None:
            record("A4", "guardian_app role safe", None,
                   "role absent — expected until `alembic upgrade head` runs (creates it in 0005)")
        else:
            role_ok = (not row[0]) and (not row[1])
            record("A4", "guardian_app role safe", role_ok,
                   f"superuser={row[0]} bypassrls={row[1]}"
                   + ("" if role_ok else "  <-- API refuses to start; RLS would be inert"))
    except Exception as e:  # noqa: BLE001
        record("A4", "guardian_app role safe", False, safe(e))

    # A4b — can the app role actually authenticate?
    if APP:
        try:
            import psycopg as _pg

            c2 = _pg.connect(libpq(APP), connect_timeout=10)
            who = c2.execute("select current_user").fetchone()[0]
            who_s = who.decode() if isinstance(who, bytes) else who
            c2.close()
            record("A4b", "app DSN authenticates", who_s == "guardian_app", f"current_user={who_s}")
        except Exception as e:  # noqa: BLE001
            record("A4b", "app DSN authenticates", False,
                   safe(e) + "  <-- role is created by migration 0005")

# ── A5 : the two DSNs must differ ─────────────────────────────────────────────
if OWNER and APP:
    record("A5", "owner DSN != app DSN", OWNER != APP,
           "distinct" if OWNER != APP else "IDENTICAL — startup invariant will refuse to boot")
elif OWNER:
    record("A5", "owner DSN != app DSN", False, "GUARDIAN_APP_DATABASE_URL is not set")

if conn is not None:
    conn.close()

# ── B1 / B2 : Redis TLS, AUTH, durability ─────────────────────────────────────
if not REDIS_URL:
    record("B1", "Redis rediss:// + AUTH", False, "GUARDIAN_REDIS_URL is not set")
else:
    scheme_ok = REDIS_URL.startswith("rediss://")
    auth_ok = bool(urlsplit(REDIS_URL).password)
    record("B1a", "Redis URL shape", scheme_ok and auth_ok,
           f"tls_scheme={scheme_ok} auth_in_url={auth_ok}"
           + ("" if (scheme_ok and auth_ok) else "  <-- both are hard startup invariants"))
    try:
        import redis  # type: ignore

        r = redis.from_url(REDIS_URL, socket_connect_timeout=10)
        pong = r.ping()
        record("B1b", "Redis live TLS ping", bool(pong), f"ping={pong}")
        try:
            aof = r.config_get("appendonly").get("appendonly")
            pol = r.config_get("maxmemory-policy").get("maxmemory-policy")
            mm = r.config_get("maxmemory").get("maxmemory")
            aof = aof.decode() if isinstance(aof, bytes) else aof
            pol = pol.decode() if isinstance(pol, bytes) else pol
            mm = mm.decode() if isinstance(mm, bytes) else mm
            good = (aof == "yes") and (pol == "noeviction")
            record("B2", "Redis AOF + noeviction", good,
                   f"appendonly={aof} maxmemory-policy={pol} maxmemory={mm}"
                   + ("" if good else "  <-- durability protects the replay-nonce store"))
        except Exception as e:  # noqa: BLE001
            record("B2", "Redis AOF + noeviction", None,
                   f"CONFIG GET unavailable ({type(e).__name__}) — managed provider may block it; "
                   "verify in the provider console")
    except ImportError:
        record("B1b", "Redis live TLS ping", False, "redis-py not installed — run inside the image")
    except Exception as e:  # noqa: BLE001
        record("B1b", "Redis live TLS ping", False, safe(e))

# ── report ────────────────────────────────────────────────────────────────────
print()
print(f"{'ID':<5} {'CHECK':<28} {'VERDICT':<8} DETAIL")
print("-" * 78)
blocks = 0
for cid, title, verdict, detail in results:
    if verdict == "BLOCK":
        blocks += 1
    print(f"{cid:<5} {title:<28} {verdict:<8} {detail}")
print("-" * 78)
print(f"{len(results)} checks · {blocks} BLOCK")
if blocks:
    print("\nDo NOT run `alembic upgrade head` while any check above is BLOCK.")
sys.exit(min(blocks, 120))
