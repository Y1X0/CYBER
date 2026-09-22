# SAST taint analysis (Python) — sources, sinks, sanitizers

Guardian's SAST engine runs a **real source→sink taint dataflow analysis** for Python
(`guardian_scanner/sast/taint.py`): AST-based, with import-alias resolution, an interprocedural
fixpoint over local functions, and **per-CWE sanitizers**. It answers "does attacker-controlled data
reach a dangerous operation, and was it neutralized on the way?" and reports the path it took — not
"is the text `eval(` present" (that's the separate regex pattern layer). The catalogue lives as data
in `guardian_scanner/sast/catalog.py`, so adding a sink is a table edit.

## FP posture (unchanged by this batch)

- **Unknown free function stops taint** (`clean(x)` is usually a validator); an unknown **method**
  does not (`x.strip()` can't launder its receiver).
- **A proven sanitizer on the path suppresses the finding** — and sanitizers are class-specific
  (`html.escape` clears XSS, not command injection).
- **A sink fires only on a real taint FLOW**, never on "the function is called."
- Literals/constants are not sources; `sys.argv` and route parameters are weaker sources (medium).
- Test files are demoted; `# nosec` suppresses, `# noqa` does not.

## Sinks

| Sink id | CWE | Class | Base severity | Matched by |
|---|---|---|---|---|
| `taint-code-exec` | CWE-95 | code evaluation (`eval`/`exec`/`compile`) | CRITICAL | dotted |
| `taint-shell-command` | CWE-78 | shell (`os.system`/`os.popen`) | CRITICAL | dotted |
| `taint-subprocess-shell` | CWE-78 | subprocess `shell=True` | CRITICAL | dotted + kwarg |
| `taint-subprocess-argv` | CWE-78 | subprocess program name | HIGH | dotted (argv[0] only) |
| `taint-sql` | CWE-89 | SQL (`cursor.execute`, `sqlalchemy.text`) | CRITICAL | dotted + method |
| `taint-deserialization` | CWE-502 | `pickle`/`yaml.load`/`marshal` | CRITICAL | dotted |
| `taint-path` | CWE-22 | filesystem path | HIGH | dotted + method |
| `taint-ssrf` | CWE-918 | outbound request URL | HIGH | dotted + `url=` |
| `taint-open-redirect` | CWE-601 | redirect target | MEDIUM | dotted |
| `taint-ssti` | CWE-1336 | template compiler | CRITICAL | dotted |
| `taint-xss` | CWE-79 | `Markup`/`mark_safe` | HIGH | dotted |
| **`taint-log-injection`** | **CWE-117** | logging call | **HIGH** | dotted (`logging.*`) + method (`log.info`/…) |
| **`taint-nosql`** | **CWE-943** | MongoDB/pymongo query | **CRITICAL → HIGH** | method (`find_one`/`update_one`/…) |
| **`taint-ldap`** | **CWE-90** | LDAP search filter | **HIGH → MEDIUM** | method (`search_s`/`search`) + `filterstr`/`search_filter` |

Rows in **bold** are added in this batch. Where a sink is matched only by an object **method** (the
receiver's type is unknown), the finding is reported at **medium confidence**, which lowers the
reported severity one step — so NoSQL (base CRITICAL) reports as HIGH and LDAP (base HIGH) as MEDIUM,
exactly as the existing SQL cursor sink reports as HIGH.

### The three new sinks

1. **Log injection (CWE-117, HIGH).** Tainted data reaching `logging.*` (module functions, dotted →
   HIGH) or a logger object's `debug/info/warning/error/critical/exception/log` method (medium). Any
   argument written into the log line counts — embedded CR/LF let an attacker forge log entries.
   *Sanitizer:* percent-encoding (`urllib.parse.quote`) or any type coercion.

2. **NoSQL injection (CWE-943, HIGH).** Tainted data that controls a pymongo query's **structure** —
   `find_one({"$where": user})`, a dynamic operator key `{user_key: 1}`, or the whole query
   `find_one(request.json)`. A **parameterized** query `find_one({"_id": user})` compares `user` as a
   value and is recognized as safe (it yields no dangerous sub-expression). Bare `.find()` is
   deliberately excluded (it collides with `str.find`); `find_one` and the typed `*_one`/`*_many`
   variants are covered. *Sanitizer:* parameterization, or typing the value (`ObjectId(user)`,
   `int(user)`).

3. **LDAP injection (CWE-90, MEDIUM).** Tainted data in an LDAP search filter — python-ldap
   `search_s(base, scope, filterstr)` (filter = 3rd arg or `filterstr=`) and ldap3 `search(...,
   search_filter=...)`. `re.search(pattern, text)` cannot fire: it has neither a 3rd positional
   argument nor a filter keyword. *Sanitizer:* `ldap.filter.escape_filter_chars` /
   `ldap3.utils.conv.escape_filter_chars`.

## Sanitizers (per-CWE)

| id | Functions | Neutralizes |
|---|---|---|
| `coerce` | `int`/`float`/`bool`/`uuid.UUID`/`ipaddress.ip_address`/`bson.ObjectId` | all classes (result is typed, not a string) |
| `shell-quote` | `shlex.quote`/`pipes.quote` | CWE-78 |
| `html-escape` | `html.escape`/`markupsafe.escape`/`bleach.clean` | CWE-79 |
| `url-quote` | `urllib.parse.quote`/`quote_plus` | CWE-601, **CWE-117** |
| `basename` | `os.path.basename` | CWE-22 |
| `regex-escape` | `re.escape` | CWE-95 |
| **`ldap-escape`** | `ldap.filter.escape_filter_chars`/`ldap3.utils.conv.escape_filter_chars` | **CWE-90** |

## Scope of this batch

Extends the **existing Python taint engine** with the three sinks above only. It does **not** touch
the regex pattern rules (which cover JS/TS/Java/Go/PHP/Ruby/C# as "construct present" at medium
confidence), and does **not** add JS/TS taint (a separate, larger effort). NoSQL `aggregate`/`distinct`
(differently-shaped injectable arguments) and update-document operator injection are deliberate
follow-ups, kept out to hold the false-positive rate down.
