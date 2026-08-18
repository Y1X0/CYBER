"""SAST v2 — taint analysis (WP-D4).

The value of this engine is not that it finds `eval(`. It is that it can tell `eval("1+1")` from
`eval(request.args["expr"])` and can say, with a trace, how the second one got there. So the tests
that matter most are the ones about *discrimination*:

  * a literal argument is not a vulnerability, and reporting it as one is how a scanner loses its
    reader;
  * `html.escape` does not make a shell command safe, and a scanner that thinks it does will clear
    a live remote-code-execution finding;
  * `subprocess.run(["ls", user_input])` is not command injection — there is no shell to inject
    into — while `subprocess.run([user_input, "-l"])` is;
  * a rename (`import os as o`) must not defeat detection, because renaming is the first thing
    anyone hiding something does.
"""

from __future__ import annotations

from guardian_core.enums import EngineKey, Severity
from guardian_scanner.engines.sast_engine import SastEngine
from guardian_scanner.sast.masking import mask_non_code, suppressed_lines
from guardian_scanner.sast.taint import analyze_python


def flows(source: str, path: str = "app.py"):
    return analyze_python(source, path)


def rule_ids(source: str) -> set[str]:
    return {f.sink.id for f in flows(source)}


def engine_findings(source: str, path: str = "app.py"):
    """Run the whole engine over one file, the way a scan does."""
    engine = SastEngine()
    return list(engine._scan_file(path, source, path[path.rfind(".") :]))  # noqa: SLF001


# ── the core discrimination: is the data attacker-controlled? ─────────────────────────────────────
def test_tainted_eval_is_a_confirmed_flow():
    found = flows(
        "from flask import request\n"
        "def handler():\n"
        "    expr = request.args['expr']\n"
        "    return eval(expr)\n"
    )
    assert [f.sink.id for f in found] == ["taint-code-exec"]
    hit = found[0]
    assert hit.severity is Severity.CRITICAL
    assert hit.confidence == "high"
    assert hit.line == 4
    assert [step.what for step in hit.trace][0] == "source"
    assert [step.what for step in hit.trace][-1] == "sink"


def test_a_literal_argument_is_not_a_flow():
    """`eval("1+1")` is not a vulnerability. v1 could not tell the difference; v2 must."""
    assert flows("def f():\n    return eval('1+1')\n") == []


def test_the_pattern_rule_still_reports_the_literal_but_at_lower_confidence():
    """The construct is worth noting; it is not worth a critical."""
    results = engine_findings("def f():\n    return eval('1+1')\n")
    assert [f.location["rule"] for f in results] == ["py-eval"]
    assert results[0].confidence == "medium"
    assert results[0].base_severity is Severity.MEDIUM


def test_a_proven_flow_replaces_the_pattern_finding_rather_than_duplicating_it():
    results = engine_findings(
        "from flask import request\n"
        "def handler():\n"
        "    return eval(request.args['x'])\n"
    )
    assert [f.location["rule"] for f in results] == ["taint-code-exec"]
    assert results[0].base_severity is Severity.CRITICAL
    assert results[0].engine is EngineKey.SAST


# ── sanitizers are class-specific ─────────────────────────────────────────────────────────────────
def test_shlex_quote_clears_a_command_injection():
    assert (
        rule_ids(
            "import os, shlex\n"
            "from flask import request\n"
            "def h():\n"
            "    os.system('ls ' + shlex.quote(request.args['d']))\n"
        )
        == set()
    )


def test_html_escape_does_not_clear_a_command_injection():
    """The finding that gets a scanner uninstalled is the live RCE it cleared because the developer
    remembered to HTML-escape. Sanitization is per class or it is meaningless."""
    assert rule_ids(
        "import os, html\n"
        "from flask import request\n"
        "def h():\n"
        "    os.system('ls ' + html.escape(request.args['d']))\n"
    ) == {"taint-shell-command"}


def test_html_escape_does_clear_a_markup_sink():
    assert (
        rule_ids(
            "import html\n"
            "from flask import request\n"
            "from markupsafe import Markup\n"
            "def h():\n"
            "    return Markup(html.escape(request.args['name']))\n"
        )
        == set()
    )


def test_type_coercion_clears_every_class():
    assert (
        rule_ids(
            "import os\n"
            "from flask import request\n"
            "def h():\n"
            "    os.system('kill -9 ' + str(int(request.args['pid'])))\n"
        )
        == set()
    )


# ── subprocess: the argv/shell distinction ────────────────────────────────────────────────────────
def test_user_input_as_an_argv_entry_is_not_command_injection():
    """`run(["ls", user])` cannot start a second command. Calling it injection is a false positive,
    and false positives are what stop a report from being read."""
    assert (
        rule_ids(
            "import subprocess\n"
            "from flask import request\n"
            "def h():\n"
            "    subprocess.run(['ls', request.args['d']])\n"
        )
        == set()
    )


def test_user_input_as_the_program_name_is_reported():
    assert rule_ids(
        "import subprocess\n"
        "from flask import request\n"
        "def h():\n"
        "    subprocess.run([request.args['cmd'], '-l'])\n"
    ) == {"taint-subprocess-argv"}


def test_shell_true_with_user_input_is_critical():
    found = flows(
        "import subprocess\n"
        "from flask import request\n"
        "def h():\n"
        "    subprocess.run(f\"ls {request.args['d']}\", shell=True)\n"
    )
    assert [f.sink.id for f in found] == ["taint-subprocess-shell"]
    assert found[0].severity is Severity.CRITICAL


def test_shell_true_is_reported_once_not_twice():
    """Two sinks match `subprocess.run`; only the one describing the actual danger should fire."""
    found = flows(
        "import subprocess\n"
        "from flask import request\n"
        "def h():\n"
        "    subprocess.run(request.args['c'], shell=True)\n"
    )
    assert len(found) == 1


# ── renames must not defeat detection ─────────────────────────────────────────────────────────────
def test_module_alias_is_resolved():
    assert rule_ids(
        "import os as o\n"
        "from flask import request\n"
        "def h():\n"
        "    o.system(request.args['c'])\n"
    ) == {"taint-shell-command"}


def test_from_import_alias_is_resolved():
    assert rule_ids(
        "from os import system as run_it\n"
        "from flask import request\n"
        "def h():\n"
        "    run_it(request.args['c'])\n"
    ) == {"taint-shell-command"}


# ── propagation rules ─────────────────────────────────────────────────────────────────────────────
def test_a_method_call_cannot_launder_taint():
    assert rule_ids(
        "import os\n"
        "from flask import request\n"
        "def h():\n"
        "    value = request.args['c'].strip().lower()\n"
        "    os.system(value)\n"
    ) == {"taint-shell-command"}


def test_an_unknown_free_function_stops_the_taint():
    """A documented trade-off: `clean(x)` is far more often a validator than a passthrough, and
    guessing the other way manufactures false positives across every codebase that has one."""
    assert (
        rule_ids(
            "import os\n"
            "from flask import request\n"
            "def h():\n"
            "    os.system(validate(request.args['c']))\n"
        )
        == set()
    )


def test_fstring_interpolation_propagates():
    assert rule_ids(
        "import os\n"
        "from flask import request\n"
        "def h():\n"
        "    os.system(f\"ping {request.args['host']}\")\n"
    ) == {"taint-shell-command"}


def test_both_branches_of_a_conditional_contribute():
    assert rule_ids(
        "import os\n"
        "from flask import request\n"
        "def h(flag):\n"
        "    target = 'localhost'\n"
        "    if flag:\n"
        "        target = request.args['host']\n"
        "    os.system('ping ' + target)\n"
    ) == {"taint-shell-command"}


def test_a_loop_variable_inherits_the_iterable_taint():
    assert rule_ids(
        "import os\n"
        "from flask import request\n"
        "def h():\n"
        "    for name in request.args.getlist('n'):\n"
        "        os.system('id ' + name)\n"
    ) == {"taint-shell-command"}


# ── inter-procedural ──────────────────────────────────────────────────────────────────────────────
def test_taint_is_followed_into_a_local_helper():
    """The flow a regex scanner can never see: neither line contains both the source and the sink."""
    found = flows(
        "import os\n"
        "from flask import request\n"
        "def run_command(cmd):\n"
        "    os.system(cmd)\n"
        "def handler():\n"
        "    run_command(request.args['c'])\n"
    )
    assert [f.sink.id for f in found] == ["taint-shell-command"]
    assert found[0].interprocedural is True
    assert [step.what for step in found[0].trace][-2:] == ["call", "sink"]


def test_a_helper_that_returns_the_value_propagates_it():
    assert rule_ids(
        "import os\n"
        "from flask import request\n"
        "def normalize(value):\n"
        "    return value.strip()\n"
        "def handler():\n"
        "    os.system(normalize(request.args['c']))\n"
    ) == {"taint-shell-command"}


def test_a_helper_that_sanitizes_breaks_the_flow():
    assert (
        rule_ids(
            "import os, shlex\n"
            "from flask import request\n"
            "def normalize(value):\n"
            "    return shlex.quote(value)\n"
            "def handler():\n"
            "    os.system(normalize(request.args['c']))\n"
        )
        == set()
    )


# ── route handler parameters are sources ──────────────────────────────────────────────────────────
def test_route_parameters_are_attacker_controlled():
    found = flows(
        "import os\n"
        "app = FastAPI()\n"
        "@app.get('/ping/{host}')\n"
        "def ping(host: str):\n"
        "    os.system('ping ' + host)\n"
    )
    assert [f.sink.id for f in found] == ["taint-shell-command"]
    # A route parameter may be typed or validated by the framework, so the claim is weaker than
    # one made about a raw request attribute — and says so rather than overstating.
    assert found[0].confidence == "medium"
    assert found[0].severity is Severity.HIGH


def test_a_plain_function_parameter_is_not_a_source():
    assert flows("import os\ndef helper(cmd):\n    os.system(cmd)\n") == []


# ── other sink classes ────────────────────────────────────────────────────────────────────────────
def test_sql_via_a_cursor_method():
    found = flows(
        "from flask import request\n"
        "def h(cursor):\n"
        "    cursor.execute(f\"SELECT * FROM u WHERE n = '{request.args['n']}'\")\n"
    )
    assert [f.sink.id for f in found] == ["taint-sql"]
    # The receiver's type is unknown, so the claim is medium confidence, not high.
    assert found[0].confidence == "medium"
    assert found[0].severity is Severity.HIGH


def test_path_traversal_through_os_path_join():
    assert rule_ids(
        "import os\n"
        "from flask import request\n"
        "def h():\n"
        "    return open(os.path.join('/data', request.args['f'])).read()\n"
    ) == {"taint-path"}


def test_basename_clears_the_traversal():
    assert (
        rule_ids(
            "import os\n"
            "from flask import request\n"
            "def h():\n"
            "    return open(os.path.join('/d', os.path.basename(request.args['f']))).read()\n"
        )
        == set()
    )


def test_ssrf_through_a_keyword_argument():
    assert rule_ids(
        "import requests\n"
        "from flask import request\n"
        "def h():\n"
        "    return requests.get(url=request.args['target']).text\n"
    ) == {"taint-ssrf"}


def test_deserialization_of_request_body():
    assert rule_ids(
        "import pickle\n"
        "from flask import request\n"
        "def h():\n"
        "    return pickle.loads(request.data)\n"
    ) == {"taint-deserialization"}


def test_template_injection():
    assert rule_ids(
        "from flask import request, render_template_string\n"
        "def h():\n"
        "    return render_template_string('Hi ' + request.args['name'])\n"
    ) == {"taint-ssti"}


# ── masking: comments and strings are not code ────────────────────────────────────────────────────
def test_a_commented_out_call_is_not_reported():
    results = engine_findings(
        "from flask import request\n"
        "def h():\n"
        "    # os.system(request.args['c'])  legacy, removed\n"
        "    return 1\n"
    )
    assert results == []


def test_a_docstring_mentioning_eval_is_not_reported():
    results = engine_findings('def h():\n    """Never call eval() on input."""\n    return 1\n')
    assert results == []


def test_a_string_literal_containing_a_dangerous_call_is_not_reported():
    results = engine_findings('MESSAGE = "do not use os.system(cmd) here"\n')
    assert results == []


def test_masking_preserves_line_numbers_and_offsets():
    text = 'a = 1  # eval(x)\nb = "os.system"\nc = 3\n'
    masked = mask_non_code(text, ".py")
    assert len(masked) == len(text)
    assert masked.count("\n") == text.count("\n")
    assert "eval" not in masked and "os.system" not in masked
    assert masked.splitlines()[2] == "c = 3"


def test_masking_does_not_end_a_string_at_an_escaped_quote():
    text = 'a = "he said \\" then eval(x)"\nb = 2\n'
    masked = mask_non_code(text, ".py")
    assert "eval" not in masked
    assert masked.splitlines()[1] == "b = 2"


def test_masking_keeps_a_url_inside_a_javascript_string_intact():
    """A naive comment stripper turns `"http://x"` into `"http:` and then mis-parses everything
    after it. That is how a scanner ends up blind to the rest of the file."""
    text = 'const u = "http://example.com/a";\neval(userInput);\n'
    masked = mask_non_code(text, ".js")
    assert masked.splitlines()[1] == "eval(userInput);"


def test_javascript_private_fields_are_not_treated_as_comments():
    text = "class A { #count = 0; ping() { eval(this.#count); } }\n"
    masked = mask_non_code(text, ".js")
    assert "eval" in masked


# ── suppression ───────────────────────────────────────────────────────────────────────────────────
def test_nosec_suppresses_a_line():
    assert suppressed_lines("a = 1  # nosec\nb = 2\n") == frozenset({1})
    results = engine_findings(
        "from flask import request\n"
        "def h():\n"
        "    return eval(request.args['x'])  # nosec - reviewed, input is fixed\n"
    )
    assert results == []


def test_noqa_is_not_a_security_waiver():
    """A style-linter directive must never delete a critical finding."""
    results = engine_findings(
        "from flask import request\n"
        "def h():\n"
        "    return eval(request.args['x'])  # noqa: E501\n"
    )
    assert [f.location["rule"] for f in results] == ["taint-code-exec"]


# ── noise control ─────────────────────────────────────────────────────────────────────────────────
def test_findings_in_test_files_are_demoted():
    source = (
        "from flask import request\n"
        "def h():\n"
        "    return eval(request.args['x'])\n"
    )
    production = engine_findings(source, "app/handlers.py")
    testish = engine_findings(source, "tests/test_handlers.py")
    assert production[0].base_severity is Severity.CRITICAL
    assert testish[0].base_severity is Severity.HIGH
    assert "test code" not in production[0].description


def test_clean_code_is_quiet():
    assert (
        engine_findings(
            "import subprocess\n"
            "def add(a, b):\n"
            "    return a + b\n"
            "def listing(path):\n"
            "    return subprocess.run(['ls', '-l', path], capture_output=True)\n"
        )
        == []
    )


# ── robustness ────────────────────────────────────────────────────────────────────────────────────
def test_an_unparseable_file_does_not_break_the_scan():
    assert analyze_python("def broken(:\n", "legacy.py") == []
    # The pattern layer still runs, so the file is not silently skipped entirely.
    assert engine_findings("def broken(:\n    os.system(x)\n") != []


def test_deeply_nested_expressions_terminate():
    source = "import os\nfrom flask import request\ndef h():\n    os.system(" + "str(" * 40 + \
             "request.args['c']" + ")" * 40 + ")\n"
    analyze_python(source, "deep.py")  # must return, not recurse forever


# ── the evidence a reviewer reads ─────────────────────────────────────────────────────────────────
def test_the_finding_carries_the_dataflow_it_claims():
    results = engine_findings(
        "import os\n"
        "from flask import request\n"
        "def run_command(cmd):\n"
        "    os.system(cmd)\n"
        "def handler():\n"
        "    run_command(request.args['c'])\n"
    )
    assert len(results) == 1
    detail = results[0].evidence["detail"]
    assert detail["analysis"] == "taint"
    assert detail["source"] == "an HTTP request"
    trace = detail["dataflow"]
    assert [step["what"] for step in trace][0] == "source"
    assert [step["what"] for step in trace][-1] == "sink"
    assert all(step["line"] > 0 and step["code"] for step in trace)
    assert results[0].cwe_id == "CWE-78"
    assert results[0].owasp_ref == "A03:2021"


def test_pattern_findings_are_labelled_as_pattern_matches():
    results = engine_findings("import requests\ndef h():\n    requests.get('x', verify=False)\n")
    assert [f.location["rule"] for f in results] == ["py-tls-verify-off"]
    assert results[0].evidence["detail"]["analysis"] == "pattern"


# ── multi-language pattern coverage ───────────────────────────────────────────────────────────────
def test_javascript_rules_fire():
    results = engine_findings(
        "const cp = require('child_process');\n"
        "cp.execSync(userInput);\n"
        "el.innerHTML = userInput;\n",
        "web/app.js",
    )
    assert {f.location["rule"] for f in results} == {"js-child-exec", "js-inner-html"}


def test_go_rules_fire():
    results = engine_findings(
        "tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}\n",
        "main.go",
    )
    assert [f.location["rule"] for f in results] == ["go-tls-skip"]


def test_java_rules_fire():
    results = engine_findings(
        "Statement s = conn.createStatement();\n"
        "ResultSet r = s.executeQuery(\"SELECT * FROM u WHERE n='\" + name + \"'\");\n",
        "Dao.java",
    )
    assert "java-sql-concat" in {f.location["rule"] for f in results}


def test_php_rules_fire():
    results = engine_findings("<?php\n$out = shell_exec($_GET['c']);\n", "index.php")
    assert [f.location["rule"] for f in results] == ["php-exec"]


# ── whole-application fixture ─────────────────────────────────────────────────────────────────────
# A complete Flask application authored to be scanned. Eight routes are vulnerable and three are
# the safe variant of a vulnerable one — the same sink reached by data that was neutralized, passed
# as an argv entry rather than a command, or coerced to an int. A scanner is only useful if it
# separates those, so both halves are asserted: every planted flaw found, and no safe route touched.
VULNERABLE_APP = '''
import os as operating_system
import pickle
import shlex
import subprocess
from flask import Flask, redirect, render_template_string, request

app = Flask(__name__)


def run_ping(target):
    operating_system.system("ping -c1 " + target)


def safely(target):
    return shlex.quote(target)


@app.route("/ping")
def ping():
    run_ping(request.args["host"])


@app.route("/safe-ping")
def safe_ping():
    operating_system.system("ping " + safely(request.args["host"]))


@app.route("/calc")
def calc():
    return str(eval(request.args["expr"]))


@app.route("/user")
def user(db):
    q = f"SELECT * FROM users WHERE name = '{request.args['n']}'"
    return str(db.cursor().execute(q).fetchall())


@app.route("/file")
def read_file():
    return open(operating_system.path.join("/srv", request.args["p"])).read()


@app.route("/restore", methods=["POST"])
def restore():
    return str(pickle.loads(request.data))


@app.route("/go")
def go():
    return redirect(request.args["next"])


@app.route("/hello")
def hello():
    return render_template_string("Hi " + request.args["name"])


@app.get("/exec/{name}")
def run_named(name: str):
    subprocess.run([name, "--version"])


@app.route("/archive")
def archive():
    subprocess.run(["tar", "-cf", "out.tar", request.args["dir"]])


@app.route("/count")
def count():
    operating_system.system("head -n %d f" % int(request.args["n"]))
'''


def test_the_vulnerable_fixture_is_fully_detected():
    found = {f.sink.id for f in flows(VULNERABLE_APP, "vulnapp/app.py")}
    assert found == {
        "taint-shell-command",     # /ping, through a helper, via `import os as operating_system`
        "taint-code-exec",         # /calc
        "taint-sql",               # /user
        "taint-path",              # /file
        "taint-deserialization",   # /restore
        "taint-open-redirect",     # /go
        "taint-ssti",              # /hello
        "taint-subprocess-argv",   # /exec, program name from a route parameter
    }


def test_the_safe_routes_produce_nothing():
    """/safe-ping, /archive and /count reach the same sinks with neutralized data. A scanner that
    cannot stay quiet here is one a customer learns to ignore."""
    lines = VULNERABLE_APP.splitlines()
    reported = {f.line for f in flows(VULNERABLE_APP, "vulnapp/app.py")}
    for marker in ('operating_system.system("ping " + safely', 'subprocess.run(["tar"', '"head -n %d f"'):
        line = next(i for i, text in enumerate(lines, start=1) if marker in text)
        assert line not in reported, f"false positive on the safe route at line {line}"


def test_the_fixture_is_reported_once_per_issue():
    found = flows(VULNERABLE_APP, "vulnapp/app.py")
    assert len(found) == len({f.line for f in found}) == 8
