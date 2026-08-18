"""Intra-file taint analysis for Python (WP-D4).

v1 answered "does this file contain the text `eval(`". That question has almost no security value:
`eval("1+1")` is noise and `eval(request.args["expr"])` is remote code execution, and the two are
indistinguishable to a regex. v2 answers the question that matters — **does attacker-controlled data
reach a dangerous operation, and was it neutralized on the way** — and reports the path it took, so
the finding can be verified by a human instead of taken on faith.

Three properties are deliberate:

**Sanitizers are class-specific.** `html.escape` clears an XSS sink and leaves a command-injection
sink untouched. Modelling "sanitized" as one boolean is how a scanner ends up clearing a live RCE.

**An unknown free function stops the taint; an unknown method does not.** `clean(x)` is far more
often a validator than a passthrough, so treating its result as tainted manufactures false
positives; `x.strip()` cannot launder anything, so treating its result as clean manufactures false
negatives. Local functions are not guessed at — they are summarized and followed.

**Analysis is over-approximate across branches and under-approximate across files.** Both arms of an
`if` contribute taint, because a vulnerability on either path is a real vulnerability. Nothing is
inferred across module boundaries, because a cross-file guess cannot be verified from the evidence
the finding carries, and an unverifiable critical is worse than a missed one.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field, replace

from guardian_core.enums import Severity

from guardian_scanner.sast.catalog import (
    REQUEST_ATTRIBUTES,
    REQUEST_OBJECTS,
    ROUTE_DECORATOR_ATTRS,
    SINKS,
    SOURCE_DOTTED,
    Sink,
    sanitizer_for,
)

# Calls whose result carries its arguments' taint. Anything not listed and not a method call is
# treated as a boundary — see the module docstring.
_PROPAGATORS: frozenset[str] = frozenset(
    {
        "str", "bytes", "bytearray", "repr", "format", "list", "tuple", "set", "dict",
        "os.path.join", "os.path.abspath", "os.path.normpath", "os.path.realpath",
        "os.path.expanduser", "posixpath.join", "pathlib.PurePath",
        "urllib.parse.urljoin", "urllib.parse.unquote", "urllib.parse.unquote_plus",
        "json.dumps", "json.loads", "copy.copy", "copy.deepcopy",
    }
)

_MAX_NODES = 60_000        # a generated file should not be able to cost minutes of analysis
_MAX_FIXPOINT_PASSES = 4   # summaries converge in one or two on real code
_MAX_FINDINGS_PER_FILE = 200


@dataclass(frozen=True)
class TraceStep:
    """One hop on the path from input to sink — the evidence a reviewer actually reads."""

    line: int
    code: str
    what: str  # "source" | "propagation" | "call" | "sink"

    def as_dict(self) -> dict:
        return {"line": self.line, "code": self.code, "what": self.what}


@dataclass(frozen=True)
class Taint:
    """A value known to derive from untrusted input."""

    source_kind: str
    origin: str                      # parameter name, when the source is a function parameter
    steps: tuple[TraceStep, ...] = ()
    neutralized: frozenset[str] = frozenset()

    def extend(self, step: TraceStep) -> Taint:
        if self.steps and self.steps[-1].line == step.line and self.steps[-1].what == step.what:
            return self
        return replace(self, steps=(*self.steps, step)[:12])

    def sanitize(self, classes: frozenset[str]) -> Taint:
        return replace(self, neutralized=self.neutralized | classes)


@dataclass
class TaintFinding:
    """A confirmed flow. `trace` is ordered source → sink."""

    sink: Sink
    path: str
    line: int
    code: str
    source_kind: str
    trace: tuple[TraceStep, ...]
    confidence: str
    severity: Severity
    interprocedural: bool = False

    def key(self) -> tuple[str, str, int]:
        return (self.sink.id, self.path, self.line)


@dataclass
class FunctionSummary:
    """What a function does with the values handed to it."""

    name: str
    params: list[str] = field(default_factory=list)
    param_sinks: dict[str, list[tuple[Sink, int, str]]] = field(default_factory=dict)
    param_returns: set[str] = field(default_factory=set)
    # Classes the value was neutralized for on its way back out. A wrapper around `shlex.quote` is
    # a sanitizer, and a caller that cannot see that will report the callee's own protection as a
    # vulnerability — which teaches customers to ignore the engine.
    param_return_sanitized: dict[str, frozenset[str]] = field(default_factory=dict)

    def record_return(self, param: str, neutralized: frozenset[str]) -> None:
        self.param_returns.add(param)
        existing = self.param_return_sanitized.get(param)
        # Intersection, not union: a value is only safe if *every* return path made it safe.
        self.param_return_sanitized[param] = (
            neutralized if existing is None else existing & neutralized
        )


def _lower(severity: Severity) -> Severity:
    order = [Severity.INFO, Severity.LOW, Severity.MEDIUM, Severity.HIGH, Severity.CRITICAL]
    return order[max(0, order.index(severity) - 1)]


# ── module-level analysis ─────────────────────────────────────────────────────────────────────────
class _Analyzer:
    def __init__(self, tree: ast.Module, source: str, path: str) -> None:
        self.tree = tree
        self.lines = source.splitlines()
        self.path = path
        self.aliases = _import_aliases(tree)
        self.functions: dict[str, ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                self.functions.setdefault(node.name, node)
        self.summaries: dict[str, FunctionSummary] = {}
        self.findings: list[TaintFinding] = []
        self._collecting = False        # True during the summary passes: observe, do not report
        self._current: FunctionSummary | None = None

    # ── naming ───────────────────────────────────────────────────────────────────────────────────
    def dotted(self, node: ast.expr) -> str | None:
        """Resolve an expression to a fully-qualified name through the module's import aliases."""
        parts: list[str] = []
        cur: ast.expr = node
        while isinstance(cur, ast.Attribute):
            parts.append(cur.attr)
            cur = cur.value
        if not isinstance(cur, ast.Name):
            return None
        parts.append(cur.id)
        parts.reverse()
        head = self.aliases.get(parts[0], parts[0])
        return ".".join([head, *parts[1:]])

    def code(self, line: int) -> str:
        if 1 <= line <= len(self.lines):
            text = self.lines[line - 1].strip()
            return text if len(text) <= 200 else text[:200] + "…"
        return ""

    def step(self, node: ast.AST, what: str) -> TraceStep:
        line = getattr(node, "lineno", 0)
        return TraceStep(line=line, code=self.code(line), what=what)

    # ── sources ──────────────────────────────────────────────────────────────────────────────────
    def _source_taint(self, node: ast.expr) -> Taint | None:
        """Whether reading this expression brings untrusted data into the program."""
        dotted = self.dotted(node)
        if dotted in SOURCE_DOTTED:
            kind = "argv" if dotted and dotted.startswith("sys.") else "request"
            return Taint(source_kind=kind, origin="", steps=(self.step(node, "source"),))

        if isinstance(node, ast.Attribute):
            base = node.value
            base_name = base.id if isinstance(base, ast.Name) else self.dotted(base)
            if base_name in REQUEST_OBJECTS and node.attr in REQUEST_ATTRIBUTES:
                return Taint(
                    source_kind="request", origin="", steps=(self.step(node, "source"),)
                )
        if isinstance(node, ast.Call):
            inner = node.func
            if isinstance(inner, ast.Name) and inner.id == "input":
                return Taint(source_kind="stdin", origin="",
                             steps=(self.step(node, "source"),))
        return None

    # ── expression taint ─────────────────────────────────────────────────────────────────────────
    def taint_of(  # noqa: C901,PLR0911,PLR0912
        self, node: ast.expr | None, env: dict[str, Taint], depth: int = 0
    ) -> Taint | None:
        if node is None or depth > 24:
            return None

        direct = self._source_taint(node)
        if direct is not None:
            return direct

        if isinstance(node, ast.Name):
            return env.get(node.id)

        if isinstance(node, ast.Attribute):
            return self.taint_of(node.value, env, depth + 1)

        if isinstance(node, ast.Subscript):
            return self.taint_of(node.value, env, depth + 1) or self.taint_of(
                node.slice, env, depth + 1
            )

        if isinstance(node, ast.Call):
            return self._call_taint(node, env, depth)

        if isinstance(node, ast.BinOp):
            return self.taint_of(node.left, env, depth + 1) or self.taint_of(
                node.right, env, depth + 1
            )

        if isinstance(node, ast.JoinedStr):  # f-strings are the most common way input gets in
            return self._first(node.values, env, depth)

        if isinstance(node, ast.FormattedValue):
            return self.taint_of(node.value, env, depth + 1)

        if isinstance(node, ast.List | ast.Tuple | ast.Set):
            return self._first(node.elts, env, depth)

        if isinstance(node, ast.Dict):
            return self._first([v for v in node.values if v is not None], env, depth)

        if isinstance(node, ast.BoolOp):
            return self._first(node.values, env, depth)

        if isinstance(node, ast.IfExp):
            return self.taint_of(node.body, env, depth + 1) or self.taint_of(
                node.orelse, env, depth + 1
            )

        if isinstance(node, ast.Starred | ast.Await | ast.UnaryOp):
            inner = getattr(node, "value", None) or getattr(node, "operand", None)
            return self.taint_of(inner, env, depth + 1)

        if isinstance(node, ast.Compare):
            return None  # a comparison yields a bool

        return None

    def _first(self, nodes: list[ast.expr], env: dict[str, Taint], depth: int) -> Taint | None:
        for item in nodes:
            found = self.taint_of(item, env, depth + 1)
            if found is not None:
                return found
        return None

    def _call_taint(self, node: ast.Call, env: dict[str, Taint], depth: int) -> Taint | None:
        dotted = self.dotted(node.func)
        args = [*node.args, *[kw.value for kw in node.keywords]]

        sanitizer = sanitizer_for(dotted)
        if sanitizer is not None:
            inner = self._first(args, env, depth)
            if inner is None:
                return None
            return inner.sanitize(sanitizer.neutralizes).extend(self.step(node, "propagation"))

        # A local function whose summary says the value comes back out.
        if dotted in self.functions:
            summary = self.summaries.get(dotted)
            if summary is not None:
                for name, expr in self._bind_arguments(summary, node):
                    if name in summary.param_returns:
                        inner = self.taint_of(expr, env, depth + 1)
                        if inner is not None:
                            cleaned = summary.param_return_sanitized.get(name, frozenset())
                            return inner.sanitize(cleaned).extend(self.step(node, "call"))
            return None

        if dotted in _PROPAGATORS:
            inner = self._first(args, env, depth)
            return inner.extend(self.step(node, "propagation")) if inner else None

        # A method call on a tainted receiver: `value.strip()`, `value.decode()`, `",".join(value)`.
        # A method cannot launder its receiver, so the taint survives.
        if isinstance(node.func, ast.Attribute):
            receiver = self.taint_of(node.func.value, env, depth + 1)
            if receiver is not None:
                return receiver.extend(self.step(node, "propagation"))
            inner = self._first(args, env, depth)
            if inner is not None and node.func.attr in {"format", "join", "format_map"}:
                return inner.extend(self.step(node, "propagation"))
            return None

        return None

    # ── sinks ────────────────────────────────────────────────────────────────────────────────────
    def _bind_arguments(
        self, summary: FunctionSummary, call: ast.Call
    ) -> list[tuple[str, ast.expr]]:
        """Map a call's arguments onto the callee's parameter names."""
        bound: list[tuple[str, ast.expr]] = []
        for index, arg in enumerate(call.args):
            if index < len(summary.params):
                bound.append((summary.params[index], arg))
        for kw in call.keywords:
            if kw.arg and kw.arg in summary.params:
                bound.append((kw.arg, kw.value))
        return bound

    def _kwarg(self, call: ast.Call, name: str) -> ast.expr | None:
        for kw in call.keywords:
            if kw.arg == name:
                return kw.value
        return None

    def _match_sink(self, call: ast.Call, sink: Sink) -> str | None:
        """Return the confidence this call is `sink`, or None."""
        dotted = self.dotted(call.func)
        confidence: str | None = None
        if dotted and dotted in sink.dotted:
            confidence = "high"
        elif isinstance(call.func, ast.Attribute) and call.func.attr in sink.methods:
            # The receiver's type is unknown, so `thing.execute(...)` may not be a database cursor.
            confidence = "medium"
        if confidence is None:
            return None

        if sink.requires_kwarg is not None:
            name, expected = sink.requires_kwarg
            value = self._kwarg(call, name)
            literal = isinstance(value, ast.Constant) and repr(value.value) == expected
            if not literal:
                return None
        elif sink.id == "taint-subprocess-argv" and self._kwarg(call, "shell") is not None:
            shell = self._kwarg(call, "shell")
            if isinstance(shell, ast.Constant) and shell.value is True:
                return None  # the shell=True rule owns this call; do not report it twice
        return confidence

    def _dangerous_exprs(self, call: ast.Call, sink: Sink) -> list[ast.expr]:
        """The argument expressions this sink actually acts on."""
        if sink.id == "taint-subprocess-argv":
            # Without a shell, only the program name is injectable. `run(["ls", user_input])` passes
            # the value as an argv entry, where it cannot become a second command — reporting that
            # as command injection is the false positive that makes developers distrust the tool.
            if not call.args:
                return []
            first = call.args[0]
            if isinstance(first, ast.List | ast.Tuple):
                return [first.elts[0]] if first.elts else []
            return [first]

        chosen: list[ast.expr] = []
        if sink.positions:
            for index in sink.positions:
                if index < len(call.args):
                    chosen.append(call.args[index])
        else:
            chosen.extend(call.args)
        for name in sink.keywords:
            value = self._kwarg(call, name)
            if value is not None:
                chosen.append(value)
        return chosen

    def check_call(self, call: ast.Call, env: dict[str, Taint]) -> None:
        for sink in SINKS:
            confidence = self._match_sink(call, sink)
            if confidence is None:
                continue
            for expr in self._dangerous_exprs(call, sink):
                taint = self.taint_of(expr, env)
                if taint is None or sink.cwe in taint.neutralized:
                    continue
                self._record(sink, call, taint, confidence)
                break

        # Passing tainted data into a local function that reaches a sink is the same vulnerability
        # one call frame away, and is the flow a regex scanner can never see.
        dotted = self.dotted(call.func)
        summary = self.summaries.get(dotted) if dotted else None
        if summary is not None:
            for name, expr in self._bind_arguments(summary, call):
                hits = summary.param_sinks.get(name)
                if not hits:
                    continue
                taint = self.taint_of(expr, env)
                if taint is None:
                    continue
                for sink, line, code in hits:
                    if sink.cwe in taint.neutralized:
                        continue
                    self._record_interprocedural(sink, call, taint, line, code, summary.name)

    def _record(self, sink: Sink, call: ast.Call, taint: Taint, confidence: str) -> None:
        if self._collecting:
            if self._current is not None and taint.origin:
                self._current.param_sinks.setdefault(taint.origin, []).append(
                    (sink, getattr(call, "lineno", 0), self.code(getattr(call, "lineno", 0)))
                )
            return
        # A raw request attribute is unambiguously attacker-controlled. A route parameter may be
        # typed and validated by the framework first, and `sys.argv` is the operator in a CLI tool
        # as often as it is an attacker in a server. Both still carry a trace, so the claim is made
        # at a confidence that matches how strong it actually is rather than being overstated.
        if taint.source_kind in {"route-parameter", "argv"} and confidence == "high":
            confidence = "medium"
        severity = sink.severity if confidence == "high" else _lower(sink.severity)
        trace = (*taint.steps, self.step(call, "sink"))
        self.findings.append(
            TaintFinding(
                sink=sink, path=self.path, line=getattr(call, "lineno", 0),
                code=self.code(getattr(call, "lineno", 0)), source_kind=taint.source_kind,
                trace=trace, confidence=confidence, severity=severity,
            )
        )

    def _record_interprocedural(
        self, sink: Sink, call: ast.Call, taint: Taint, sink_line: int, sink_code: str, callee: str
    ) -> None:
        if self._collecting:
            if self._current is not None and taint.origin:
                self._current.param_sinks.setdefault(taint.origin, []).append(
                    (sink, sink_line, sink_code)
                )
            return
        trace = (
            *taint.steps,
            self.step(call, "call"),
            TraceStep(line=sink_line, code=sink_code, what="sink"),
        )
        self.findings.append(
            TaintFinding(
                sink=sink, path=self.path, line=sink_line, code=sink_code,
                source_kind=taint.source_kind, trace=trace, confidence="medium",
                severity=_lower(sink.severity), interprocedural=True,
            )
        )
        del callee

    # ── statement walking ────────────────────────────────────────────────────────────────────────
    def exec_body(self, body: list[ast.stmt], env: dict[str, Taint], depth: int = 0) -> None:  # noqa: C901,PLR0912
        if depth > 20:
            return
        for stmt in body:
            if isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
                continue  # analysed on its own, with its own parameter environment

            # Sinks first: the values a statement uses are the ones live before it rebinds anything.
            for node in ast.walk(stmt):
                if isinstance(node, ast.Call):
                    self.check_call(node, env)

            if isinstance(stmt, ast.Assign):
                taint = self.taint_of(stmt.value, env)
                for target in stmt.targets:
                    self._bind(target, taint, env, stmt)
            elif isinstance(stmt, ast.AnnAssign) and stmt.value is not None:
                self._bind(stmt.target, self.taint_of(stmt.value, env), env, stmt)
            elif isinstance(stmt, ast.AugAssign):
                existing = self.taint_of(stmt.target, env)
                self._bind(stmt.target, existing or self.taint_of(stmt.value, env), env, stmt)
            elif isinstance(stmt, ast.Return):
                taint = self.taint_of(stmt.value, env)
                if taint is not None and self._current is not None and taint.origin:
                    self._current.record_return(taint.origin, taint.neutralized)
            elif isinstance(stmt, ast.For | ast.AsyncFor):
                self._bind(stmt.target, self.taint_of(stmt.iter, env), env, stmt)
                self.exec_body(stmt.body, env, depth + 1)
                self.exec_body(stmt.orelse, env, depth + 1)
            elif isinstance(stmt, ast.With | ast.AsyncWith):
                for item in stmt.items:
                    if item.optional_vars is not None:
                        self._bind(
                            item.optional_vars, self.taint_of(item.context_expr, env), env, stmt
                        )
                self.exec_body(stmt.body, env, depth + 1)
            elif isinstance(stmt, ast.If | ast.While):
                # Both arms contribute: a vulnerability on either path is a vulnerability.
                left, right = dict(env), dict(env)
                self.exec_body(stmt.body, left, depth + 1)
                self.exec_body(stmt.orelse, right, depth + 1)
                env.update(left)
                env.update(right)
            elif isinstance(stmt, ast.Try):
                self.exec_body(stmt.body, env, depth + 1)
                for handler in stmt.handlers:
                    self.exec_body(handler.body, env, depth + 1)
                self.exec_body(stmt.orelse, env, depth + 1)
                self.exec_body(stmt.finalbody, env, depth + 1)

    def _bind(
        self, target: ast.expr, taint: Taint | None, env: dict[str, Taint], stmt: ast.stmt
    ) -> None:
        if isinstance(target, ast.Name):
            if taint is None:
                env.pop(target.id, None)
            else:
                env[target.id] = taint.extend(self.step(stmt, "propagation"))
        elif isinstance(target, ast.Tuple | ast.List):
            for element in target.elts:
                self._bind(element, taint, env, stmt)
        elif isinstance(target, ast.Attribute | ast.Subscript) and taint is not None:
            # `self.value = tainted` — track the whole dotted path as a pseudo-variable.
            name = self.dotted(target)
            if name:
                env[name] = taint.extend(self.step(stmt, "propagation"))

    # ── passes ───────────────────────────────────────────────────────────────────────────────────
    def build_summaries(self) -> None:
        """Fixpoint over local functions: which parameters reach a sink, which reach the return."""
        self._collecting = True
        for _ in range(_MAX_FIXPOINT_PASSES):
            before = _summary_shape(self.summaries)
            for name, func in self.functions.items():
                summary = FunctionSummary(name=name, params=_parameters(func))
                self._current = summary
                env = {
                    param: Taint(source_kind="parameter", origin=param)
                    for param in summary.params
                }
                self.exec_body(func.body, env)
                self.summaries[name] = summary
            self._current = None
            if _summary_shape(self.summaries) == before:
                break
        self._collecting = False

    def report(self) -> list[TaintFinding]:
        for func in self.functions.values():
            env: dict[str, Taint] = {}
            if _is_route_handler(func):
                for param in _parameters(func):
                    env[param] = Taint(
                        source_kind="route-parameter",
                        origin=param,
                        steps=(self.step(func, "source"),),
                    )
            self._current = None
            self.exec_body(func.body, env)

        module_body = [
            stmt
            for stmt in self.tree.body
            if not isinstance(stmt, ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef)
        ]
        self.exec_body(module_body, {})

        deduped: dict[tuple[str, str, int], TaintFinding] = {}
        for finding in self.findings:
            existing = deduped.get(finding.key())
            if existing is None or _better(finding, existing):
                deduped[finding.key()] = finding
        return sorted(deduped.values(), key=lambda f: (f.line, f.sink.id))[:_MAX_FINDINGS_PER_FILE]


def _better(candidate: TaintFinding, current: TaintFinding) -> bool:
    order = {"high": 2, "medium": 1, "low": 0}
    if order[candidate.confidence] != order[current.confidence]:
        return order[candidate.confidence] > order[current.confidence]
    return candidate.severity.rank > current.severity.rank


def _summary_shape(summaries: dict[str, FunctionSummary]) -> dict:
    return {
        name: (
            tuple(sorted(s.param_returns)),
            tuple(sorted((p, len(hits)) for p, hits in s.param_sinks.items())),
            tuple(sorted((p, tuple(sorted(c))) for p, c in s.param_return_sanitized.items())),
        )
        for name, s in summaries.items()
    }


def _parameters(func: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
    args = func.args
    names = [a.arg for a in (*args.posonlyargs, *args.args, *args.kwonlyargs)]
    if args.vararg:
        names.append(args.vararg.arg)
    if args.kwarg:
        names.append(args.kwarg.arg)
    return [n for n in names if n not in {"self", "cls"}]


def _is_route_handler(func: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """`@app.get(...)`, `@router.post(...)`, `@blueprint.route(...)` — the parameters come off the
    wire, so they are attacker-controlled before the first line of the body runs."""
    for decorator in func.decorator_list:
        node = decorator.func if isinstance(decorator, ast.Call) else decorator
        if isinstance(node, ast.Attribute) and node.attr in ROUTE_DECORATOR_ATTRS:
            return True
    return False


def _import_aliases(tree: ast.Module) -> dict[str, str]:
    """`import os as o` and `from os import system as run` both have to resolve, or a scanner is
    defeated by a rename — which is the first thing anyone hiding a backdoor would try."""
    aliases: dict[str, str] = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                bound = alias.asname or alias.name.split(".")[0]
                aliases[bound] = alias.name if alias.asname else alias.name.split(".")[0]
        elif isinstance(node, ast.ImportFrom):
            if node.level or not node.module:
                continue
            for alias in node.names:
                aliases[alias.asname or alias.name] = f"{node.module}.{alias.name}"
    return aliases


def analyze_python(source: str, path: str) -> list[TaintFinding]:
    """Analyse one Python file. Returns [] for anything unparseable rather than raising —
    a Python 2 file in a repository is not a reason to fail the customer's whole scan."""
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return []
    if sum(1 for _ in ast.walk(tree)) > _MAX_NODES:
        return []
    analyzer = _Analyzer(tree, source, path)
    try:
        analyzer.build_summaries()
        return analyzer.report()
    except RecursionError:
        return []
