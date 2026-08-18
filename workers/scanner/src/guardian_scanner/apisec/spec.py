"""Reading an OpenAPI document for what can be tested (WP-D10).

Two jobs. The first is the static review the previous engine did, kept because a contract that
declares no authentication is worth saying out loud. The second is new and is what the active tester
runs on: which operations exist, which of their parameters carry an **object identifier**, and which
operations the document itself marks as privileged.

Object-identifier detection is the part that decides whether BOLA testing works at all. A path
template `{id}` is one; so is `{userId}`, `{invoice_id}`, and a query parameter named `account`.
Getting this wrong in the permissive direction wastes the request budget on pagination cursors;
getting it wrong in the strict direction means the scanner tests nothing.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

METHODS = ("get", "head")  # GET and HEAD only: nothing here may change state.
ALL_METHODS = ("get", "put", "post", "delete", "options", "head", "patch", "trace")

# A parameter that names an object rather than describing a query.
_ID_NAME = re.compile(
    r"(?i)^(?:id|uuid|guid|.*_id|.*id|.*_uuid|.*key|.*_ref|ref|slug|number|no|code|"
    r"account|user|customer|tenant|org|organisation|organization|invoice|order|document|file|"
    r"record|resource|entity)$"
)
# Names that look like identifiers but are not object references — testing them finds nothing and
# spends the budget.
_NOT_AN_ID = frozenset({
    "page", "per_page", "perpage", "limit", "offset", "cursor", "size", "count", "sort",
    "order_by", "orderby", "q", "query", "search", "filter", "fields", "expand", "include",
    "format", "version", "api_version", "locale", "lang", "timezone", "code_challenge",
})

# Words in a path, tag, or operation id that mark an operation as privileged.
_PRIVILEGED = re.compile(
    r"(?i)(?:^|[/_\-.])(?:admin|administration|internal|management|manage|superuser|root|"
    r"system|ops|operator|audit|impersonate|debug)(?:$|[/_\-.])"
)


@dataclass(frozen=True)
class Parameter:
    name: str
    where: str          # path | query | header | cookie
    required: bool = False
    example: str = ""
    schema_type: str = ""

    @property
    def is_object_id(self) -> bool:
        lowered = self.name.lower()
        if lowered in _NOT_AN_ID:
            return False
        if self.where not in ("path", "query"):
            return False
        return bool(_ID_NAME.match(lowered))


@dataclass(frozen=True)
class Operation:
    method: str
    path: str
    operation_id: str = ""
    summary: str = ""
    tags: tuple[str, ...] = ()
    parameters: tuple[Parameter, ...] = ()
    security: tuple[str, ...] = ()      # names of the security schemes required
    security_declared: bool = False     # whether the document said anything at all
    responses: tuple[str, ...] = ()

    @property
    def label(self) -> str:
        return f"{self.method.upper()} {self.path}"

    @property
    def object_ids(self) -> tuple[Parameter, ...]:
        return tuple(p for p in self.parameters if p.is_object_id)

    @property
    def privileged(self) -> bool:
        """Whether the document itself marks this operation as administrative."""
        haystack = " ".join((self.path, self.operation_id, self.summary, *self.tags))
        return bool(_PRIVILEGED.search(haystack))


@dataclass
class Spec:
    servers: tuple[str, ...] = ()
    schemes: dict = field(default_factory=dict)
    operations: tuple[Operation, ...] = ()
    global_security: tuple[str, ...] = ()
    title: str = ""


def _security_names(entries) -> tuple[str, ...]:  # noqa: ANN001
    if not isinstance(entries, list):
        return ()
    names: list[str] = []
    for entry in entries:
        if isinstance(entry, dict):
            names.extend(str(k) for k in entry)
    return tuple(names)


def _parameters(raw, components: dict) -> tuple[Parameter, ...]:  # noqa: ANN001
    out: list[Parameter] = []
    for item in raw or []:
        if not isinstance(item, dict):
            continue
        if "$ref" in item:
            item = _resolve(str(item["$ref"]), components) or {}
            if not item:
                continue
        schema = item.get("schema") or {}
        example = item.get("example")
        if example is None:
            example = schema.get("example") if isinstance(schema, dict) else None
        out.append(Parameter(
            name=str(item.get("name") or ""),
            where=str(item.get("in") or ""),
            required=bool(item.get("required")),
            example="" if example is None else str(example),
            schema_type=str((schema or {}).get("type") or "") if isinstance(schema, dict) else "",
        ))
    return tuple(p for p in out if p.name)


def _resolve(ref: str, components: dict) -> dict | None:
    """`#/components/parameters/UserId` → the object."""
    if not ref.startswith("#/"):
        return None
    node: object = {"components": components}
    for part in ref[2:].split("/"):
        if not isinstance(node, dict):
            return None
        node = node.get(part)
    return node if isinstance(node, dict) else None


def parse(document: dict) -> Spec:
    """An OpenAPI 3 (or Swagger 2) document, reduced to what can be tested."""
    if not isinstance(document, dict):
        return Spec()

    components = document.get("components") or {}
    schemes = (components.get("securitySchemes")
               or document.get("securityDefinitions")  # Swagger 2
               or {})
    servers = tuple(
        str(s.get("url")) for s in (document.get("servers") or []) if isinstance(s, dict)
        and s.get("url")
    )
    if not servers and document.get("host"):  # Swagger 2
        scheme = (document.get("schemes") or ["https"])[0]
        servers = (f"{scheme}://{document['host']}{document.get('basePath', '')}",)

    global_security = _security_names(document.get("security"))
    operations: list[Operation] = []

    for path, item in (document.get("paths") or {}).items():
        if not isinstance(item, dict):
            continue
        shared = _parameters(item.get("parameters"), components)
        for method, operation in item.items():
            if method.lower() not in ALL_METHODS or not isinstance(operation, dict):
                continue
            declared = "security" in operation or bool(global_security)
            security = (_security_names(operation.get("security"))
                        if "security" in operation else global_security)
            operations.append(Operation(
                method=method.lower(),
                path=str(path),
                operation_id=str(operation.get("operationId") or ""),
                summary=str(operation.get("summary") or ""),
                tags=tuple(str(t) for t in (operation.get("tags") or [])),
                parameters=shared + _parameters(operation.get("parameters"), components),
                security=security,
                security_declared=declared,
                responses=tuple(str(code) for code in (operation.get("responses") or {})),
            ))

    return Spec(servers=servers, schemes=schemes if isinstance(schemes, dict) else {},
                operations=tuple(operations), global_security=global_security,
                title=str((document.get("info") or {}).get("title") or ""))


def build_url(server: str, operation: Operation, values: dict[str, str]) -> str:
    """Concrete URL for an operation, substituting path templates and adding query parameters.

    Only the values supplied are filled in. A path with an unfilled template is not requested — a
    literal `/users/{id}` reaches a 404 handler at best and a wildcard route at worst, and either
    way it tests nothing.
    """
    from urllib.parse import quote, urlencode  # noqa: PLC0415

    path = operation.path
    for parameter in operation.parameters:
        if parameter.where != "path":
            continue
        value = values.get(parameter.name)
        if value is None:
            return ""
        path = path.replace("{" + parameter.name + "}", quote(str(value), safe=""))
    if "{" in path:
        return ""

    query = {p.name: values[p.name] for p in operation.parameters
             if p.where == "query" and p.name in values}
    url = server.rstrip("/") + "/" + path.lstrip("/")
    return f"{url}?{urlencode(query)}" if query else url


__all__ = ["ALL_METHODS", "METHODS", "Operation", "Parameter", "Spec", "build_url", "parse"]
