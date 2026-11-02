"""Every query against a tenant table names the tenant, or says why not.

RLS protects requests made with a user's token. A backend that talks to the
database with the service role bypasses it, and from then on the only thing
between one customer's rows and another's is a ``WHERE tenant_id = $1`` that
somebody has to remember, in every query, forever. One missing clause in an
ad-hoc query returns another customer's row, and the bug report it produces
reads as a product failure, not a leak.

This scanner reads every SQL string in your Python source and fails on any
statement that touches a tenant table without naming the tenant column. A
query that is cross-tenant on purpose (a webhook keyed on a provider's own id,
a fleet-wide health check) goes on an allowlist with the reason, so the
exception is a decision someone made, not a ``WHERE`` someone forgot.

Details that matter:

* **It reads the corpus, not a helper.** A test that feeds hand-written SQL to
  a scoping function passes forever while the next unscoped literal walks past
  it. What has to be measured is every literal the code actually contains.
* **Each statement is judged on its own.** A literal holding two statements
  passes only if both name the tenant column.
* **The column must be in the SQL itself**, not in a comment or a string
  value inside it.
* **f-strings are read whole**, and so are ``+``, ``%`` and ``.format()``
  built on literals. A module-level string constant used in one is read as
  its value, so ``BASE + " where id = $1"`` is its own query, and a table
  named through a constant is still seen. Docstrings are skipped.
* **Licences are keyed by file and statement fingerprint, not line number.**
  A line number is not an identity: a new cross-tenant query landing on a
  licensed line would inherit the licence. The fingerprint (a hash of the
  normalized statement) makes a changed query need a new decision, and an
  edit elsewhere in the file breaks nothing.
* **Stale licences fail too**: an entry that matches no query makes the
  allowlist read as more permissive than the code is.
* **The scan must find something.** A wrong glob collects zero queries and
  reports green; ``min_queries`` turns that into a failure. A file that does
  not parse fails as well: its queries can't be seen.
"""

from __future__ import annotations

import ast
import hashlib
import os
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from pathlib import Path

from rls_guard.migrations import SqlSyntaxError, tokenize

_VERB = re.compile(
    r"\b(?:select|insert\s+into|update|delete\s+from|merge\s+into)\b"
    r"|^\s*(?:truncate|copy|table)\b",
    re.IGNORECASE,
)


def fingerprint(sql: str) -> str:
    """A short, stable hash of a statement: lower-cased, whitespace collapsed,
    so reflowing a query keeps it and changing its words does not."""
    return hashlib.sha256(" ".join(sql.lower().split()).encode()).hexdigest()[:10]


@dataclass(frozen=True)
class Query:
    path: str
    line: int
    sql: str

    @property
    def fingerprint(self) -> str:
        return fingerprint(self.sql)

    @property
    def key(self) -> str:
        return f"{self.path}::{self.fingerprint}"


@dataclass(frozen=True)
class Licence:
    path: str
    fingerprint: str
    reason: str

    @property
    def key(self) -> str:
        return f"{self.path}::{self.fingerprint}"


@dataclass
class SourceScan:
    queries: list[Query] = field(default_factory=list)
    unparsed: list[tuple[str, str]] = field(default_factory=list)  # (path, why)


@dataclass
class ScopingReport:
    queries: list[Query] = field(default_factory=list)
    unscoped: list[Query] = field(default_factory=list)
    undeclared: list[Query] = field(default_factory=list)
    stale: list[Licence] = field(default_factory=list)
    weak_reasons: list[Licence] = field(default_factory=list)
    unparsed: list[tuple[str, str]] = field(default_factory=list)
    too_few: str | None = None

    @property
    def ok(self) -> bool:
        return not (
            self.undeclared or self.stale or self.weak_reasons or self.unparsed or self.too_few
        )

    def problems(self) -> list[str]:
        out = []
        for path, why in self.unparsed:
            out.append(
                f"{path} could not be parsed ({why}), so its queries can't be checked. "
                "Run rls-guard on the Python version the code is written for."
            )
        if self.too_few:
            out.append(self.too_few)
        for q in self.undeclared:
            first = " ".join(q.sql.split())[:120]
            out.append(
                f"{q.path}:{q.line} queries a tenant table without the tenant column "
                f"(fingerprint {q.fingerprint}): {first}"
            )
        for lic in self.stale:
            out.append(
                f"allowlist entry {lic.path} {lic.fingerprint} matches no query: the query "
                "was scoped, changed or removed. Delete the entry, or read the new query "
                "before licensing it."
            )
        for lic in self.weak_reasons:
            out.append(f"allowlist entry {lic.path} {lic.fingerprint} needs a real reason")
        return out


_HOLE = "{}"


class _Renderer:
    """Turns string expressions into the SQL text they build, as far as the
    source shows it; anything else becomes ``{}``."""

    def __init__(self, tree: ast.Module) -> None:
        self.constants: dict[str, str] = {}
        for node in tree.body:
            target: ast.expr | None = None
            value: ast.expr | None = None
            if isinstance(node, ast.Assign) and len(node.targets) == 1:
                target, value = node.targets[0], node.value
            elif isinstance(node, ast.AnnAssign) and node.value is not None:
                target, value = node.target, node.value
            if not isinstance(target, ast.Name) or value is None:
                continue
            rendered = self.render(value)
            if rendered is None:
                self.constants.pop(target.id, None)
            else:
                self.constants[target.id] = rendered

    def part(self, node: ast.expr) -> str:
        """A piece of a composed string: its text when known, else ``{}``."""
        if isinstance(node, ast.Name) and node.id in self.constants:
            return self.constants[node.id]
        rendered = self.render(node)
        return _HOLE if rendered is None else rendered

    def render(self, node: ast.AST) -> str | None:
        """The text of a string expression built from literals and constants,
        or None when ``node`` is not one."""
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        if isinstance(node, ast.JoinedStr):
            out = []
            for value in node.values:
                if isinstance(value, ast.Constant) and isinstance(value.value, str):
                    out.append(value.value)
                elif (
                    isinstance(value, ast.FormattedValue)
                    and value.format_spec is None
                    and value.conversion in (-1, ord("s"))
                ):
                    out.append(self.part(value.value))
                else:
                    out.append(_HOLE)
            return "".join(out)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            left, right = self.render_side(node.left), self.render_side(node.right)
            if left is None and right is None:
                return None
            return (left if left is not None else _HOLE) + (right if right is not None else _HOLE)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            template = self.render_side(node.left)
            if template is None:
                return None
            items = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
            values = tuple(self.value(item) for item in items)
            try:
                return template % (values if isinstance(node.right, ast.Tuple) else values[0])
            except (TypeError, ValueError, KeyError):
                return template
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "format"
        ):
            template = self.render_side(node.func.value)
            if template is None:
                return None
            args = [self.value(a) for a in node.args]
            kwargs = {k.arg: self.value(k.value) for k in node.keywords if k.arg is not None}
            try:
                return template.format(*args, **kwargs)
            except (IndexError, KeyError, ValueError, AttributeError):
                return template
        return None

    def render_side(self, node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return self.constants.get(node.id)
        return self.render(node)

    def value(self, node: ast.expr) -> object:
        if isinstance(node, ast.Constant):
            return node.value
        return self.part(node)


def _skipped(tree: ast.AST) -> set[int]:
    skip: set[int] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Module | ast.FunctionDef | ast.AsyncFunctionDef | ast.ClassDef):
            body = node.body
            if body and isinstance(body[0], ast.Expr):
                skip.add(id(body[0].value))
    return skip


def _statements(sql: str) -> list[tuple[int, str]]:
    """(line offset, text) of each statement in a literal; the whole literal
    when it can't be split."""
    try:
        return [(s.line - 1, s.text) for s in tokenize(sql)]
    except SqlSyntaxError:
        return [(0, sql)]


def collect_sources(patterns: Iterable[str], root: Path) -> list[Path]:
    """The ``.py`` files the globs match, outside ``__pycache__``. A folder a
    glob matches stands for every ``.py`` file under it, so ``src/**`` reads
    the same on every Python version."""
    found: set[Path] = set()
    for pattern in patterns:
        for match in root.glob(pattern):
            for path in match.rglob("*.py") if match.is_dir() else [match]:
                if path.is_file() and path.suffix == ".py" and "__pycache__" not in path.parts:
                    found.add(path)
    return sorted(found)


def _relative(path: Path, root: Path) -> str:
    return Path(os.path.relpath(path.resolve(), root.resolve())).as_posix()


def scan_sources(sources: Iterable[Path], *, root: Path, tables: re.Pattern[str]) -> SourceScan:
    """Every SQL statement in ``sources`` that touches a table matching
    ``tables``, and the files that could not be parsed."""
    scan = SourceScan()
    for path in sorted(set(sources)):
        rel = _relative(path, root)
        try:
            tree = ast.parse(path.read_bytes(), filename=str(path))
        except (SyntaxError, ValueError, UnicodeDecodeError) as exc:
            scan.unparsed.append((rel, f"{type(exc).__name__}: {exc}"))
            continue
        except OSError as exc:
            scan.unparsed.append((rel, f"could not read it: {exc}"))
            continue
        renderer = _Renderer(tree)
        skip = _skipped(tree)
        for node in ast.walk(tree):
            if id(node) in skip:
                continue
            sql = renderer.render(node)
            if sql is None:
                continue
            # Judge a composed string once, whole: never its parts again.
            skip.update(id(child) for child in ast.walk(node) if child is not node)
            line = getattr(node, "lineno", 0)
            multiline = getattr(node, "end_lineno", line) != line
            for offset, statement in _statements(sql):
                if tables.search(statement) and _VERB.search(statement):
                    scan.queries.append(Query(rel, line + offset if multiline else line, statement))
    scan.queries.sort(key=lambda q: (q.path, q.line))
    return scan


def find_queries(sources: Iterable[Path], *, root: Path, tables: re.Pattern[str]) -> list[Query]:
    """Every SQL statement in ``sources`` that touches a table matching
    ``tables``. Raises ValueError if a file can't be parsed: its queries would
    go unchecked."""
    scan = scan_sources(sources, root=root, tables=tables)
    if scan.unparsed:
        raise ValueError("could not parse " + ", ".join(path for path, _ in scan.unparsed))
    return scan.queries


def _names_column(sql: str, column: str) -> bool:
    """The tenant column appears as a name in the SQL, not in a comment or a
    string value. Falls back to a word match when the text isn't SQL we can
    read (a fragment with an open quote)."""
    try:
        statements = tokenize(sql)
    except SqlSyntaxError:
        return re.search(rf"\b{re.escape(column)}\b", sql, re.IGNORECASE) is not None
    folded = column.lower()
    return any(
        (tok.kind == "word" and tok.text == folded) or (tok.kind == "ident" and tok.text == column)
        for statement in statements
        for tok in statement.tokens
    )


def check_scoping(
    queries: Iterable[Query],
    *,
    tenant_column: str,
    licences: Iterable[Licence] = (),
    min_queries: int = 1,
    min_reason_length: int = 20,
    unparsed: Iterable[tuple[str, str]] = (),
) -> ScopingReport:
    report = ScopingReport(queries=list(queries), unparsed=list(unparsed))
    report.unscoped = [q for q in report.queries if not _names_column(q.sql, tenant_column)]
    by_key: Mapping[str, Licence] = {lic.key: lic for lic in licences}
    report.undeclared = [q for q in report.unscoped if q.key not in by_key]
    unscoped_keys = {q.key for q in report.unscoped}
    report.stale = [lic for key, lic in sorted(by_key.items()) if key not in unscoped_keys]
    report.weak_reasons = [
        lic for lic in by_key.values() if len(lic.reason.strip()) < min_reason_length
    ]
    if len(report.queries) < min_queries:
        report.too_few = (
            f"found {len(report.queries)} queries against tenant tables, expected at least "
            f"{min_queries}: the source globs or the table pattern match nothing, so this "
            "check would pass while reading no code"
        )
    return report


__all__ = [
    "Licence",
    "Query",
    "ScopingReport",
    "SourceScan",
    "check_scoping",
    "collect_sources",
    "find_queries",
    "fingerprint",
    "scan_sources",
]
