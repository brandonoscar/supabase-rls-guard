"""Static checks over your SQL migrations. No database needed.

The migrations are replayed in order, statement by statement, and the checks
read where that leaves each table and view:

**Every table gets row-level security.** On Supabase, a table in an exposed
schema is reachable by the ``anon`` and ``authenticated`` roles through the
API, and the anon key ships in your frontend. A table whose RLS is off after
the last migration is readable by anyone holding it. The enable may come in a
later migration than the create. A later ``disable row level security`` counts.
So does a ``drop`` and re-``create``, a ``select ... into``, or an ``alter table
... set schema`` that moves a table into an exposed schema.

**Every view keeps RLS in force.** ``enable row level security`` protects the
table, not a view someone defines over it later. A view runs with its owner's
rights unless it is ``security_invoker``, and the owner is usually
``postgres``, which bypasses RLS. Supabase's default privileges also grant
every new table and view to ``anon`` and ``authenticated``. Together, any new
view is a world-readable window around RLS. The check: at the end, every view
is ``security_invoker`` and neither browser role holds a privilege on it.
``create or replace view`` without the option drops it, and a re-created view
gets the default grant back. A materialized view can't be
``security_invoker``, and a foreign table can't have RLS, so for those only
the grants count.

**Reading SQL the way Postgres does.** A small tokenizer drops comments
(nested ones too), and keeps string literals, quoted identifiers and
``$tag$`` bodies whole, so prose and data never count as statements. A ``DO``
block runs when its migration runs, so its statements count. A function body
doesn't run, so its statements don't. An unqualified name goes to the first
schema on the ``search_path``, which ``set search_path`` and
``set_config('search_path', ...)`` change. Each file starts from ``public``.

A migration kept for history but never applied starts with the line
``-- rls-guard: never-applied``, and is skipped: a never-applied migration that
"enables RLS" is how a table ships without it. Only that first line counts,
so a comment like "do not re-run" elsewhere skips nothing.
"""

from __future__ import annotations

import itertools
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass, field
from pathlib import Path

NEVER_APPLIED = "-- rls-guard: never-applied"
DEFAULT_SCHEMAS = ("public",)
BROWSER_ROLES = ("anon", "authenticated")
ALL_PRIVILEGES = frozenset(
    {"select", "insert", "update", "delete", "truncate", "references", "trigger"}
)
_PRIVILEGE_WORDS = ALL_PRIVILEGES | {"maintain"}  # MAINTAIN: Postgres 17 and later

_NEVER_APPLIED_LINE = re.compile(r"--\s*rls-guard:\s*never-applied\b", re.IGNORECASE)
_SPACE = re.compile(r"\s+")
_WORD = re.compile(r"[^\W\d][\w$]*")
_NUMBER = re.compile(r"(?:\d+(?:\.\d*)?|\.\d+)(?:[eE][+-]?\d+)?")
_PARAM = re.compile(r"\$\d+")
_DOLLAR = re.compile(r"\$(?:[^\W\d]\w*)?\$")
_COMMENT_MARK = re.compile(r"/\*|\*/")
_COPY_END = re.compile(r"^\\\.[ \t]*\r?$", re.MULTILINE)
_PLAIN_NAME = re.compile(r"[a-z_][a-z0-9_$]*")
_ASCII_LOWER = str.maketrans("ABCDEFGHIJKLMNOPQRSTUVWXYZ", "abcdefghijklmnopqrstuvwxyz")


# --- tokenizer ---------------------------------------------------------------


@dataclass(frozen=True)
class Token:
    """One SQL token. ``word`` text is folded to lower case the way Postgres
    folds unquoted names; ``ident`` is a quoted identifier, exact; ``string``
    and ``dollar`` hold the literal's value."""

    kind: str  # word, ident, string, dollar, number, param, op
    text: str
    line: int


@dataclass(frozen=True)
class Statement:
    tokens: tuple[Token, ...]
    line: int
    text: str


class SqlSyntaxError(ValueError):
    """SQL that Postgres would refuse to run: an unterminated string,
    identifier, ``$tag$`` body or comment."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


def _line_at(sql: str, offset: int) -> int:
    return sql.count("\n", 0, offset) + 1


def _quoted(sql: str, start: int, quote: str, *, backslash: bool = False) -> tuple[str, int]:
    """The value of the quoted string or identifier whose opening quote is at
    ``start``, and the index just past its closing quote."""
    out: list[str] = []
    i, n = start + 1, len(sql)
    while i < n:
        c = sql[i]
        if backslash and c == "\\" and i + 1 < n:
            out.append(sql[i + 1])
            i += 2
        elif c == quote:
            if sql.startswith(quote, i + 1):
                out.append(quote)
                i += 2
            else:
                return "".join(out), i + 1
        else:
            out.append(c)
            i += 1
    what = "quoted identifier" if quote == '"' else "string"
    raise SqlSyntaxError(f"unterminated {what}", _line_at(sql, start))


def _block_comment_end(sql: str, start: int) -> int:
    """The index just past the ``*/`` closing the comment at ``start``.
    Postgres nests block comments, so ``/* /* */ */`` is one comment."""
    depth, i = 0, start
    while (m := _COMMENT_MARK.search(sql, i)) is not None:
        depth += 1 if m.group() == "/*" else -1
        i = m.end()
        if depth == 0:
            return i
    raise SqlSyntaxError("unterminated /* comment", _line_at(sql, start))


def _copies_from_stdin(tokens: Sequence[Token]) -> bool:
    if not tokens or tokens[0].text != "copy" or tokens[0].kind != "word":
        return False
    words = [t.text for t in tokens if t.kind == "word"]
    return any(a == "from" and b == "stdin" for a, b in itertools.pairwise(words))


def tokenize(sql: str) -> list[Statement]:
    """Split SQL into statements of tokens, the way Postgres reads it.

    Comments are dropped; ``;`` ends a statement; string literals, quoted
    identifiers and dollar-quoted bodies are single tokens, so a ``--`` or a
    ``;`` inside one is data. Raises :class:`SqlSyntaxError` on text Postgres
    would refuse.
    """
    statements: list[Statement] = []
    tokens: list[Token] = []
    first = -1
    i, n, line = 0, len(sql), 1

    def close(end: int) -> None:
        nonlocal tokens, first
        if tokens:
            statements.append(Statement(tuple(tokens), tokens[0].line, sql[first:end].strip()))
        tokens, first = [], -1

    while i < n:
        c = sql[i]
        if c.isspace():
            m = _SPACE.match(sql, i)
            assert m is not None
            line += m.group().count("\n")
            i = m.end()
            continue
        if sql.startswith("--", i):
            j = sql.find("\n", i)
            i = n if j < 0 else j
            continue
        if sql.startswith("/*", i):
            j = _block_comment_end(sql, i)
            line += sql.count("\n", i, j)
            i = j
            continue
        if c == ";":
            close(i)
            i += 1
            if statements and _copies_from_stdin(statements[-1].tokens):
                # COPY ... FROM stdin: the rows that follow are data up to "\.".
                j = sql.find("\n", i)
                end = n
                if j >= 0 and (m2 := _COPY_END.search(sql, j + 1)) is not None:
                    end = m2.end()
                line += sql.count("\n", i, end)
                i = end
            continue
        start = i
        kind: str
        text: str
        if c == "'":
            kind = "string"
            text, i = _quoted(sql, i, "'")
        elif c == '"':
            kind = "ident"
            text, i = _quoted(sql, i, '"')
        elif c == "$":
            if (m := _PARAM.match(sql, i)) is not None:
                kind, text, i = "param", m.group(), m.end()
            elif (m := _DOLLAR.match(sql, i)) is not None:
                tag = m.group()
                end = sql.find(tag, m.end())
                if end < 0:
                    raise SqlSyntaxError(f"unterminated {tag} body", line)
                kind, text, i = "dollar", sql[m.end() : end], end + len(tag)
            else:
                kind, text, i = "op", "$", i + 1
        elif (m := _WORD.match(sql, i)) is not None:
            word = m.group().translate(_ASCII_LOWER)
            after = m.end()
            if word in ("e", "b", "x", "n") and sql.startswith("'", after):
                kind = "string"
                text, i = _quoted(sql, after, "'", backslash=word == "e")
            elif word == "u" and sql.startswith("&'", after):
                kind = "string"
                text, i = _quoted(sql, after + 1, "'")
            elif word == "u" and sql.startswith('&"', after):
                kind = "ident"
                text, i = _quoted(sql, after + 1, '"')
            else:
                kind, text, i = "word", word, after
        elif (m := _NUMBER.match(sql, i)) is not None:
            kind, text, i = "number", m.group(), m.end()
        elif sql.startswith("::", i):
            kind, text, i = "op", "::", i + 2
        else:
            kind, text, i = "op", c, i + 1
        if first < 0:
            first = start
        tokens.append(Token(kind, text, line))
        line += sql.count("\n", start, i)
    close(n)
    return statements


def split_statements(sql: str) -> list[str]:
    """The text of each statement in ``sql``, without comments around it."""
    return [s.text for s in tokenize(sql)]


def is_never_applied(sql: str) -> bool:
    """True when the file's first non-blank line is ``-- rls-guard: never-applied``."""
    for raw in sql.lstrip("﻿").splitlines():
        if raw.strip():
            return _NEVER_APPLIED_LINE.match(raw.strip()) is not None
    return False


def parse_name(raw: str) -> tuple[str | None, str]:
    """A table or schema name as SQL reads it: ``notes``, ``public.notes`` or
    ``"Mixed"."Case"``. Unquoted names are lower-cased, as Postgres does."""
    try:
        statements = tokenize(raw)
    except SqlSyntaxError:
        statements = []
    tokens = list(statements[0].tokens) if len(statements) == 1 else []
    parsed = _name(tokens, 0)
    if parsed is None or parsed[2] != len(tokens):
        raise ValueError(f"{raw!r} is not a name: write it as in SQL, e.g. public.notes")
    return parsed[0], parsed[1]


def quote_name(name: str) -> str:
    return name if _PLAIN_NAME.fullmatch(name) else '"' + name.replace('"', '""') + '"'


def qualified(schema: str, name: str) -> str:
    return f"{quote_name(schema)}.{quote_name(name)}"


# --- token helpers -------------------------------------------------------------


def _word(t: Sequence[Token], i: int, *words: str) -> bool:
    """``t[i:]`` starts with these unquoted words."""
    if i + len(words) > len(t):
        return False
    return all(t[i + k].kind == "word" and t[i + k].text == w for k, w in enumerate(words))


def _op(t: Sequence[Token], i: int, op: str) -> bool:
    return i < len(t) and t[i].kind == "op" and t[i].text == op


def _is_name(tok: Token) -> bool:
    return tok.kind in ("word", "ident")


def _name(t: Sequence[Token], i: int) -> tuple[str | None, str, int] | None:
    """A possibly qualified name at ``t[i]``: (schema or None, name, next index)."""
    parts: list[str] = []
    j = i
    while j < len(t) and _is_name(t[j]):
        parts.append(t[j].text)
        if _op(t, j + 1, "."):
            j += 2
            continue
        j += 1
        break
    if not parts:
        return None
    return (parts[-2] if len(parts) > 1 else None), parts[-1], j


def _name_list(t: Sequence[Token], i: int) -> tuple[list[tuple[str | None, str]], int]:
    names: list[tuple[str | None, str]] = []
    while (parsed := _name(t, i)) is not None:
        names.append((parsed[0], parsed[1]))
        i = parsed[2]
        if not _op(t, i, ","):
            break
        i += 1
    return names, i


def _close_paren(t: Sequence[Token], i: int) -> int:
    """``t[i]`` is ``(``: the index just past its matching ``)``."""
    depth = 0
    for j in range(i, len(t)):
        if _op(t, j, "("):
            depth += 1
        elif _op(t, j, ")"):
            depth -= 1
            if depth == 0:
                return j + 1
    return len(t)


def _options(t: Sequence[Token], i: int) -> tuple[dict[str, str | None], int]:
    """``( key [= value] [, ...] )`` at ``t[i]``; a bare key has value None."""
    end = _close_paren(t, i)
    options: dict[str, str | None] = {}
    for item in _split_commas(t[i + 1 : end - 1]):
        if not item or not _is_name(item[0]):
            continue
        key = item[0].text
        k = 1
        while _op(item, k, ".") and k + 1 < len(item):
            key += "." + item[k + 1].text
            k += 2
        value = item[k + 1].text if _op(item, k, "=") and k + 1 < len(item) else None
        options[key.lower()] = value
    return options, end


def _split_commas(t: Sequence[Token]) -> list[list[Token]]:
    """Split on commas outside parentheses."""
    parts: list[list[Token]] = [[]]
    depth = 0
    for tok in t:
        if tok.kind == "op" and tok.text == "(":
            depth += 1
        elif tok.kind == "op" and tok.text == ")":
            depth -= 1
        if depth == 0 and tok.kind == "op" and tok.text == ",":
            parts.append([])
        else:
            parts[-1].append(tok)
    return parts


def pg_bool(value: str | None) -> bool:
    """Postgres's reading of a boolean option: a bare option is true, and so
    is any unique prefix of true, yes or on, or 1."""
    if value is None:
        return True
    v = value.strip().lower()
    if not v:
        return False
    if v == "1" or "true".startswith(v) or "yes".startswith(v):
        return True
    return len(v) >= 2 and "on".startswith(v)


def _invoker(options: dict[str, str | None]) -> bool:
    return "security_invoker" in options and pg_bool(options["security_invoker"])


def _parse_search_path(raw: str) -> list[str]:
    out: list[str] = []
    for part in re.findall(r'(?:"(?:[^"]|"")*"|[^,])+', raw):
        item = part.strip()
        if item.startswith('"') and item.endswith('"') and len(item) >= 2:
            out.append(item[1:-1].replace('""', '"'))
        elif item:
            out.append(item.translate(_ASCII_LOWER))
    return out


# --- replay --------------------------------------------------------------------


@dataclass(frozen=True)
class Finding:
    check: str
    name: str
    detail: str

    def __str__(self) -> str:
        return f"[{self.check}] {self.name}: {self.detail}"


@dataclass(frozen=True)
class Migration:
    """One migration file: its name (as findings print it) and its SQL."""

    name: str
    sql: str


@dataclass
class _Relation:
    kind: str  # table, view, matview, foreign, unknown
    created_in: str | None = None  # None: created somewhere these migrations don't show
    rls: bool | None = None  # None: unknown
    rls_off_in: str | None = None
    moved_in: str | None = None
    force_rls: bool = False
    owner: str | None = None
    invoker: bool | None = None
    grants: dict[str, set[str]] = field(default_factory=dict)
    default_grant: set[str] = field(default_factory=set)  # roles whose grant is untouched


_NON_TABLE_OBJECTS = frozenset(
    {
        "sequence",
        "database",
        "domain",
        "foreign",
        "function",
        "procedure",
        "routine",
        "language",
        "large",
        "parameter",
        "schema",
        "tablespace",
        "type",
    }
)
_DDL = frozenset({"create", "alter", "drop", "grant", "revoke"})
_PLPGSQL_LEAD = frozenset({"begin", "then", "else", "loop", "declare"})


class _Replay:
    def __init__(self) -> None:
        self.relations: dict[tuple[str, str], _Relation] = {}
        self.schemas_seen: set[str] = set()
        self.problems: list[Finding] = []
        self.imports: list[tuple[str, str]] = []  # (schema, file)
        self.file = ""
        self.path: list[str] = ["public"]

    # -- driving

    def run(self, migrations: Sequence[Migration]) -> None:
        for migration in migrations:
            if is_never_applied(migration.sql):
                continue
            self.file = migration.name
            self.path = ["public"]
            try:
                statements = tokenize(migration.sql)
            except SqlSyntaxError as exc:
                self.problems.append(
                    Finding(
                        "parse",
                        migration.name,
                        f"{exc}: Postgres would refuse this file, and rls-guard can't check it",
                    )
                )
                continue
            for statement in statements:
                self.statement(list(statement.tokens), top_level=True)

    def statement(self, t: list[Token], *, top_level: bool) -> None:
        if not t or t[0].kind != "word":
            return
        head = t[0].text
        if head == "create":
            self.create(t)
        elif head == "alter":
            self.alter(t)
        elif head == "drop":
            self.drop(t)
        elif head in ("grant", "revoke"):
            self.privileges(t, grant=head == "grant")
        elif head in ("set", "reset"):
            self.set_path(t)
        elif head in ("select", "with"):
            if top_level:
                self.select_into(t)
            self.set_config(t)
        elif head == "do":
            self.do_block(t)
        elif head == "import":
            self.import_foreign(t)

    # -- names and state

    def creation_schema(self) -> str | None:
        for schema in self.path:
            if schema == "$user" or schema == "pg_catalog" or schema.startswith("pg_temp"):
                continue
            return schema
        return None

    def resolve(self, schema: str | None, name: str) -> tuple[str, str] | None:
        if schema is not None:
            return schema, name
        for candidate in self.path:
            if (candidate, name) in self.relations:
                return candidate, name
        fallback = self.creation_schema()
        return (fallback, name) if fallback is not None else None

    def new(self, key: tuple[str, str], kind: str) -> _Relation:
        relation = _Relation(
            kind=kind,
            created_in=self.file,
            rls=False if kind == "table" else None,
            invoker=False if kind == "view" else None,
            grants={role: set(ALL_PRIVILEGES) for role in BROWSER_ROLES},
            default_grant=set(BROWSER_ROLES),
        )
        self.relations[key] = relation
        self.schemas_seen.add(key[0])
        return relation

    def existing(self, key: tuple[str, str], kind: str) -> _Relation:
        """The relation at ``key``, or a placeholder for one these migrations
        never created (a table made by hand, or by an extension)."""
        relation = self.relations.get(key)
        if relation is None:
            relation = _Relation(kind=kind)
            self.relations[key] = relation
            self.schemas_seen.add(key[0])
        return relation

    def move(self, old: tuple[str, str], new: tuple[str, str]) -> None:
        relation = self.relations.pop(old, None)
        if relation is None:
            return
        if new[0] != old[0]:
            relation.moved_in = self.file
        self.relations[new] = relation
        self.schemas_seen.add(new[0])

    # -- statements

    def create(self, t: list[Token]) -> None:
        i = 1
        replace = temp = materialized = foreign = False
        while i < len(t) and t[i].kind == "word":
            w = t[i].text
            if w == "or" and _word(t, i + 1, "replace"):
                replace = True
                i += 2
            elif w in ("temp", "temporary"):
                temp = True
                i += 1
            elif w in ("global", "local", "unlogged", "recursive"):
                i += 1
            elif w == "materialized":
                materialized = True
                i += 1
            elif w == "foreign" and _word(t, i + 1, "table"):
                foreign = True
                i += 1
            else:
                break
        if _word(t, i, "table"):
            self.create_table(t, i + 1, temp=temp, foreign=foreign)
        elif _word(t, i, "view"):
            self.create_view(t, i + 1, temp=temp, replace=replace, materialized=materialized)
        elif _word(t, i, "schema"):
            self.create_schema(t, i + 1)

    def create_table(self, t: list[Token], i: int, *, temp: bool, foreign: bool) -> None:
        if_not_exists = _word(t, i, "if", "not", "exists")
        if if_not_exists:
            i += 3
        parsed = _name(t, i)
        if parsed is None or temp or parsed[0] == "pg_temp":
            return
        self.create_relation(parsed[0], parsed[1], "foreign" if foreign else "table", if_not_exists)

    def create_relation(
        self, schema: str | None, name: str, kind: str, if_not_exists: bool
    ) -> _Relation | None:
        target = schema if schema is not None else self.creation_schema()
        if target is None:
            return None
        key = (target, name)
        if if_not_exists and key in self.relations:
            return None
        return self.new(key, kind)

    def create_view(
        self, t: list[Token], i: int, *, temp: bool, replace: bool, materialized: bool
    ) -> None:
        if_not_exists = _word(t, i, "if", "not", "exists")
        if if_not_exists:
            i += 3
        parsed = _name(t, i)
        if parsed is None or temp:
            return
        schema, name, j = parsed
        if _op(t, j, "("):
            j = _close_paren(t, j)
        if _word(t, j, "using"):
            j += 2
        options: dict[str, str | None] = {}
        if _word(t, j, "with") and _op(t, j + 1, "("):
            options, j = _options(t, j + 1)
        target = schema if schema is not None else self.creation_schema()
        if target is None:
            return
        key = (target, name)
        current = self.relations.get(key)
        if materialized:
            if not (if_not_exists and current is not None):
                self.new(key, "matview")
            return
        if replace and current is not None and current.kind == "view":
            # Postgres replaces the options and keeps the grants.
            current.invoker = _invoker(options)
            return
        self.new(key, "view").invoker = _invoker(options)

    def create_schema(self, t: list[Token], i: int) -> None:
        if any(tok.kind == "word" and tok.text in ("create", "grant") for tok in t[i:]):
            self.problems.append(
                Finding(
                    "parse",
                    self.file,
                    f"line {t[0].line}: CREATE SCHEMA with tables or views inside it. "
                    "rls-guard can't read those; create them in statements of their own",
                )
            )

    def alter(self, t: list[Token]) -> None:
        i = 1
        if _word(t, i, "table"):
            kind, i = "table", i + 1
        elif _word(t, i, "view"):
            kind, i = "view", i + 1
        elif _word(t, i, "materialized", "view"):
            kind, i = "matview", i + 2
        elif _word(t, i, "foreign", "table"):
            kind, i = "foreign", i + 2
        elif _word(t, i, "schema"):
            self.alter_schema(t, i + 1)
            return
        else:
            return
        if _word(t, i, "if", "exists"):
            i += 2
        if _word(t, i, "only"):
            i += 1
        parsed = _name(t, i)
        if parsed is None:
            return
        schema, name, j = parsed
        if _op(t, j, "*"):
            j += 1
        key = self.resolve(schema, name)
        if key is None:
            return
        if _word(t, j, "rename", "to"):
            renamed = _name(t, j + 2)
            if renamed is not None:
                self.move(key, (key[0], renamed[1]))
            return
        if _word(t, j, "set", "schema"):
            target = _name(t, j + 2)
            if target is not None:
                self.move(key, (target[1], key[1]))
            return
        for action in _split_commas(t[j:]):
            self.alter_action(key, kind, action)

    def alter_action(self, key: tuple[str, str], kind: str, a: list[Token]) -> None:
        if _word(a, 0, "enable", "row", "level", "security"):
            relation = self.existing(key, "table")
            relation.rls, relation.rls_off_in = True, None
        elif _word(a, 0, "disable", "row", "level", "security"):
            relation = self.existing(key, "table")
            relation.rls, relation.rls_off_in = False, self.file
        elif _word(a, 0, "force", "row", "level", "security"):
            self.existing(key, "table").force_rls = True
        elif _word(a, 0, "no", "force", "row", "level", "security"):
            self.existing(key, "table").force_rls = False
        elif _word(a, 0, "owner", "to") and len(a) > 2 and _is_name(a[2]):
            owner = a[2].text
            if a[2].kind == "word" and owner in ("current_user", "current_role", "session_user"):
                owner = ""
            self.existing(key, kind).owner = owner or None
        elif _word(a, 0, "set") and _op(a, 1, "("):
            options, _ = _options(a, 1)
            if "security_invoker" in options:
                self.existing(key, "view").invoker = _invoker(options)
        elif _word(a, 0, "reset") and _op(a, 1, "("):
            options, _ = _options(a, 1)
            if "security_invoker" in options:
                self.existing(key, "view").invoker = False

    def alter_schema(self, t: list[Token], i: int) -> None:
        parsed = _name(t, i)
        if parsed is None or not _word(t, parsed[2], "rename", "to"):
            return
        renamed = _name(t, parsed[2] + 2)
        if renamed is None:
            return
        old, new = parsed[1], renamed[1]
        for key in [k for k in self.relations if k[0] == old]:
            self.relations[(new, key[1])] = self.relations.pop(key)
        self.schemas_seen.add(new)

    def drop(self, t: list[Token]) -> None:
        i = 1
        if _word(t, i, "table") or _word(t, i, "view"):
            i += 1
        elif _word(t, i, "materialized", "view") or _word(t, i, "foreign", "table"):
            i += 2
        elif _word(t, i, "schema"):
            i += 1
            if _word(t, i, "if", "exists"):
                i += 2
            names, _ = _name_list(t, i)
            if any(tok.kind == "word" and tok.text == "cascade" for tok in t):
                dropped = {n for _, n in names}
                for key in [k for k in self.relations if k[0] in dropped]:
                    del self.relations[key]
            return
        else:
            return
        if _word(t, i, "if", "exists"):
            i += 2
        names, _ = _name_list(t, i)
        for schema, name in names:
            target = self.resolve(schema, name)
            if target is not None:
                self.relations.pop(target, None)

    def privileges(self, t: list[Token], *, grant: bool) -> None:
        i = 1
        if not grant and _word(t, i, "grant", "option", "for"):
            return  # takes away the grant option, not the privilege
        privileges, i = self.privilege_list(t, i)
        if privileges is None or not _word(t, i, "on"):
            return  # a role membership, or a grant on something other than a table
        i += 1
        if _word(t, i, "all", "tables", "in", "schema"):
            schemas, i = _name_list(t, i + 4)
            wanted = {n for _, n in schemas}
            keys = [k for k in self.relations if k[0] in wanted]
        else:
            if i < len(t) and t[i].kind == "word" and t[i].text in _NON_TABLE_OBJECTS:
                return
            if _word(t, i, "table"):
                i += 1
            names, i = _name_list(t, i)
            keys = [k for s, n in names if (k := self.resolve(s, n)) is not None]
        if not _word(t, i, "to" if grant else "from"):
            return
        roles = _grantees(t, i + 1)
        for key in keys:
            relation = self.relations.get(key)
            if relation is None:
                if not grant:
                    continue
                relation = self.existing(key, "unknown")
            for role in roles:
                relation.default_grant.discard(role)
                held = relation.grants.setdefault(role, set())
                if grant:
                    held.update(privileges)
                else:
                    for privilege in privileges:
                        held.discard(privilege)
                        if "(" not in privilege:
                            # A table-level revoke takes the column grants too.
                            held.difference_update(
                                {p for p in held if p.startswith(privilege + "(")}
                            )

    @staticmethod
    def privilege_list(t: list[Token], i: int) -> tuple[set[str] | None, int]:
        if _word(t, i, "all"):
            i += 1
            if _word(t, i, "privileges"):
                i += 1
            if _op(t, i, "("):
                return None, i  # all (columns): rare enough to leave alone
            return set(ALL_PRIVILEGES), i
        privileges: set[str] = set()
        while i < len(t) and t[i].kind == "word" and t[i].text in _PRIVILEGE_WORDS:
            privilege = t[i].text
            i += 1
            if _op(t, i, "("):
                end = _close_paren(t, i)
                columns = [tok.text for tok in t[i + 1 : end - 1] if _is_name(tok)]
                privileges.update(f"{privilege}({column})" for column in columns)
                i = end
            else:
                privileges.add(privilege)
            if not _op(t, i, ","):
                break
            i += 1
        return (privileges or None), i

    def set_path(self, t: list[Token]) -> None:
        if t[0].text == "reset":
            if _word(t, 1, "search_path") or _word(t, 1, "all"):
                self.path = ["public"]
            return
        i = 1
        if _word(t, i, "session") or _word(t, i, "local"):
            i += 1
        if not _word(t, i, "search_path"):
            return
        i += 1
        if not (_word(t, i, "to") or _op(t, i, "=")):
            return
        i += 1
        if _word(t, i, "default"):
            self.path = ["public"]
            return
        path: list[str] = []
        for tok in t[i:]:
            if tok.kind in ("word", "ident"):
                path.append(tok.text)
            elif tok.kind == "string":
                path.extend(_parse_search_path(tok.text))
        self.path = path

    def set_config(self, t: list[Token]) -> None:
        for k in range(len(t) - 4):
            if (
                _word(t, k, "set_config")
                and _op(t, k + 1, "(")
                and t[k + 2].kind == "string"
                and t[k + 2].text.lower() == "search_path"
                and _op(t, k + 3, ",")
                and t[k + 4].kind == "string"
            ):
                self.path = _parse_search_path(t[k + 4].text)

    def select_into(self, t: list[Token]) -> None:
        depth = 0
        for k, tok in enumerate(t):
            if tok.kind == "op" and tok.text == "(":
                depth += 1
            elif tok.kind == "op" and tok.text == ")":
                depth -= 1
            elif depth == 0 and tok.kind == "word" and tok.text == "into":
                if k > 0 and t[k - 1].kind == "word" and t[k - 1].text in ("insert", "merge"):
                    return
                j = k + 1
                if _word(t, j, "temporary") or _word(t, j, "temp"):
                    return
                if _word(t, j, "unlogged"):
                    j += 1
                if _word(t, j, "table"):
                    j += 1
                parsed = _name(t, j)
                if parsed is not None:
                    self.create_relation(parsed[0], parsed[1], "table", False)
                return

    def do_block(self, t: list[Token]) -> None:
        language, body = "plpgsql", None
        for k, tok in enumerate(t[1:], 1):
            if tok.kind == "word" and tok.text == "language" and k + 1 < len(t):
                language = t[k + 1].text.lower()
            elif tok.kind in ("dollar", "string") and body is None:
                body = tok.text
        if body is None or language != "plpgsql":
            return
        try:
            inner = tokenize(body)
        except SqlSyntaxError as exc:
            self.problems.append(
                Finding("parse", self.file, f"a DO block at line {t[0].line}: {exc}")
            )
            return
        for statement in inner:
            tokens = list(statement.tokens)
            start = _first_ddl(tokens)
            if start is not None:
                self.statement(tokens[start:], top_level=False)

    def import_foreign(self, t: list[Token]) -> None:
        if not _word(t, 1, "foreign", "schema"):
            return
        for k in range(len(t) - 1):
            if _word(t, k, "into") and (parsed := _name(t, k + 1)) is not None:
                self.imports.append((parsed[1], self.file))
                self.schemas_seen.add(parsed[1])
                return


def _grantees(t: list[Token], i: int) -> list[str]:
    """The roles in ``to a, group b, public``."""
    roles: list[str] = []
    while i < len(t):
        if _word(t, i, "group"):
            i += 1
        if i >= len(t) or not _is_name(t[i]):
            break
        roles.append(t[i].text)
        i += 1
        if not _op(t, i, ","):
            break
        i += 1
    return roles


def _first_ddl(t: list[Token]) -> int | None:
    """Where the DDL starts in a PL/pgSQL fragment like ``begin if ... then
    create table ...``: the first create/alter/drop/grant/revoke outside
    parentheses, or a set/reset that opens the fragment or a block."""
    depth = 0
    for k, tok in enumerate(t):
        if tok.kind == "op" and tok.text == "(":
            depth += 1
        elif tok.kind == "op" and tok.text == ")":
            depth -= 1
        elif depth == 0 and tok.kind == "word":
            if tok.text in _DDL:
                return k
            if tok.text in ("set", "reset") and (
                k == 0 or (t[k - 1].kind == "word" and t[k - 1].text in _PLPGSQL_LEAD)
            ):
                return k
    return None


# --- findings ------------------------------------------------------------------


def _as_migrations(items: Iterable[str | Migration]) -> list[Migration]:
    return [
        item if isinstance(item, Migration) else Migration(f"migration {n}", item)
        for n, item in enumerate(items, 1)
    ]


def _parse_allowlist(entries: Iterable[str]) -> list[tuple[str | None, str]]:
    return [parse_name(entry) for entry in entries]


def _allowed(key: tuple[str, str], allowlist: Sequence[tuple[str | None, str]]) -> bool:
    return any(name == key[1] and schema in (None, key[0]) for schema, name in allowlist)


def _held(relation: _Relation, role: str) -> set[str]:
    return relation.grants.get(role, set()) | relation.grants.get("public", set())


def _describe(privileges: set[str]) -> str:
    if privileges >= ALL_PRIVILEGES:
        return "all privileges"
    return ", ".join(sorted(privileges))


def _grant_findings(
    check: str, key: tuple[str, str], relation: _Relation, roles: Sequence[str], why: str
) -> list[Finding]:
    name = qualified(*key)
    findings = []
    for role in roles:
        held = _held(relation, role)
        if not held:
            continue
        default = (
            " (Supabase grants every new relation to it)"
            if (role in relation.default_grant and "public" not in relation.grants)
            else ""
        )
        findings.append(
            Finding(
                check,
                name,
                f"{role} still holds {_describe(held)} on it{default}; {why}"
                f"`revoke all on {name} from {role}`",
            )
        )
    return findings


def _table_findings(
    replay: _Replay,
    exposed: set[str],
    allowlist: Sequence[tuple[str | None, str]],
    roles: Sequence[str],
) -> list[Finding]:
    findings: list[Finding] = []
    for key in sorted(replay.relations):
        relation = replay.relations[key]
        if key[0] not in exposed:
            continue
        name = qualified(*key)
        if relation.kind == "table":
            if relation.rls is False and not _allowed(key, allowlist):
                if relation.rls_off_in is not None:
                    detail = (
                        f"row level security disabled in {relation.rls_off_in} "
                        "and not enabled again"
                    )
                elif relation.moved_in is not None:
                    detail = (
                        f"moved into {key[0]} by {relation.moved_in} with row level security off"
                    )
                else:
                    detail = (
                        f"created in {relation.created_in}; no later migration enables "
                        "row level security"
                    )
                findings.append(Finding("table-rls", name, detail))
            if relation.owner in roles and not relation.force_rls and relation.rls is not False:
                findings.append(
                    Finding(
                        "table-owner",
                        name,
                        f"owned by {relation.owner}, so its row level security doesn't apply "
                        f"to {relation.owner}; add `alter table {name} force row level security` "
                        "or give it another owner",
                    )
                )
        elif relation.kind == "foreign":
            findings.extend(
                _grant_findings(
                    "foreign-table-grant",
                    key,
                    relation,
                    roles,
                    "a foreign table can't have row level security, so revoke it: ",
                )
            )
    for schema, file in replay.imports:
        if schema in exposed:
            findings.append(
                Finding(
                    "foreign-import",
                    schema,
                    f"`import foreign schema` in {file} brings in tables rls-guard can't "
                    "name, and a foreign table can't have row level security. Import into a "
                    "schema the API doesn't expose",
                )
            )
    return findings


def _view_findings(replay: _Replay, exposed: set[str], roles: Sequence[str]) -> list[Finding]:
    findings: list[Finding] = []
    for key in sorted(replay.relations):
        relation = replay.relations[key]
        if key[0] not in exposed:
            continue
        name = qualified(*key)
        if relation.kind == "view":
            if relation.invoker is False:
                findings.append(
                    Finding(
                        "view-invoker",
                        name,
                        "runs with its owner's rights, which bypass RLS; add "
                        f"`alter view {name} set (security_invoker = true)`",
                    )
                )
            findings.extend(_grant_findings("view-grant", key, relation, roles, "add "))
        elif relation.kind == "matview":
            findings.extend(
                _grant_findings(
                    "matview-grant",
                    key,
                    relation,
                    roles,
                    "a materialized view can't be security_invoker and RLS doesn't filter "
                    "it, so revoke it: ",
                )
            )
    return findings


def _replay(sql: Iterable[str | Migration]) -> _Replay:
    replay = _Replay()
    replay.run(_as_migrations(sql))
    return replay


def _exposed(schemas: Iterable[str]) -> set[str]:
    return {parse_name(s)[1] for s in schemas}


def check_migrations(
    migrations: Iterable[str | Migration],
    *,
    schemas: Sequence[str] = DEFAULT_SCHEMAS,
    allowlist: Iterable[str] = (),
    roles: Sequence[str] = BROWSER_ROLES,
) -> list[Finding]:
    """Every migration finding, in the order the CLI prints them: files it
    can't read, exposed schemas nothing is created in, tables, then views."""
    replay = _replay(migrations)
    exposed = _exposed(schemas)
    findings = list(replay.problems)
    findings.extend(
        Finding(
            "schema",
            quote_name(schema),
            "no migration creates a table or view in it. If that's right, take it out of "
            "`schemas`; if it's a typo, the checks aren't looking where your tables are",
        )
        for schema in sorted(exposed - replay.schemas_seen)
    )
    findings.extend(_table_findings(replay, exposed, _parse_allowlist(allowlist), roles))
    findings.extend(_view_findings(replay, exposed, roles))
    return findings


def tables_without_rls(
    sql_texts: Iterable[str | Migration],
    *,
    schemas: Sequence[str] = DEFAULT_SCHEMAS,
    allowlist: Iterable[str] = (),
    roles: Sequence[str] = BROWSER_ROLES,
) -> list[Finding]:
    """Tables in ``schemas`` whose RLS is off after the last migration, tables
    owned by a browser role without ``force row level security``, and foreign
    tables a browser role can still reach. Allowlist entries are names as in
    SQL: ``notes`` (any exposed schema) or ``public.notes``."""
    replay = _replay(sql_texts)
    return _table_findings(replay, _exposed(schemas), _parse_allowlist(allowlist), roles)


def unsafe_views(
    sql_texts: Iterable[str | Migration],
    *,
    schemas: Sequence[str] = DEFAULT_SCHEMAS,
    roles: Sequence[str] = BROWSER_ROLES,
) -> list[Finding]:
    """Views in ``schemas`` that are not ``security_invoker`` after the last
    migration, and views or materialized views a browser role still holds a
    privilege on."""
    return _view_findings(_replay(sql_texts), _exposed(schemas), roles)


class MigrationReadError(ValueError):
    pass


def read_migrations(patterns: Iterable[str], root: Path = Path()) -> list[Migration]:
    """Every file matching ``patterns`` (globs, relative to ``root``), in the
    order migration tools apply them: by file name."""
    files: set[Path] = set()
    for pattern in patterns:
        files.update(p for p in root.glob(pattern) if p.is_file())
    migrations = []
    for path in sorted(files, key=lambda p: (p.name, p.as_posix())):
        try:
            sql = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError) as exc:
            raise MigrationReadError(f"could not read {path}: {exc}") from exc
        try:
            name = path.relative_to(root).as_posix()
        except ValueError:
            name = path.as_posix()
        migrations.append(Migration(name, sql))
    return migrations


__all__ = [
    "BROWSER_ROLES",
    "NEVER_APPLIED",
    "Finding",
    "Migration",
    "MigrationReadError",
    "SqlSyntaxError",
    "Statement",
    "Token",
    "check_migrations",
    "is_never_applied",
    "parse_name",
    "pg_bool",
    "qualified",
    "quote_name",
    "read_migrations",
    "split_statements",
    "tables_without_rls",
    "tokenize",
    "unsafe_views",
]
