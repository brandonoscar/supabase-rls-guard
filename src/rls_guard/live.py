"""Checks that ask the database itself (``pip install "supabase-rls-guard[live]"``).

The static checks read migrations, so they cannot see tables a library
creates at runtime (an embeddings store, a job queue) or a migration someone
applied by hand. These read the catalog, in the exposed schemas:

* tables with RLS off;
* tables owned by ``anon`` or ``authenticated`` without ``force row level
  security``: a table's owner skips its RLS, so every user signed in as that
  role reads every row;
* views that are not ``security_invoker``;
* views, materialized views and foreign tables that ``anon`` or
  ``authenticated`` holds any privilege on, a column grant included.

A schema in the config that doesn't exist in the database is a "could not
run", not a pass. The checks read names only, never rows, so a finding can go
into an issue without carrying anyone's data.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from rls_guard.migrations import BROWSER_ROLES, Finding, parse_name, pg_bool

_MISSING_SCHEMAS = """
select s from unnest($1::text[]) s
 where not exists (select 1 from pg_namespace where nspname = s)
 order by 1
"""

_RELATIONS = """
select n.nspname as schema, c.relname as name, c.relkind::text as kind,
       format('%I.%I', n.nspname, c.relname) as qualified,
       c.relrowsecurity as rls, c.relforcerowsecurity as force_rls,
       pg_get_userbyid(c.relowner)::text as owner,
       coalesce(c.reloptions, '{}') as options, c.oid as oid
  from pg_class c
  join pg_namespace n on n.oid = c.relnamespace
 where c.relkind in ('r', 'p', 'v', 'm', 'f')
   and n.nspname = any($1::text[])
 order by n.nspname collate "C", c.relname collate "C"
"""

_ROLE_EXISTS = "select 1 from pg_roles where rolname = $1"

_PRIVILEGES = """
select array(
         select p from unnest(array['SELECT', 'INSERT', 'UPDATE', 'DELETE', 'TRUNCATE',
                                    'REFERENCES', 'TRIGGER']) p
          where has_table_privilege($1, $2::oid, p)
       ) as whole,
       array(
         select p from unnest(array['SELECT', 'INSERT', 'UPDATE', 'REFERENCES']) p
          where has_any_column_privilege($1, $2::oid, p)
            and not has_table_privilege($1, $2::oid, p)
       ) as columns
"""


class LiveConfigError(ValueError):
    """The config names something the database doesn't have."""


def _allowed(row: Any, allowlist: Sequence[str]) -> bool:
    for entry in allowlist:
        schema, name = parse_name(entry)
        if name == row["name"] and schema in (None, row["schema"]):
            return True
    return False


def _invoker(options: Sequence[str]) -> bool:
    for option in options:
        key, _, value = option.partition("=")
        if key.strip().lower() == "security_invoker":
            return pg_bool(value)
    return False


async def _relations(conn: Any, schemas: Sequence[str]) -> list[Any]:
    missing = [r["s"] for r in await conn.fetch(_MISSING_SCHEMAS, list(schemas))]
    if missing:
        raise LiveConfigError(
            f"schema(s) {missing} don't exist in this database: a typo here would check "
            "nothing. Names are lower-cased unless quoted, as in SQL"
        )
    return list(await conn.fetch(_RELATIONS, list(schemas)))


async def _held(conn: Any, role: str, oid: int) -> str:
    row = await conn.fetchrow(_PRIVILEGES, role, oid)
    whole, columns = list(row["whole"]), list(row["columns"])
    if len(whole) == 7:
        return "all privileges"
    return ", ".join([*whole, *(f"{p} (some columns)" for p in columns)])


async def tables_without_rls(
    conn: Any, *, schemas: Sequence[str] = ("public",), allowlist: Sequence[str] = ()
) -> list[Finding]:
    return [
        Finding("live-table-rls", row["qualified"], "row level security is off")
        for row in await _relations(conn, schemas)
        if row["kind"] in ("r", "p") and not row["rls"] and not _allowed(row, allowlist)
    ]


async def tables_owned_by_api_roles(
    conn: Any, *, schemas: Sequence[str] = ("public",), roles: Sequence[str] = BROWSER_ROLES
) -> list[Finding]:
    return [
        Finding(
            "live-table-owner",
            row["qualified"],
            f"owned by {row['owner']}, so its row level security doesn't apply to "
            f"{row['owner']}; force it or give the table another owner",
        )
        for row in await _relations(conn, schemas)
        if row["kind"] in ("r", "p") and row["owner"] in roles and not row["force_rls"]
    ]


async def unsafe_views(
    conn: Any,
    *,
    schemas: Sequence[str] = ("public",),
    roles: Sequence[str] = BROWSER_ROLES,
) -> list[Finding]:
    """Views that aren't ``security_invoker``, and views, materialized views
    and foreign tables a browser role holds any privilege on."""
    findings: list[Finding] = []
    present_roles = [r for r in roles if await conn.fetchrow(_ROLE_EXISTS, r) is not None]
    check = {"v": "live-view-grant", "m": "live-matview-grant", "f": "live-foreign-table-grant"}
    for row in await _relations(conn, schemas):
        if row["kind"] not in check:
            continue
        if row["kind"] == "v" and not _invoker(row["options"]):
            findings.append(
                Finding(
                    "live-view-invoker", row["qualified"], "not security_invoker: it bypasses RLS"
                )
            )
        for role in present_roles:
            held = await _held(conn, role, row["oid"])
            if held:
                findings.append(
                    Finding(check[row["kind"]], row["qualified"], f"{role} holds {held} on it")
                )
    return findings


async def run_all(
    dsn: str,
    *,
    schemas: Sequence[str] = ("public",),
    rls_off_allowlist: Sequence[str] = ("spatial_ref_sys",),
) -> list[Finding]:
    import asyncpg

    conn = await asyncpg.connect(dsn, statement_cache_size=0)
    try:
        return [
            *await tables_without_rls(conn, schemas=schemas, allowlist=rls_off_allowlist),
            *await tables_owned_by_api_roles(conn, schemas=schemas),
            *await unsafe_views(conn, schemas=schemas),
        ]
    finally:
        await conn.close()


__all__ = [
    "LiveConfigError",
    "run_all",
    "tables_owned_by_api_roles",
    "tables_without_rls",
    "unsafe_views",
]
