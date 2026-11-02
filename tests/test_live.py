"""Against a real Postgres: each test gets a fresh database with the Supabase
role shim and the example app's migrations applied."""

from __future__ import annotations

import asyncio
import urllib.parse
import uuid
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from rls_guard import live
from rls_guard.cli import main
from rls_guard.migrations import is_never_applied
from rls_guard.testing import apply_supabase_shim, as_user, count_visible

from .conftest import DSN

pytestmark = pytest.mark.postgres

EXAMPLE = Path(__file__).parents[1] / "examples" / "app"
COMPANY_A, COMPANY_B = str(uuid.uuid4()), str(uuid.uuid4())
USER_A, USER_B = str(uuid.uuid4()), str(uuid.uuid4())


def _with_database(dsn: str, name: str) -> str:
    parts = urllib.parse.urlsplit(dsn)
    return urllib.parse.urlunsplit(parts._replace(path=f"/{name}"))


@pytest.fixture
async def dsn() -> AsyncIterator[str]:
    import asyncpg

    name = f"rls_guard_{uuid.uuid4().hex[:10]}"
    admin = await asyncpg.connect(DSN)
    await admin.execute(f"create database {name}")
    url = _with_database(DSN, name)
    conn = await asyncpg.connect(url)
    try:
        await apply_supabase_shim(conn)
        for path in sorted((EXAMPLE / "supabase" / "migrations").glob("*.sql")):
            sql = path.read_text()
            if not is_never_applied(sql):
                await conn.execute(sql)
    finally:
        await conn.close()
    try:
        yield url
    finally:
        await admin.execute(f"drop database {name} with (force)")
        await admin.close()


@pytest.fixture
async def conn(dsn: str) -> AsyncIterator[Any]:
    import asyncpg

    connection = await asyncpg.connect(dsn)
    await connection.execute(
        """
        insert into companies (id, name) values ($1, 'Company A'), ($2, 'Company B');
        insert into company_users (company_id, user_id) values ($1, $3), ($2, $4);
        """.replace("$1", f"'{COMPANY_A}'")
        .replace("$2", f"'{COMPANY_B}'")
        .replace("$3", f"'{USER_A}'")
        .replace("$4", f"'{USER_B}'")
    )
    try:
        yield connection
    finally:
        await connection.close()


async def note(conn: Any, company: str) -> str:
    return str(
        await conn.fetchval(
            "insert into app_notes (company_id, body) values ($1, 'a note') returning id",
            company,
        )
    )


async def test_the_example_database_is_clean(dsn: str) -> None:
    assert await live.run_all(dsn) == []


async def test_a_table_created_at_runtime_without_rls_is_found(dsn: str, conn: Any) -> None:
    await conn.execute("create table public.library_cache (id int)")
    findings = await live.run_all(dsn)
    assert [(f.check, f.name) for f in findings] == [("live-table-rls", "public.library_cache")]
    assert await live.run_all(dsn, rls_off_allowlist=["library_cache"]) == []


async def test_an_unsafe_view_is_found(dsn: str, conn: Any) -> None:
    await conn.execute(
        "create view public.app_bodies as select body from public.app_notes;"
        "grant select on public.app_bodies to anon;"
    )
    findings = {(f.check, f.name, f.detail) for f in await live.run_all(dsn)}
    assert ("live-view-invoker", "public.app_bodies", "not security_invoker: it bypasses RLS") in (
        findings
    )
    assert ("live-view-grant", "public.app_bodies", "anon holds all privileges on it") in findings


async def test_one_company_cannot_read_another_companys_notes(conn: Any) -> None:
    note_a = await note(conn, COMPANY_A)
    async with as_user(conn, USER_A):
        assert await count_visible(conn, "app_notes", "id = $1", note_a) == 1
    async with as_user(conn, USER_B):
        assert await count_visible(conn, "app_notes", "id = $1", note_a) == 0
        assert await count_visible(conn, "app_notes") == 0
    async with as_user(conn, None):  # anon holds Supabase's default grant; RLS filters
        assert await count_visible(conn, "app_notes") == 0


async def test_a_user_cannot_write_into_another_company(conn: Any) -> None:
    import asyncpg

    async with as_user(conn, USER_B):
        with pytest.raises(asyncpg.InsufficientPrivilegeError, match="row-level security"):
            await conn.execute(
                "insert into app_notes (company_id, body) values ($1, 'planted')", COMPANY_A
            )
    assert await conn.fetchval("select count(*) from app_notes") == 0  # rolled back


async def test_rls_on_with_a_wrong_policy_is_caught_by_the_proof_not_the_catalog(
    dsn: str, conn: Any
) -> None:
    await conn.execute(
        """
        create table public.app_files (id serial primary key, company_id uuid not null);
        alter table public.app_files enable row level security;
        create policy "left over from debugging" on public.app_files for select using (true);
        grant select on public.app_files to authenticated;
        """
    )
    await conn.execute("insert into app_files (company_id) values ($1)", COMPANY_A)
    # The catalog says RLS is on, so the catalog check is satisfied...
    assert await live.run_all(dsn) == []
    # ...but reading as company B's user shows company A's row.
    async with as_user(conn, USER_B):
        assert await count_visible(conn, "app_files") == 1


async def test_the_cli_live_check(dsn: str, conn: Any, capsys: pytest.CaptureFixture[str]) -> None:
    # The CLI runs its own event loop, so call it from a thread.
    args = ["live", "--dsn", dsn, "--config", str(EXAMPLE / "rls-guard.toml")]
    assert await asyncio.to_thread(main, args) == 0
    await conn.execute("create table public.leaky (id int)")
    assert await asyncio.to_thread(main, args) == 1
    assert "FAIL [live-table-rls] public.leaky" in capsys.readouterr().out


def test_an_unreachable_database_could_not_run() -> None:
    assert main(["live", "--dsn", "postgresql://nobody@127.0.0.1:9/none"]) == 2


async def test_a_table_owned_by_a_browser_role_is_found(dsn: str, conn: Any) -> None:
    await conn.execute(
        """
        create table public.app_owned (id int, company_id uuid);
        insert into public.app_owned values (1, gen_random_uuid()), (2, gen_random_uuid());
        alter table public.app_owned enable row level security;
        alter table public.app_owned owner to authenticated;
        """
    )
    # RLS is on and there is no policy, yet every signed-in user reads every row.
    async with as_user(conn, USER_B):
        assert await count_visible(conn, "app_owned") == 2
    findings = [(f.check, f.name) for f in await live.run_all(dsn)]
    assert findings == [("live-table-owner", "public.app_owned")]
    await conn.execute("alter table public.app_owned force row level security")
    assert await live.run_all(dsn) == []


async def test_column_grants_matviews_and_foreign_tables(dsn: str, conn: Any) -> None:
    await conn.execute(
        """
        create view public.app_cols with (security_invoker = yes) as
            select 1 as id, 'secret'::text as body;
        revoke all on public.app_cols from anon, authenticated;
        grant select (body) on public.app_cols to anon;
        create materialized view public.app_totals as select 1 as notes;
        revoke all on public.app_totals from authenticated;
        create foreign data wrapper rls_guard_fdw;
        create server rls_guard_srv foreign data wrapper rls_guard_fdw;
        create foreign table public.app_remote (id int) server rls_guard_srv;
        revoke all on public.app_remote from anon;
        """
    )
    findings = {(f.check, f.name, f.detail) for f in await live.run_all(dsn)}
    assert findings == {
        ("live-view-grant", "public.app_cols", "anon holds SELECT (some columns) on it"),
        ("live-matview-grant", "public.app_totals", "anon holds all privileges on it"),
        (
            "live-foreign-table-grant",
            "public.app_remote",
            "authenticated holds all privileges on it",
        ),
    }


async def test_a_schema_that_does_not_exist_could_not_run(
    dsn: str, capsys: pytest.CaptureFixture[str], tmp_path: Path
) -> None:
    with pytest.raises(live.LiveConfigError, match="don't exist"):
        await live.run_all(dsn, schemas=["pubic"])
    config = tmp_path / "rls-guard.toml"
    config.write_text('[live]\nschemas = ["API"]\n')
    args = ["live", "--dsn", dsn, "--config", str(config)]
    assert await asyncio.to_thread(main, args) == 2
    assert "schema(s) ['api'] don't exist" in capsys.readouterr().err


async def test_the_shim_grants_like_supabase(conn: Any) -> None:
    # On Supabase, anon can read a table with RLS off; without the default
    # privileges plain Postgres would say "permission denied" and look safe.
    await conn.execute(
        "create table public.app_open (id int); insert into public.app_open values (1);"
    )
    async with as_user(conn, None):
        assert await count_visible(conn, "app_open") == 1


async def test_as_user_never_pastes_the_role_into_sql(conn: Any) -> None:
    import asyncpg

    role = 'authenticated"; commit; create table public.pwned (id int); begin; set local role "x'
    with pytest.raises(asyncpg.PostgresError):
        async with as_user(conn, USER_A, role=role):
            pass
    assert await conn.fetchval("select to_regclass('public.pwned') is null")
    async with as_user(conn, USER_A):
        assert await conn.fetchval("select current_user") == "authenticated"
    assert await conn.fetchval("select current_user") == "postgres"
