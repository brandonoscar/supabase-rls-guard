"""Prove your RLS policies in a test: one tenant's user cannot read another's rows.

``relrowsecurity = true`` proves RLS is on, not that its policies are right. A
policy can be on and wrong (a membership join that matches every company, a
``using (true)`` left from debugging). The only proof is to read as a real
user and count:

    async with as_user(conn, user_b):
        assert await count_visible(conn, "app_notes", "id = $1", note_from_company_a) == 0

``as_user`` opens a transaction, switches to the ``authenticated`` role and
sets the JWT claims the way Supabase's API does, so ``auth.uid()`` returns the
user you name. Everything is rolled back at the end, so a test can insert its
own two tenants and leave nothing behind.

To run the same tests on plain Postgres (CI, no Supabase), apply
:data:`SUPABASE_SHIM_SQL` once, before your migrations. It creates the
``anon``, ``authenticated`` and ``service_role`` roles, ``auth.uid()`` and
``auth.jwt()`` reading the request's JWT claims, and Supabase's default
privileges in ``public``: every table, view and sequence the applying role
creates there is granted to all three roles, as on Supabase. Without those
grants, a table with RLS off answers ``anon`` with "permission denied", which
looks safe and isn't. The roles are created only if missing; on a real
Supabase database use :func:`as_user` without the shim.
"""

from __future__ import annotations

import contextlib
import json
from collections.abc import AsyncIterator, Mapping
from typing import Any

SUPABASE_SHIM_SQL = """
do $$
begin
  if not exists (select 1 from pg_roles where rolname = 'anon') then
    create role anon nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'authenticated') then
    create role authenticated nologin noinherit;
  end if;
  if not exists (select 1 from pg_roles where rolname = 'service_role') then
    create role service_role nologin noinherit bypassrls;
  end if;
end
$$;
create schema if not exists auth;
create or replace function auth.jwt() returns jsonb
  language sql stable
  as $fn$
    select coalesce(nullif(current_setting('request.jwt.claims', true), ''), '{}')::jsonb
  $fn$;
create or replace function auth.uid() returns uuid
  language sql stable
  as $fn$ select nullif(auth.jwt() ->> 'sub', '')::uuid $fn$;
grant usage on schema auth to anon, authenticated, service_role;
grant execute on function auth.jwt(), auth.uid() to anon, authenticated, service_role;
grant usage on schema public to anon, authenticated, service_role;
alter default privileges in schema public
  grant all on tables to anon, authenticated, service_role;
alter default privileges in schema public
  grant all on sequences to anon, authenticated, service_role;
alter default privileges in schema public
  grant all on functions to anon, authenticated, service_role;
"""


async def apply_supabase_shim(conn: Any) -> None:
    """Create Supabase's roles, ``auth`` functions and default privileges on
    plain Postgres."""
    await conn.execute(SUPABASE_SHIM_SQL)


@contextlib.asynccontextmanager
async def as_user(
    conn: Any,
    user_id: str | None,
    *,
    role: str = "authenticated",
    claims: Mapping[str, Any] | None = None,
) -> AsyncIterator[Any]:
    """Run the block as a signed-in user (or ``anon`` with ``user_id=None``),
    inside a transaction that is always rolled back."""
    payload = dict(claims or {})
    if user_id is not None:
        payload.setdefault("sub", user_id)
        payload.setdefault("role", role)
    else:
        role = "anon"
        payload.setdefault("role", "anon")
    transaction = conn.transaction()
    await transaction.start()
    try:
        # Bound as a value, never pasted into SQL: set_config('role', ..., true)
        # is SET LOCAL ROLE, and a role name can't end the statement.
        await conn.execute("select set_config('role', $1, true)", role)
        await conn.execute("select set_config('request.jwt.claims', $1, true)", json.dumps(payload))
        yield conn
    finally:
        await transaction.rollback()


async def count_visible(conn: Any, table: str, where: str = "true", *args: Any) -> int:
    """Rows of ``table`` matching ``where`` that the current role can see.

    ``table`` and ``where`` are SQL your test writes, pasted in as written;
    pass values as ``$1``, ``$2`` arguments, never inside ``where``."""
    return int(await conn.fetchval(f"select count(*) from {table} where {where}", *args))


__all__ = ["SUPABASE_SHIM_SQL", "apply_supabase_shim", "as_user", "count_visible"]
