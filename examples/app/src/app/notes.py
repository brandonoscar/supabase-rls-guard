"""Data access for notes, through the service role (which bypasses RLS).

Every query names company_id, so one customer's request can never read
another's notes. The one exception is licensed in rls-guard.toml.
"""

from typing import Any

LIST_NOTES = "select id, body from app_notes where company_id = $1 order by created_at desc"


async def list_notes(conn: Any, company_id: str) -> list[Any]:
    return await conn.fetch(LIST_NOTES, company_id)


async def recent_notes(conn: Any, company_id: str, limit: int) -> list[Any]:
    order = "created_at desc"
    return await conn.fetch(
        f"select id, body from app_notes where company_id = $1 order by {order} limit {int(limit)}",
        company_id,
    )


async def add_note(conn: Any, company_id: str, body: str) -> str:
    return await conn.fetchval(
        "insert into app_notes (company_id, body) values ($1, $2) returning id",
        company_id,
        body,
    )


async def total_notes(conn: Any) -> int:
    # Fleet-wide, on purpose: a number for the ops dashboard, never row content.
    return await conn.fetchval("select count(*) from app_notes")
