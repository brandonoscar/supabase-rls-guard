from __future__ import annotations

import pytest

from rls_guard.migrations import (
    Finding,
    Migration,
    SqlSyntaxError,
    check_migrations,
    is_never_applied,
    parse_name,
    pg_bool,
    split_statements,
    tables_without_rls,
    tokenize,
    unsafe_views,
)

REVOKE = "revoke all on public.v from anon, authenticated;"
SAFE_VIEW = "create view public.v with (security_invoker = true) as select 1;"


def names(findings: list[Finding]) -> list[tuple[str, str]]:
    return [(f.check, f.name) for f in findings]


# --- tables -----------------------------------------------------------------


def test_a_table_without_rls_is_flagged() -> None:
    sql = "create table public.app_notes (id int);"
    assert names(tables_without_rls([sql])) == [("table-rls", "public.app_notes")]


def test_rls_may_arrive_in_a_later_migration() -> None:
    first = "create table if not exists app_notes (id int);"
    later = "alter table public.app_notes enable row level security;"
    assert tables_without_rls([first, later]) == []


def test_quoted_and_only_forms() -> None:
    sql = (
        'create table "public"."Leads" (id int);\n'
        'alter table only public."Leads" enable row level security;'
    )
    assert tables_without_rls([sql]) == []


def test_a_later_disable_counts() -> None:
    sql = [
        "create table public.app_notes (id int);\n"
        "alter table public.app_notes enable row level security;",
        "alter table public.app_notes disable row level security;",
    ]
    findings = tables_without_rls([Migration("0001.sql", sql[0]), Migration("0002.sql", sql[1])])
    assert names(findings) == [("table-rls", "public.app_notes")]
    assert "disabled in 0002.sql" in findings[0].detail
    # Enabled again afterwards: clean.
    again = "alter table public.app_notes enable row level security;"
    assert tables_without_rls([*sql, again]) == []


def test_drop_and_create_again_needs_a_new_enable() -> None:
    sql = [
        "create table public.app_notes (id int);\n"
        "alter table public.app_notes enable row level security;",
        "drop table public.app_notes;\ncreate table public.app_notes (id int, company_id uuid);",
    ]
    assert names(tables_without_rls(sql)) == [("table-rls", "public.app_notes")]


def test_create_if_not_exists_keeps_the_existing_table() -> None:
    sql = [
        "create table public.app_notes (id int);\n"
        "alter table public.app_notes enable row level security;",
        "create table if not exists public.app_notes (id int);",
    ]
    assert tables_without_rls(sql) == []


def test_select_into_and_create_as_make_tables() -> None:
    sql = (
        "select * into public.app_notes_backup from public.app_notes;\n"
        "create table public.app_copy as select * from public.app_notes;\n"
        "select 1 as x into temp scratch;\n"
        "with recent as (select 1) insert into public.app_log select * from recent;"
    )
    assert names(tables_without_rls([sql])) == [
        ("table-rls", "public.app_copy"),
        ("table-rls", "public.app_notes_backup"),
    ]


def test_moving_a_table_into_an_exposed_schema_counts() -> None:
    sql = "create table private.app_jobs (id int);\nalter table private.app_jobs set schema public;"
    findings = tables_without_rls([sql])
    assert names(findings) == [("table-rls", "public.app_jobs")]
    assert "moved into public" in findings[0].detail
    # Renamed, it is the same table under its new name.
    renamed = [
        "create table public.a (id int); alter table public.a enable row level security;",
        "alter table public.a rename to b;",
    ]
    assert tables_without_rls(renamed) == []


def test_names_are_keyed_by_schema_and_exact_case() -> None:
    two_schemas = (
        "create table public.notes (id int); create table api.notes (id int);\n"
        "alter table api.notes enable row level security;"
    )
    assert names(tables_without_rls([two_schemas], schemas=["public", "api"])) == [
        ("table-rls", "public.notes")
    ]
    mixed_case = (
        'create table public."Notes" (id int);\ncreate table public.notes (id int);\n'
        "alter table public.notes enable row level security;"
    )
    assert names(tables_without_rls([mixed_case])) == [("table-rls", 'public."Notes"')]


def test_unqualified_names_follow_the_search_path() -> None:
    sql = "set search_path to api;\ncreate table secrets (id int);"
    assert names(tables_without_rls([sql], schemas=["api"])) == [("table-rls", "api.secrets")]
    assert tables_without_rls([sql]) == []  # public isn't where it went
    dump_style = (
        "select pg_catalog.set_config('search_path', 'api, public', false);\n"
        "create table secrets (id int);"
    )
    assert names(tables_without_rls([dump_style], schemas=["api"])) == [
        ("table-rls", "api.secrets")
    ]
    # Each file starts from public again.
    assert names(tables_without_rls(["set search_path = api;", "create table t (id int);"])) == [
        ("table-rls", "public.t")
    ]


def test_schemas_and_allowlist() -> None:
    sql = "create table private.jobs (id int); create table public.lookup (id int);"
    assert names(tables_without_rls([sql])) == [("table-rls", "public.lookup")]
    assert names(tables_without_rls([sql], schemas=["public", "private"])) == [
        ("table-rls", "private.jobs"),
        ("table-rls", "public.lookup"),
    ]
    assert tables_without_rls([sql], allowlist=["LOOKUP"]) == []
    assert tables_without_rls([sql], allowlist=["public.lookup"]) == []
    assert names(tables_without_rls([sql], allowlist=["private.lookup"])) == [
        ("table-rls", "public.lookup")
    ]


def test_a_table_owned_by_a_browser_role_needs_force() -> None:
    sql = (
        "create table public.app_x (id int);\n"
        "alter table public.app_x enable row level security;\n"
        "alter table public.app_x owner to authenticated;"
    )
    assert names(tables_without_rls([sql])) == [("table-owner", "public.app_x")]
    forced = sql + "\nalter table public.app_x force row level security;"
    assert tables_without_rls([forced]) == []


def test_a_foreign_table_can_only_be_revoked() -> None:
    sql = "create foreign table public.stripe_customers (id text) server stripe;"
    assert names(tables_without_rls([sql])) == [
        ("foreign-table-grant", "public.stripe_customers"),
        ("foreign-table-grant", "public.stripe_customers"),
    ]
    revoked = sql + "\nrevoke all on public.stripe_customers from anon, authenticated;"
    assert tables_without_rls([revoked]) == []


def test_import_foreign_schema_into_an_exposed_schema_fails() -> None:
    sql = "import foreign schema remote from server srv into public;"
    assert names(tables_without_rls([sql])) == [("foreign-import", "public")]
    assert tables_without_rls(["import foreign schema remote from server srv into private;"]) == []


# --- reading SQL the way Postgres does ----------------------------------------


def test_a_comment_never_counts_as_protection() -> None:
    sql = (
        "-- alter table app_notes enable row level security;\n"
        "/* alter table app_notes enable row level security; */\n"
        "create table app_notes (id int);"
    )
    assert names(tables_without_rls([sql])) == [("table-rls", "public.app_notes")]


def test_a_comment_never_creates_a_table() -> None:
    sql = "-- create table if not exists whatever (id int)\nselect 1;"
    assert tables_without_rls([sql]) == []


def test_nested_block_comments_hide_what_is_inside() -> None:
    sql = (
        "create table public.app_notes (id int);\n"
        "/* disabled for now:\n   select 1; /* inner note */\n"
        "   alter table public.app_notes enable row level security;\n*/"
    )
    assert names(tables_without_rls([sql])) == [("table-rls", "public.app_notes")]


def test_comment_and_quote_characters_inside_other_tokens() -> None:
    slash_star = (
        "-- storage paths look like avatars/*\ncreate table public.app_leak (id int);\n"
        "-- see docs/*/rls"
    )
    assert names(tables_without_rls([slash_star])) == [("table-rls", "public.app_leak")]
    dashes_in_string = (
        "insert into public.settings values ('sep', '--'); create table public.app_leak (id int);"
    )
    assert names(tables_without_rls([dashes_in_string])) == [("table-rls", "public.app_leak")]


def test_strings_and_function_bodies_are_not_statements() -> None:
    in_comment_on = (
        "create table public.app_notes (id int);\n"
        "comment on table public.app_notes is "
        "'TODO: alter table app_notes enable row level security';"
    )
    in_function = (
        "create table public.app_notes (id int);\n"
        "create function public.lock() returns void language sql as $$\n"
        "  alter table public.app_notes enable row level security;\n$$;"
    )
    for sql in (in_comment_on, in_function):
        assert names(tables_without_rls([sql])) == [("table-rls", "public.app_notes")]


def test_a_do_block_runs_so_its_statements_count() -> None:
    sql = (
        "do $$ begin\n"
        "  if not exists (select 1 from pg_tables where tablename = 'app_x') then\n"
        "    create table public.app_x (id int);\n"
        "  end if;\n"
        "end $$;"
    )
    assert names(tables_without_rls([sql])) == [("table-rls", "public.app_x")]
    enabled = sql + "\ndo $do$ begin alter table public.app_x enable row level security; end $do$;"
    assert tables_without_rls([enabled]) == []


def test_create_schema_with_tables_inside_is_reported() -> None:
    sql = "create schema api create table t (id int);"
    assert next(f.check for f in check_migrations([sql], schemas=["api"])) == "parse"


def test_sql_postgres_would_refuse_is_reported_not_skipped() -> None:
    for broken in ("create table x (id int); /* never closed", "select 'never closed"):
        findings = check_migrations([Migration("0009_broken.sql", broken)])
        assert [(f.check, f.name) for f in findings][:1] == [("parse", "0009_broken.sql")]


def test_tokenizer_basics() -> None:
    statements = tokenize(
        "select 'it''s; fine' as a, $1, e'\\''; -- tail\n"
        "select $tag$ ; $$ $tag$; copy t from stdin;\n1\t-- not sql\n\\.\nselect 2"
    )
    assert [s.text for s in statements] == [
        "select 'it''s; fine' as a, $1, e'\\''",
        "select $tag$ ; $$ $tag$",
        "copy t from stdin",
        "select 2",
    ]
    assert [t.text for t in statements[0].tokens if t.kind == "string"] == ["it's; fine", "'"]
    assert statements[3].line == 5
    assert split_statements('select "a;b"; select 2') == ['select "a;b"', "select 2"]
    with pytest.raises(SqlSyntaxError):
        tokenize("select $x$ unterminated")


# --- the never-applied directive ------------------------------------------------


def test_a_never_applied_migration_is_ignored_both_ways() -> None:
    dead_enable = "-- rls-guard: never-applied\nalter table app_notes enable row level security;"
    create = "create table app_notes (id int);"
    # The dead file's "enable" must not protect the real table...
    assert names(tables_without_rls([create, dead_enable])) == [("table-rls", "public.app_notes")]
    # ...and its own tables are not findings.
    assert tables_without_rls(["-- RLS-Guard: never-applied\ncreate table old (id int);"]) == []


def test_only_the_first_line_directive_skips_a_file() -> None:
    for sql in (
        "-- Backfill; not idempotent, do not re-run by hand.\ncreate table public.app_x (id int);",
        "-- Replaces 0003, marked DO NOT RE-RUN.\ncreate table public.app_x (id int);",
        "create table public.app_x (id int, note text default 'do not re-run');",
        "create table public.app_x (id int);\n-- rls-guard: never-applied",
    ):
        assert names(tables_without_rls([sql])) == [("table-rls", "public.app_x")], sql
    assert is_never_applied("\n\n  -- rls-guard: never-applied (superseded by 0002)\nselect 1;")
    assert not is_never_applied("select 1; -- rls-guard: never-applied")


# --- views -------------------------------------------------------------------


def test_a_view_needs_security_invoker_and_revokes() -> None:
    sql = "create view public.note_counts as select 1;"
    findings = unsafe_views([sql])
    assert names(findings) == [
        ("view-invoker", "public.note_counts"),
        ("view-grant", "public.note_counts"),
        ("view-grant", "public.note_counts"),
    ]
    assert "anon still holds all privileges" in findings[1].detail
    assert "Supabase grants every new relation" in findings[1].detail


def test_invoker_in_the_create_or_a_later_alter() -> None:
    revokes = "revoke all on public.note_counts from anon, authenticated;"
    at_create = "create view note_counts with (security_invoker = true) as select 1;"
    later = [
        "create or replace view public.note_counts as select 1;",
        "alter view public.note_counts set (security_invoker = on);",
    ]
    assert unsafe_views([at_create, revokes]) == []
    assert unsafe_views([*later, revokes]) == []


def test_each_role_must_be_revoked_in_full() -> None:
    sql = [SAFE_VIEW, "revoke all on table public.v from anon;"]
    findings = unsafe_views(sql)
    assert [(f.check, f.detail.split(" (")[0]) for f in findings] == [
        ("view-grant", "authenticated still holds all privileges on it")
    ]
    # Revoking only SELECT leaves the writes.
    partial = unsafe_views([SAFE_VIEW, "revoke select on public.v from anon, authenticated;"])
    assert len(partial) == 2
    assert "delete, insert, references, trigger, truncate, update" in partial[0].detail


def test_create_or_replace_without_the_option_drops_it() -> None:
    sql = [SAFE_VIEW, REVOKE, "create or replace view public.v as select 2;"]
    assert names(unsafe_views(sql)) == [("view-invoker", "public.v")]  # grants survive


def test_drop_and_create_again_resets_options_and_grants() -> None:
    sql = [SAFE_VIEW, REVOKE, "drop view public.v;\ncreate view public.v as select 2;"]
    assert names(unsafe_views(sql)) == [
        ("view-invoker", "public.v"),
        ("view-grant", "public.v"),
        ("view-grant", "public.v"),
    ]


def test_a_later_grant_or_reset_counts() -> None:
    assert names(unsafe_views([SAFE_VIEW, REVOKE, "grant select on public.v to anon;"])) == [
        ("view-grant", "public.v")
    ]
    assert names(unsafe_views([SAFE_VIEW, REVOKE, "grant select on public.v to public;"])) == [
        ("view-grant", "public.v"),
        ("view-grant", "public.v"),
    ]
    assert names(unsafe_views([SAFE_VIEW, REVOKE, "grant select (x) on public.v to anon;"])) == [
        ("view-grant", "public.v")
    ]
    assert names(
        unsafe_views([SAFE_VIEW, REVOKE, "alter view public.v reset (security_invoker);"])
    ) == [("view-invoker", "public.v")]
    assert (
        unsafe_views([SAFE_VIEW, REVOKE, "grant select on all tables in schema private to anon;"])
        == []
    )
    assert names(
        unsafe_views([SAFE_VIEW, REVOKE, "grant select on all tables in schema public to anon;"])
    ) == [("view-grant", "public.v")]


def test_a_revoke_ends_with_its_file() -> None:
    no_semicolon = [SAFE_VIEW, "revoke all on public.v from anon", "-- authenticated\nselect 1;"]
    assert names(unsafe_views(no_semicolon)) == [("view-grant", "public.v")]


def test_recursive_views_and_views_in_other_schemas() -> None:
    recursive = "create recursive view public.tree (n) as select 1 union all select n+1 from tree;"
    assert ("view-invoker", "public.tree") in names(unsafe_views([recursive]))
    two = [SAFE_VIEW, REVOKE, "create view api.v as select 1;"]
    assert names(unsafe_views(two, schemas=["public", "api"])) == [
        ("view-invoker", "api.v"),
        ("view-grant", "api.v"),
        ("view-grant", "api.v"),
    ]


@pytest.mark.parametrize(
    "create",
    [
        "create view public.v (a) with (security_invoker = true) as select 1;",
        "create view public.v with (security_invoker) as select 1;",
        "CREATE VIEW public.v WITH (security_invoker='true') AS SELECT 1;",
        "create view public.v with (security_invoker = yes, security_barrier) as select 1;",
    ],
)
def test_every_spelling_of_security_invoker(create: str) -> None:
    assert unsafe_views([create, REVOKE]) == []


def test_revoking_from_a_list_of_relations() -> None:
    sql = [SAFE_VIEW, "revoke all on public.v, public.w from anon, authenticated;"]
    assert unsafe_views(sql) == []


def test_prose_about_a_view_is_not_its_protection() -> None:
    sql = (
        "-- alter view v set (security_invoker = true); revoke all on v from anon;\n"
        "create view v as select 1;"
    )
    assert {f.check for f in unsafe_views([sql])} == {"view-invoker", "view-grant"}


def test_materialized_views_need_only_their_revokes() -> None:
    sql = "create materialized view public.mv as select 1;"
    assert names(unsafe_views([sql])) == [
        ("matview-grant", "public.mv"),
        ("matview-grant", "public.mv"),
    ]
    revoked = sql + "\nrevoke all on public.mv from anon, authenticated;"
    assert unsafe_views([revoked]) == []


# --- the whole check -------------------------------------------------------------


def test_a_schema_with_nothing_in_it_is_reported() -> None:
    sql = "create table public.t (id int); alter table public.t enable row level security;"
    assert names(check_migrations([sql], schemas=["pubic"])) == [("schema", "pubic")]
    assert check_migrations([sql], schemas=["PUBLIC"]) == []


def test_names_in_config_read_as_sql() -> None:
    assert parse_name("Public.Notes") == ("public", "notes")
    assert parse_name('"API"."Notes"') == ("API", "Notes")
    for bad in ("", "a b", "x; drop table y"):
        with pytest.raises(ValueError, match="is not a name"):
            parse_name(bad)


def test_postgres_booleans() -> None:
    for true in (None, "true", "t", "TR", "yes", "y", "on", "1"):
        assert pg_bool(true), true
    for false in ("false", "f", "off", "of", "no", "0", "o", "2", ""):
        assert not pg_bool(false), false
