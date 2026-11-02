# supabase-rls-guard

[![CI](https://github.com/brandonoscar/supabase-rls-guard/actions/workflows/ci.yml/badge.svg)](https://github.com/brandonoscar/supabase-rls-guard/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)

CI guards for multi-tenant Postgres and Supabase apps. Each one catches a way one customer's rows end up in front of another customer:

| Check | Catches |
|---|---|
| **Every table gets RLS** (migrations, then the live catalog) | A table the API exposes with row-level security off after the last migration. The anon key ships in your frontend, so that table is readable by anyone. |
| **Every view keeps RLS in force** | A view runs with its owner's rights unless it's `security_invoker`, and Supabase's default privileges grant every new view to `anon` and `authenticated`. Any new view is a window around RLS. |
| **Every tenant query names the tenant** | A backend on the service role bypasses RLS. From then on only `WHERE company_id = $1` stands between customers, in every query, forever. This fails CI on any SQL statement in your Python that touches a tenant table without it, unless it's licensed with a reason. |
| **Read as a real user** (test helpers) | RLS that is on but wrong (`using (true)` left over from debugging). The catalog can't see it; reading as company B's user can. |

The static checks need only the standard library. The live checks need `asyncpg`.

## Try it

```bash
git clone https://github.com/brandonoscar/supabase-rls-guard
cd supabase-rls-guard
pip install -e .
rls-guard check --config examples/app/rls-guard.toml
```

```text
rls-guard check OK: 3 migration file(s) (1 never applied), 4 tenant-table queries (1 licensed cross-tenant)
```

Add a table without RLS, or a query without `company_id`, and it fails:

```text
FAIL [table-rls] public.app_leads: created in supabase/migrations/0003_leads.sql; no later migration enables row level security
FAIL [scoping] src/app/notes.py:38 queries a tenant table without the tenant column (fingerprint ae549fc19c): select body from app_notes
rls-guard check FAILED: 4 migration file(s) (1 never applied), 5 tenant-table queries (1 licensed cross-tenant)
```

## Use it in CI

```yaml
- uses: actions/checkout@v7
- uses: brandonoscar/supabase-rls-guard@main   # or pin a commit SHA
  with:
    config: rls-guard.toml
    live-dsn: ${{ secrets.DATABASE_URL }}                 # optional: also check the live catalog
    require-live: ${{ github.event_name == 'schedule' }}  # there, a missing secret fails
```

With no `live-dsn`, the live checks are skipped with a notice in the run. `require-live: true` fails the step instead. Set it wherever the secret must be present: pull requests from forks and Dependabot get no secrets, and a misnamed secret is empty too.

Or `pip install "supabase-rls-guard[live] @ git+https://github.com/brandonoscar/supabase-rls-guard"` (not on PyPI yet) and run `rls-guard check` / `rls-guard live` yourself. Exit codes: 0 clean, 1 findings, **2 could not run**. Treat 2 as a failure: a check that didn't run (no database URL, an unreadable or mistyped config, a schema that doesn't exist) checked nothing.

## Configure it

`rls-guard.toml`, with paths relative to the file:

```toml
[migrations]
paths = ["supabase/migrations/*.sql"]
schemas = ["public"]            # the schemas your API exposes
rls_off_allowlist = []          # keep empty unless you can say why

[scoping]
sources = ["src/**/*.py"]
tables = '\bapp_[a-z_]+\b'      # regex matching your tenant tables
tenant_column = "company_id"
min_queries = 4                 # fewer found means a broken glob, so fail

[[scoping.allow]]
path = "src/app/notes.py"
fingerprint = "6b6784c33a"
reason = "Fleet-wide note count for the ops dashboard: a number, never row content"

[live]
schemas = ["public"]
rls_off_allowlist = ["spatial_ref_sys"]   # PostGIS's reference table, no tenant rows
```

- **Every key is checked.** An unknown key (`source` for `sources`), a wrong type or an empty `schemas` is exit 2. A typo never turns a check off quietly.
- **Names read as in SQL.** Unquoted names are lower-cased, so `API` means `api`; write `'"Mixed"'` for a quoted one. An allowlist entry is `notes` (any exposed schema) or `public.notes`.
- **A schema that matches nothing fails.** In `[migrations]`, a schema no migration creates anything in is a finding; in `[live]`, a schema the database doesn't have is exit 2. Either way a typo would point the check at nothing.
- **Never-applied migrations** start with the line `-- rls-guard: never-applied`, and rls-guard skips them. Only that first line counts: a comment saying "do not re-run" anywhere else skips nothing.
- Leave out `[scoping]` to run only the migration checks. The summary then says `query scoping not configured`.

## How the migration checks work, and where they stop

rls-guard replays the migrations in file-name order, the order Supabase applies them, statement by statement, and checks where that leaves each table and view:

- **Tables:** creates (`create table`, `create table ... as`, `select ... into`), drops, renames, `set schema`, and every `enable` or `disable row level security`. A table owned by `anon` or `authenticated` also needs `force row level security`, since an owner skips its own table's RLS.
- **Views:** `security_invoker` set in `create view` or `alter view ... set (...)`, taken away by `reset (...)` or by a `create or replace view` without it. Every grant and revoke counts, including `on all tables in schema` and column grants. A view must end `security_invoker`, and neither browser role may hold any privilege on it. Materialized views can't be `security_invoker`, and foreign tables can't have RLS, so for those only the revokes count.
- **SQL as Postgres reads it:** comments (nested ones too), string literals, quoted names and `$tag$` bodies, so prose and data never count. A `DO` block runs, so its statements count; a function body doesn't run, so its statements don't. An unqualified name goes to the first schema on the `search_path`, which `set search_path` and `set_config('search_path', ...)` change. Each file starts from `public`.
- **Supabase's default privileges are assumed:** every new table and view is granted to `anon` and `authenticated`. So a view needs its revoke even if your project changed those defaults.

Where it stops: SQL built at run time (`execute format(...)` in a `DO` block) isn't seen, and a statement inside an `if` in a `DO` block counts as run. `alter default privileges` isn't read. A file it can't tokenize, a `create schema` with tables inside it, and an `import foreign schema` into an exposed schema are reported as findings rather than guessed at. The live checks catch what the migrations don't show.

## The live checks

`rls-guard live` asks the database for the exposed schemas' tables with RLS off, and for tables owned by `anon` or `authenticated` without `force row level security`. It also finds views that aren't `security_invoker`, and any view, materialized view or foreign table a browser role holds a privilege on, a column grant included. It reads names only, never rows. With `--config` it reads that file, and a path that doesn't exist is exit 2. Without `--config` it reads `rls-guard.toml` if there is one, and otherwise checks `public` and says so.

## How the scoping check works, and where it stops

It parses your `.py` files with `ast` and reads every SQL string: literals, f-strings, and strings built with `+`, `%` and `.format()` from literals and module-level constants. Each statement is judged on its own. One that touches a table matching `tables` without the tenant column fails unless it's licensed.

- **Licences are keyed by file and statement fingerprint**, not line number. A line number isn't an identity: a new cross-tenant query landing on a licensed line would inherit the licence. With a fingerprint, edits elsewhere in the file break nothing, and a changed query needs a new decision. The failure message prints the fingerprint to license, so read the query before you paste it.
- **A licence covers one statement.** Licensing `BASE = "select ... from app_notes"` doesn't license `BASE + " where id = $1"`, which is its own query. A table named through a constant (`f"select ... from {NOTES}"`) is still seen.
- **A licence that matches nothing fails**, so the list never reads as more permissive than the code.
- **The tenant column has to be in the SQL itself.** In a comment or inside a string value it doesn't count. f-strings are read whole, so a column in another fragment counts and a hole shows as `{}`. Docstrings are skipped.
- **`min_queries`** fails a scan that found too little: a wrong glob would otherwise pass while reading no code.
- **A file that doesn't parse fails the check**, since its queries can't be seen. Run rls-guard on the Python version your code is written for (the Action's `python-version`).

Where it stops: it's a text check for a forgotten clause, not a proof. A query that names `company_id` without filtering on it passes. SQL built outside string expressions isn't seen: a query builder, or a table name read at run time. The live tests below are the proof.

## Prove isolation in your tests

```python
from rls_guard.testing import apply_supabase_shim, as_user, count_visible


async def test_company_b_cannot_read_company_a(conn):
    note_id = await conn.fetchval(
        "insert into app_notes (company_id, body) values ($1, 'x') returning id", company_a
    )
    async with as_user(conn, user_in_company_b):
        assert await count_visible(conn, "app_notes", "id = $1", note_id) == 0
```

`as_user` opens a transaction, switches to the `authenticated` role and sets the JWT claims the way Supabase's API does, so `auth.uid()` is the user you name. Everything is rolled back afterwards. `as_user(conn, None)` reads as `anon`.

On plain Postgres (CI without Supabase), run `apply_supabase_shim(conn)` once, before your migrations. It creates the roles, `auth.uid()` and Supabase's default privileges. Without those grants, a table with RLS off answers `anon` with "permission denied", which looks safe and isn't. This repo's own tests do exactly that against Postgres 16. One test has a table whose RLS is on with a `using (true)` policy: the catalog check passes it, and reading as the other company's user catches it.

## Development

```bash
pip install -e ".[dev]"
pytest                                       # live tests skip without a database
RLS_GUARD_TEST_DSN=postgresql://postgres@localhost:5432/postgres pytest
ruff check . && ruff format --check . && mypy
```

Pull requests are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md). Report security problems privately, as [SECURITY.md](SECURITY.md) describes, not in an issue. Changes are listed in [CHANGELOG.md](CHANGELOG.md).

## License

[MIT](LICENSE).
