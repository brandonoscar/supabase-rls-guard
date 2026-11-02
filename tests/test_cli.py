from __future__ import annotations

import json
import shutil
from pathlib import Path

import pytest

from rls_guard.cli import main
from rls_guard.config import ConfigError, load

EXAMPLE = Path(__file__).parents[1] / "examples" / "app"


@pytest.fixture
def project(tmp_path: Path) -> Path:
    """A copy of the example app to break in different ways."""
    target = tmp_path / "app"
    shutil.copytree(EXAMPLE, target)
    return target


def run(project: Path, *args: str) -> int:
    return main(["check", "--config", str(project / "rls-guard.toml"), *args])


def test_the_example_passes(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(project) == 0
    assert capsys.readouterr().out.strip() == (
        "rls-guard check OK: 3 migration file(s) (1 never applied), "
        "4 tenant-table queries (1 licensed cross-tenant)"
    )


def test_a_new_table_without_rls_fails(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (project / "supabase/migrations/0003_leads.sql").write_text(
        "create table public.app_leads (id uuid primary key, company_id uuid);\n"
    )
    assert run(project) == 1
    assert "FAIL [table-rls] public.app_leads" in capsys.readouterr().out


def test_a_new_unsafe_view_fails(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    (project / "supabase/migrations/0003_view.sql").write_text(
        "create view public.app_note_bodies as select body from public.app_notes;\n"
    )
    assert run(project) == 1
    out = capsys.readouterr().out
    assert "FAIL [view-invoker] public.app_note_bodies" in out
    assert "FAIL [view-grant] public.app_note_bodies" in out


def test_an_unscoped_query_fails(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    notes = project / "src/app/notes.py"
    added = 'async def any_note(conn):\n    return await conn.fetch("select body from app_notes")\n'
    notes.write_text(notes.read_text() + "\n\n" + added)
    assert run(project, "--json") == 1
    report = json.loads(capsys.readouterr().out)
    assert any("select body from app_notes" in p for p in report["scoping"])


def test_a_licensed_query_that_changes_fails(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    notes = project / "src/app/notes.py"
    notes.write_text(
        notes.read_text().replace("select count(*) from app_notes", "select body from app_notes")
    )
    assert run(project) == 1
    assert "matches no query" in capsys.readouterr().out


def test_a_missing_config_could_not_run(tmp_path: Path) -> None:
    assert main(["check", "--config", str(tmp_path / "nope.toml")]) == 2


def test_no_migrations_is_a_finding_not_a_pass(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    for sql in (project / "supabase/migrations").glob("*.sql"):
        sql.unlink()
    assert run(project) == 1
    assert "nothing was checked" in capsys.readouterr().out


def test_live_without_a_database_could_not_run(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.delenv("RLS_GUARD_DSN", raising=False)
    monkeypatch.delenv("DATABASE_URL", raising=False)
    assert main(["live", "--config", str(EXAMPLE / "rls-guard.toml")]) == 2
    assert "Not a pass" in capsys.readouterr().err


SCOPING = "[scoping]\nsources = ['src/*.py']\ntables = 'app_'\n"


@pytest.mark.parametrize(
    ("toml", "error"),
    [
        ("[nonsense]\n", "unknown section"),
        ("[scoping]\nsources = ['x.py']\ntables = '('\n", "not a valid regex"),
        (SCOPING + "[[scoping.allow]]\npath = 'x.py'\n", "missing"),
        ("[migrations]\npaths = 'one.sql'\n", "list of strings"),
        ("not toml at all [", "Expected"),
        # A typo turns nothing off quietly.
        ("[scoping]\nsource = ['src/*.py']\ntables = 'app_'\n", "unknown key"),
        ("[scoping]\ntables = 'app_'\n", "needs sources"),
        ("[migrations]\ndead_marker = 'DO NOT RE-RUN'\n", "never-applied"),
        ("[migrations]\nschemas = []\n", "schemas is empty"),
        ("[live]\nschemas = ['public.notes']\n", "is a schema"),
        ("[migrations]\nrls_off_allowlist = ['a b']\n", "not a name"),
        (SCOPING + "min_queries = 'four'\n", "whole number"),
        (SCOPING + "min_queries = true\n", "whole number"),
        (SCOPING + "[scoping.allow]\npath = 'x.py'\n", "two pairs of brackets"),
        (
            SCOPING + "[[scoping.allow]]\npath = 'x.py'\nfingerprint = 'abc'\nreason = 'r'\n",
            "10 characters",
        ),
        (
            SCOPING
            + "[[scoping.allow]]\npath = 'x.py'\nfingerprint = '6b6784c33a'\nreason = 'r'\n"
            + "why = 'x'\n",
            "unknown key",
        ),
    ],
)
def test_config_errors(tmp_path: Path, toml: str, error: str) -> None:
    path = tmp_path / "rls-guard.toml"
    path.write_text(toml)
    with pytest.raises(ConfigError, match=error):
        load(path)
    assert main(["check", "--config", str(path)]) == 2


def test_config_paths_are_relative_to_the_file() -> None:
    config = load(EXAMPLE / "rls-guard.toml")
    assert config.root == EXAMPLE.resolve()
    assert config.scoping.enabled
    assert config.scoping.allow[0].path == "src/app/notes.py"


def test_config_names_read_as_sql(tmp_path: Path) -> None:
    path = tmp_path / "rls-guard.toml"
    path.write_text("[migrations]\nschemas = ['API', '\"Mixed\"']\n[live]\nschemas = ['Public']\n")
    config = load(path)
    assert config.migrations.schemas == ("api", "Mixed")
    assert config.live.schemas == ("public",)


def test_a_schema_typo_fails_the_static_check(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = project / "rls-guard.toml"
    config.write_text(config.read_text().replace('schemas = ["public"]', 'schemas = ["pubic"]', 1))
    (project / "supabase/migrations/0003_leads.sql").write_text(
        "create table public.app_leads (id uuid primary key);\n"
    )
    assert run(project) == 1
    assert "FAIL [schema] pubic: no migration creates" in capsys.readouterr().out


def test_without_scoping_the_summary_says_so(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config = project / "rls-guard.toml"
    text = config.read_text()
    config.write_text(text[: text.index("[scoping]")] + text[text.index("[live]") :])
    assert run(project) == 0
    assert "query scoping not configured" in capsys.readouterr().out


def test_a_source_that_does_not_parse_fails(
    project: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    (project / "src/app/admin.py").write_text(
        'async def purge(conn:\n    await conn.execute("delete from app_notes")\n'
    )
    (project / "src/app/latin1.py").write_bytes(b'X = "caf\xe9"\n')
    assert run(project) == 1
    out = capsys.readouterr().out
    assert "src/app/admin.py could not be parsed" in out
    assert "src/app/latin1.py could not be parsed" in out


def test_a_glob_that_matches_folders_still_works(project: Path) -> None:
    config = project / "rls-guard.toml"
    config.write_text(config.read_text().replace('"src/**/*.py"', '"src/**"'))
    assert run(project) == 0


def test_a_crash_is_could_not_run(
    project: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    def boom(*args: object, **kwargs: object) -> None:
        raise RuntimeError("something nobody expected")

    monkeypatch.setattr("rls_guard.cli.check_migrations", boom)
    assert run(project) == 2
    assert "could not run: RuntimeError" in capsys.readouterr().err


def test_an_unreadable_migration_is_could_not_run(project: Path) -> None:
    (project / "supabase/migrations/0003_bad.sql").write_bytes(b"select '\xff';\n")
    assert run(project) == 2


def test_live_with_a_config_that_does_not_exist_could_not_run(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    args = ["live", "--dsn", "postgresql://nobody@127.0.0.1:9/none"]
    assert main([*args, "--config", str(tmp_path / "typo.toml")]) == 2
    assert "typo.toml not found" in capsys.readouterr().err


def test_json_says_whether_scoping_ran(project: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert run(project, "--json") == 0
    report = json.loads(capsys.readouterr().out)
    assert report["scoping_configured"] is True
    assert report["counts"]["never_applied"] == 1
