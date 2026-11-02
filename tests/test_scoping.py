from __future__ import annotations

import re
from pathlib import Path

import pytest

from rls_guard.scoping import (
    Licence,
    Query,
    check_scoping,
    collect_sources,
    find_queries,
    fingerprint,
    scan_sources,
)

TABLES = re.compile(r"\bapp_[a-z_]+\b")


def scan(tmp_path: Path, source: str) -> list[Query]:
    (tmp_path / "data.py").write_text(source)
    return find_queries([tmp_path / "data.py"], root=tmp_path, tables=TABLES)


def unscoped(tmp_path: Path, source: str, *licences: Licence) -> list[str]:
    report = check_scoping(scan(tmp_path, source), tenant_column="company_id", licences=licences)
    return [" ".join(q.sql.split()) for q in report.undeclared]


def test_an_unscoped_query_is_flagged_and_a_scoped_one_is_not(tmp_path: Path) -> None:
    source = (
        'A = "select * from app_notes where company_id = $1"\n'
        'B = "select * from app_notes where id = $1"\n'
        'C = "select * from other_table"\n'
    )
    assert unscoped(tmp_path, source) == ["select * from app_notes where id = $1"]


def test_an_f_string_is_read_whole(tmp_path: Path) -> None:
    # The tenant column sits in a different fragment from the table name.
    scoped = 'def f(o):\n    return f"select * from app_notes where {o} and company_id = $1"\n'
    assert unscoped(tmp_path, scoped) == []
    # Judged once, whole: its fragments are not separate queries.
    assert len(scan(tmp_path, scoped)) == 1
    hole = 'def f(c):\n    return f"select * from app_notes where id = {c}"\n'
    assert unscoped(tmp_path, hole) == ["select * from app_notes where id = {}"]


def test_docstrings_are_not_queries(tmp_path: Path) -> None:
    source = (
        '"""Reads app_notes: select from app_notes, never update."""\n'
        "def f():\n"
        '    """select * from app_notes"""\n'
        "    return 1\n"
    )
    assert scan(tmp_path, source) == []


def test_a_licence_is_keyed_by_file_and_statement_not_line(tmp_path: Path) -> None:
    sql = "select count(*) from app_notes"
    licence = Licence("data.py", fingerprint(sql), "fleet-wide count for the ops dashboard only")
    assert unscoped(tmp_path, f'X = "{sql}"\n', licence) == []
    # Lines added above it break nothing.
    assert unscoped(tmp_path, f'import os\n\n\nX = "{sql}"\n', licence) == []
    # Reflowing it keeps its fingerprint.
    assert unscoped(tmp_path, 'X = """select count(*)\n    from app_notes"""\n', licence) == []


def test_a_changed_statement_needs_a_new_decision(tmp_path: Path) -> None:
    licence = Licence(
        "data.py", fingerprint("select count(*) from app_notes"), "fleet-wide count for ops"
    )
    (tmp_path / "data.py").write_text('X = "select body from app_notes"\n')
    report = check_scoping(
        find_queries([tmp_path / "data.py"], root=tmp_path, tables=TABLES),
        tenant_column="company_id",
        licences=[licence],
    )
    assert [q.sql for q in report.undeclared] == ["select body from app_notes"]
    assert report.stale == [licence]
    assert not report.ok
    problems = "\n".join(report.problems())
    assert "matches no query" in problems
    assert fingerprint("select body from app_notes") in problems


def test_reasons_must_say_something(tmp_path: Path) -> None:
    sql = "select count(*) from app_notes"
    (tmp_path / "data.py").write_text(f'X = "{sql}"\n')
    report = check_scoping(
        find_queries([tmp_path / "data.py"], root=tmp_path, tables=TABLES),
        tenant_column="company_id",
        licences=[Licence("data.py", fingerprint(sql), "ok")],
    )
    assert report.weak_reasons
    assert not report.ok


def test_a_scan_that_finds_nothing_fails(tmp_path: Path) -> None:
    report = check_scoping([], tenant_column="company_id", min_queries=1)
    assert report.too_few is not None
    assert not report.ok


def test_the_column_is_matched_as_a_word(tmp_path: Path) -> None:
    source = 'X = "select * from app_notes where company_id_hash = $1"\n'
    assert unscoped(tmp_path, source) == ["select * from app_notes where company_id_hash = $1"]


def test_writes_are_queries_too(tmp_path: Path) -> None:
    source = (
        'A = "update app_notes set body = $2 where id = $1"\n'
        'B = "delete from app_notes where id = $1"\n'
        'C = "insert into app_notes (body) values ($1)"\n'
    )
    assert len(unscoped(tmp_path, source)) == 3


def test_fingerprints_ignore_case_and_whitespace() -> None:
    assert fingerprint("SELECT  *\nFROM app_notes") == fingerprint("select * from app_notes")
    assert fingerprint("select * from app_notes") != fingerprint("select 1 from app_notes")


def test_each_statement_in_a_literal_is_judged(tmp_path: Path) -> None:
    source = (
        'PURGE = """\n'
        "delete from app_notes where id = $1;\n"
        "insert into app_audit (company_id, action) values ($2, 'delete');\n"
        '"""\n'
    )
    queries = scan(tmp_path, source)
    assert [q.line for q in queries] == [2, 3]
    assert unscoped(tmp_path, source) == ["delete from app_notes where id = $1"]


def test_truncate_copy_and_table_are_queries(tmp_path: Path) -> None:
    source = (
        'A = "truncate app_notes"\n'
        'B = "copy app_notes to stdout"\n'
        'C = "table app_notes"\n'
        'D = "could not copy the rows of app_notes"\n'
        'E = "drop table app_notes"\n'
    )
    assert unscoped(tmp_path, source) == [
        "truncate app_notes",
        "copy app_notes to stdout",
        "table app_notes",
    ]


def test_the_column_must_be_in_the_sql_not_a_comment_or_value(tmp_path: Path) -> None:
    source = (
        'A = "select * from app_notes -- TODO company_id"\n'
        "B = \"select * from app_notes where note = 'company_id'\"\n"
        'C = "select * from app_notes n where n.company_id = $1"\n'
    )
    assert unscoped(tmp_path, source) == [
        "select * from app_notes -- TODO company_id",
        "select * from app_notes where note = 'company_id'",
    ]


def test_strings_built_from_a_licensed_base_are_new_queries(tmp_path: Path) -> None:
    base = "select id, body from app_notes"
    source = (
        f'BASE = "{base}"\n'
        "async def by_company(conn, cid):\n"
        '    return await conn.fetch(BASE + " where company_id = $1", cid)\n'
        "async def by_id(conn, note_id):\n"
        '    return await conn.fetch(BASE + " where id = $1", note_id)\n'
    )
    licence = Licence("data.py", fingerprint(base), "base select; callers add their own filter")
    assert unscoped(tmp_path, source, licence) == ["select id, body from app_notes where id = $1"]


def test_a_table_named_through_a_constant_is_seen(tmp_path: Path) -> None:
    source = (
        'NOTES = "app_notes"\n'
        "def a(i):\n"
        '    return f"select body from {NOTES} where id = $1"\n'
        "def b(i):\n"
        '    return "select body from %s where id = $1" % NOTES\n'
        "def c(i):\n"
        '    return "select body from {} where id = $1".format(NOTES)\n'
        "def d(i):\n"
        '    return "select body from %s where id = %s" % (NOTES, i)\n'
    )
    assert unscoped(tmp_path, source) == [
        "select body from app_notes where id = $1",
        "select body from app_notes where id = $1",
        "select body from app_notes where id = $1",
        "select body from app_notes where id = {}",
    ]


def test_a_file_that_does_not_parse_fails_the_scan(tmp_path: Path) -> None:
    (tmp_path / "ok.py").write_text('X = "select * from app_notes where company_id = $1"\n')
    (tmp_path / "broken.py").write_text(
        'def purge(conn:\n    conn.execute("delete from app_notes")\n'
    )
    (tmp_path / "latin1.py").write_bytes(b'X = "caf\xe9"\n')
    sources = [tmp_path / "ok.py", tmp_path / "broken.py", tmp_path / "latin1.py"]
    result = scan_sources(sources, root=tmp_path, tables=TABLES)
    assert [path for path, _ in result.unparsed] == ["broken.py", "latin1.py"]
    report = check_scoping(result.queries, tenant_column="company_id", unparsed=result.unparsed)
    assert not report.ok
    assert "broken.py could not be parsed" in "\n".join(report.problems())
    with pytest.raises(ValueError, match=r"broken\.py"):
        find_queries(sources, root=tmp_path, tables=TABLES)


def test_sources_are_python_files_only(tmp_path: Path) -> None:
    (tmp_path / "src" / "pkg" / "__pycache__").mkdir(parents=True)
    (tmp_path / "src" / "pkg" / "a.py").write_text("X = 1\n")
    (tmp_path / "src" / "pkg" / "notes.sql").write_text("select 1;\n")
    (tmp_path / "src" / "pkg" / "__pycache__" / "a.cpython-312.pyc").write_bytes(b"\x00\x01")
    found = collect_sources(["src/**", "src/**/*.py"], tmp_path)
    assert [p.relative_to(tmp_path).as_posix() for p in found] == ["src/pkg/a.py"]
