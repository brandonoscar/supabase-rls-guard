"""``rls-guard``: run the checks from CI.

    rls-guard check                 # migrations + query scoping, no database
    rls-guard live                  # the catalog checks, needs a database URL

Exit codes: 0 clean, 1 findings, 2 could not run. Exit 2 is not a pass: a
check that did not run (a missing database URL, an unreadable config, a
schema that doesn't exist) has checked nothing, and treating it as green is
how a guard stays broken for weeks without anyone noticing. Fail the job on it.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path

from rls_guard import live as live_checks
from rls_guard.config import Config, ConfigError, load
from rls_guard.migrations import (
    Finding,
    MigrationReadError,
    check_migrations,
    is_never_applied,
    read_migrations,
)
from rls_guard.scoping import check_scoping, collect_sources, scan_sources

DEFAULT_CONFIG = "rls-guard.toml"


def _config(path: str) -> Config:
    if not Path(path).exists():
        raise ConfigError(f"{path} not found (pass --config)")
    return load(path)


def run_check(config: Config) -> tuple[list[Finding], list[str], dict[str, int]]:
    """Static findings, scoping problems, and counts for the summary."""
    migrations = read_migrations(config.migrations.paths, config.root)
    findings = check_migrations(
        migrations,
        schemas=config.migrations.schemas,
        allowlist=config.migrations.rls_off_allowlist,
    )
    counts = {
        "migrations": len(migrations),
        "never_applied": sum(is_never_applied(m.sql) for m in migrations),
        "queries": 0,
        "unscoped_licensed": 0,
    }
    problems: list[str] = []
    if not migrations:
        problems.append(
            f"no migration files match {list(config.migrations.paths)}: nothing was checked"
        )
    if config.scoping.enabled:
        scan = scan_sources(
            collect_sources(config.scoping.sources, config.root),
            root=config.root,
            tables=config.scoping.table_pattern(),
        )
        report = check_scoping(
            scan.queries,
            tenant_column=config.scoping.tenant_column,
            licences=config.scoping.allow,
            min_queries=config.scoping.min_queries,
            unparsed=scan.unparsed,
        )
        counts["queries"] = len(report.queries)
        counts["unscoped_licensed"] = len(report.unscoped) - len(report.undeclared)
        problems.extend(report.problems())
    return findings, problems, counts


def _summary(config: Config, ok: bool, counts: dict[str, int]) -> str:
    files = f"{counts['migrations']} migration file(s)"
    if counts["never_applied"]:
        files += f" ({counts['never_applied']} never applied)"
    if config.scoping.enabled:
        scoping = (
            f"{counts['queries']} tenant-table queries ({counts['unscoped_licensed']} "
            "licensed cross-tenant)"
        )
    else:
        scoping = "query scoping not configured"
    return f"rls-guard check {'OK' if ok else 'FAILED'}: {files}, {scoping}"


def _check(args: argparse.Namespace) -> int:
    try:
        config = _config(args.config)
        findings, problems, counts = run_check(config)
    except (ConfigError, MigrationReadError) as exc:
        print(f"rls-guard: could not run: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # a crash checked nothing: never a pass
        print(f"rls-guard: could not run: {type(exc).__name__}: {exc}", file=sys.stderr)
        return 2
    ok = not (findings or problems)
    if args.json:
        print(
            json.dumps(
                {
                    "findings": [f.__dict__ for f in findings],
                    "scoping": problems,
                    "scoping_configured": config.scoping.enabled,
                    "counts": counts,
                },
                indent=2,
            )
        )
    else:
        for finding in findings:
            print(f"FAIL {finding}")
        for problem in problems:
            print(f"FAIL [scoping] {problem}")
        print(_summary(config, ok, counts))
    return 0 if ok else 1


def _live_config(path: str | None) -> Config:
    if path is not None:
        return _config(path)
    if Path(DEFAULT_CONFIG).exists():
        return load(DEFAULT_CONFIG)
    print(
        f"rls-guard live: no {DEFAULT_CONFIG} here, so checking the default schemas "
        f"({', '.join(Config().live.schemas)}); pass --config to check yours",
        file=sys.stderr,
    )
    return Config()


def _live(args: argparse.Namespace) -> int:
    try:
        config = _live_config(args.config)
    except ConfigError as exc:
        print(f"rls-guard live: could not run: {exc}", file=sys.stderr)
        return 2
    dsn = args.dsn or os.environ.get("RLS_GUARD_DSN") or os.environ.get("DATABASE_URL")
    if not dsn:
        print(
            "rls-guard live: could not run: no database URL (--dsn, RLS_GUARD_DSN or "
            "DATABASE_URL). Not a pass.",
            file=sys.stderr,
        )
        return 2
    try:
        findings = asyncio.run(
            live_checks.run_all(
                dsn,
                schemas=config.live.schemas,
                rls_off_allowlist=config.live.rls_off_allowlist,
            )
        )
    except live_checks.LiveConfigError as exc:
        print(f"rls-guard live: could not run: {exc}", file=sys.stderr)
        return 2
    except Exception as exc:  # unreachable database: report, do not pass
        print(f"rls-guard live: could not run: {type(exc).__name__}", file=sys.stderr)
        return 2
    for finding in findings:
        print(f"FAIL {finding}")
    print(f"rls-guard live {'FAILED' if findings else 'OK'}: {len(findings)} finding(s)")
    return 1 if findings else 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="rls-guard", description=__doc__.split("\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)
    check = sub.add_parser("check", help="migrations and query scoping, no database")
    check.add_argument("--config", default=DEFAULT_CONFIG)
    check.add_argument("--json", action="store_true")
    live = sub.add_parser("live", help="catalog checks against a database")
    live.add_argument(
        "--config",
        default=None,
        help=f"defaults to {DEFAULT_CONFIG} when it exists; a path that doesn't exist is exit 2",
    )
    live.add_argument("--dsn", help="defaults to $RLS_GUARD_DSN, then $DATABASE_URL")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    return _check(args) if args.command == "check" else _live(args)


if __name__ == "__main__":
    raise SystemExit(main())
