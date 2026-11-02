"""``rls-guard.toml``: what to scan and what is allowed.

[migrations]
paths = ["supabase/migrations/*.sql"]
schemas = ["public"]            # schemas your API exposes
rls_off_allowlist = []          # keep empty unless you can say why

[scoping]
sources = ["src/**/*.py"]
tables = '\\bapp_[a-z_]+\\b'     # regex for your tenant tables
tenant_column = "company_id"
min_queries = 1

[[scoping.allow]]
path = "src/app/billing.py"
fingerprint = "711c62ba24"
reason = "Stripe webhook: the event carries only Stripe's ids, unique per company"

[live]
schemas = ["public"]
rls_off_allowlist = ["spatial_ref_sys"]   # PostGIS reference table, no tenant rows

Every mistake is an error, never a default: an unknown key (a typo like
``source``), a wrong type, an empty list of schemas. A guard whose config
quietly turned it off reads as green. Names follow SQL: ``notes`` and
``public.notes`` are lower-cased, and ``'"Notes"'`` keeps its case.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from rls_guard.migrations import parse_name
from rls_guard.scoping import Licence

_KEYS = {
    "migrations": ("paths", "schemas", "rls_off_allowlist"),
    "scoping": ("sources", "tables", "tenant_column", "min_queries", "allow"),
    "live": ("schemas", "rls_off_allowlist"),
}
_ALLOW_KEYS = ("path", "fingerprint", "reason")
_RETIRED = {
    "dead_marker": (
        "dead_marker is gone: start a never-applied migration with the line "
        "`-- rls-guard: never-applied` instead"
    ),
}
_FINGERPRINT = re.compile(r"[0-9a-f]{10}")


@dataclass(frozen=True)
class MigrationsConfig:
    paths: tuple[str, ...] = ("supabase/migrations/*.sql",)
    schemas: tuple[str, ...] = ("public",)
    rls_off_allowlist: tuple[str, ...] = ()


@dataclass(frozen=True)
class ScopingConfig:
    sources: tuple[str, ...] = ()
    tables: str = ""
    tenant_column: str = "company_id"
    min_queries: int = 1
    allow: tuple[Licence, ...] = ()

    @property
    def enabled(self) -> bool:
        return bool(self.sources and self.tables)

    def table_pattern(self) -> re.Pattern[str]:
        return re.compile(self.tables, re.IGNORECASE)


@dataclass(frozen=True)
class LiveConfig:
    schemas: tuple[str, ...] = ("public",)
    rls_off_allowlist: tuple[str, ...] = ("spatial_ref_sys",)


@dataclass(frozen=True)
class Config:
    root: Path = field(default_factory=Path)
    migrations: MigrationsConfig = field(default_factory=MigrationsConfig)
    scoping: ScopingConfig = field(default_factory=ScopingConfig)
    live: LiveConfig = field(default_factory=LiveConfig)


class ConfigError(ValueError):
    pass


def _section(data: dict[str, Any], name: str) -> dict[str, Any] | None:
    if name not in data:
        return None
    section = data[name]
    if not isinstance(section, dict):
        raise ConfigError(f"[{name}] must be a table")
    unknown = sorted(set(section) - set(_KEYS[name]))
    for key in unknown:
        if key in _RETIRED:
            raise ConfigError(f"[{name}] {_RETIRED[key]}")
    if unknown:
        raise ConfigError(
            f"[{name}] has unknown key(s) {unknown}; the keys are {list(_KEYS[name])}"
        )
    return section


def _strings(
    section: dict[str, Any], name: str, key: str, default: tuple[str, ...], *, required: bool
) -> tuple[str, ...]:
    if key not in section:
        if required:
            raise ConfigError(f"[{name}] needs {key}")
        return default
    value = section[key]
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ConfigError(f"[{name}] {key} must be a list of strings")
    return tuple(value)


def _string(section: dict[str, Any], name: str, key: str, default: str) -> str:
    value = section.get(key, default)
    if not isinstance(value, str) or not value.strip():
        raise ConfigError(f"[{name}] {key} must be a non-empty string")
    return value


def _schemas(section: dict[str, Any], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    raw = _strings(section, name, "schemas", default, required=False)
    if not raw:
        raise ConfigError(f"[{name}] schemas is empty, so nothing would be checked")
    folded = []
    for entry in raw:
        try:
            schema, value = parse_name(entry)
        except ValueError as exc:
            raise ConfigError(f"[{name}] schemas: {exc}") from None
        if schema is not None:
            raise ConfigError(f"[{name}] schemas: {entry!r} is a schema, not schema.name")
        folded.append(value)
    return tuple(folded)


def _allowlist(section: dict[str, Any], name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    entries = _strings(section, name, "rls_off_allowlist", default, required=False)
    for entry in entries:
        try:
            parse_name(entry)
        except ValueError as exc:
            raise ConfigError(f"[{name}] rls_off_allowlist: {exc}") from None
    return entries


def _licences(section: dict[str, Any]) -> tuple[Licence, ...]:
    entries = section.get("allow", [])
    if isinstance(entries, dict):
        raise ConfigError(
            "scoping.allow must be a list of entries: write each one as [[scoping.allow]], "
            "with two pairs of brackets"
        )
    if not isinstance(entries, list):
        raise ConfigError("scoping.allow must be a list of entries ([[scoping.allow]])")
    licences = []
    for i, entry in enumerate(entries):
        if not isinstance(entry, dict):
            raise ConfigError(f"scoping.allow[{i}] must be a table with path, fingerprint, reason")
        missing = [k for k in _ALLOW_KEYS if k not in entry]
        if missing:
            raise ConfigError(f"scoping.allow[{i}] is missing {missing}")
        unknown = sorted(set(entry) - set(_ALLOW_KEYS))
        if unknown:
            raise ConfigError(f"scoping.allow[{i}] has unknown key(s) {unknown}")
        if not all(isinstance(entry[k], str) for k in _ALLOW_KEYS):
            raise ConfigError(f"scoping.allow[{i}]: path, fingerprint and reason are strings")
        if not _FINGERPRINT.fullmatch(entry["fingerprint"]):
            raise ConfigError(
                f"scoping.allow[{i}] fingerprint {entry['fingerprint']!r} is not one: copy the "
                "10 characters rls-guard printed"
            )
        licences.append(Licence(entry["path"], entry["fingerprint"], entry["reason"]))
    return tuple(licences)


def _scoping(section: dict[str, Any]) -> ScopingConfig:
    sources = _strings(section, "scoping", "sources", (), required=True)
    if not sources:
        raise ConfigError("[scoping] sources is empty, so no code would be read")
    tables = _string(section, "scoping", "tables", "")
    try:
        re.compile(tables)
    except re.error as exc:
        raise ConfigError(f"[scoping] tables is not a valid regex: {exc}") from None
    min_queries = section.get("min_queries", 1)
    if isinstance(min_queries, bool) or not isinstance(min_queries, int) or min_queries < 1:
        raise ConfigError("[scoping] min_queries must be a whole number, 1 or more")
    return ScopingConfig(
        sources=sources,
        tables=tables,
        tenant_column=_string(section, "scoping", "tenant_column", "company_id"),
        min_queries=min_queries,
        allow=_licences(section),
    )


def load(path: str | Path) -> Config:
    """Read a config file. Paths in it are relative to the file's directory."""
    file = Path(path)
    try:
        data = tomllib.loads(file.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ConfigError(f"{file}: {exc}") from exc
    unknown = sorted(set(data) - set(_KEYS))
    if unknown:
        raise ConfigError(f"{file}: unknown section(s) {unknown}; the sections are {list(_KEYS)}")
    try:
        migrations = MigrationsConfig()
        if (mig := _section(data, "migrations")) is not None:
            migrations = MigrationsConfig(
                paths=_strings(mig, "migrations", "paths", MigrationsConfig.paths, required=False),
                schemas=_schemas(mig, "migrations", MigrationsConfig.schemas),
                rls_off_allowlist=_allowlist(mig, "migrations", ()),
            )
        scoping = ScopingConfig()
        if (sc := _section(data, "scoping")) is not None:
            scoping = _scoping(sc)
        live = LiveConfig()
        if (lv := _section(data, "live")) is not None:
            live = LiveConfig(
                schemas=_schemas(lv, "live", LiveConfig.schemas),
                rls_off_allowlist=_allowlist(lv, "live", LiveConfig.rls_off_allowlist),
            )
    except ConfigError as exc:
        raise ConfigError(f"{file}: {exc}") from None
    return Config(root=file.resolve().parent, migrations=migrations, scoping=scoping, live=live)


__all__ = ["Config", "ConfigError", "LiveConfig", "MigrationsConfig", "ScopingConfig", "load"]
