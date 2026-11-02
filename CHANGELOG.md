# Changelog

Notable changes, newest first. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [semantic versioning](https://semver.org/).

## [Unreleased]

## [0.1.0] - 2026-11-02

First release.

### Added

- `rls-guard check`: the migrations replayed in order, so every table in the exposed schemas ends with row-level security on and no view opens a way around it; and every SQL statement in your Python that touches a tenant table names the tenant column, unless a licence keyed by file and statement fingerprint says why not.
- `rls-guard live`: the table and view checks against a live database's catalog, plus tables owned by a browser role.
- Test helpers: `as_user`, `count_visible`, and a shim that gives plain Postgres Supabase's roles, `auth.uid()` and default privileges.
- A composite GitHub Action (`action.yml`), with `require-live` to fail when the database URL is missing.

[Unreleased]: https://github.com/brandonoscar/supabase-rls-guard/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/brandonoscar/supabase-rls-guard/releases/tag/v0.1.0
