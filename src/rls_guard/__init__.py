"""CI guards for multi-tenant Postgres and Supabase.

* ``migrations``: the migrations replayed in order; every table ends with
  RLS on, and every view is ``security_invoker`` with the browser roles
  revoked.
* ``scoping``: every SQL statement against a tenant table names the tenant
  column, or is licensed with a reason.
* ``live``: the same questions asked of the database catalog.
* ``testing``: read as a real user inside a rolled-back transaction, to prove
  one tenant cannot see another's rows.
"""

from rls_guard.migrations import (
    Finding,
    Migration,
    check_migrations,
    tables_without_rls,
    unsafe_views,
)
from rls_guard.scoping import Licence, Query, ScopingReport, check_scoping, find_queries

__version__ = "0.1.0"

__all__ = [
    "Finding",
    "Licence",
    "Migration",
    "Query",
    "ScopingReport",
    "__version__",
    "check_migrations",
    "check_scoping",
    "find_queries",
    "tables_without_rls",
    "unsafe_views",
]
