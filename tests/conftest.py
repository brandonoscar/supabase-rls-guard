from __future__ import annotations

import os

import pytest

DSN = os.environ.get("RLS_GUARD_TEST_DSN", "")
REQUIRE_POSTGRES = os.environ.get("RLS_GUARD_REQUIRE_POSTGRES") == "1"


def pytest_collection_modifyitems(config: pytest.Config, items: list[pytest.Item]) -> None:
    if DSN:
        return
    if REQUIRE_POSTGRES:
        raise pytest.UsageError("RLS_GUARD_REQUIRE_POSTGRES=1 but RLS_GUARD_TEST_DSN is not set")
    skip = pytest.mark.skip(reason="set RLS_GUARD_TEST_DSN to run the live tests")
    for item in items:
        if "postgres" in item.keywords:
            item.add_marker(skip)
