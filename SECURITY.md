# Security policy

## Reporting a vulnerability

Report it privately on GitHub: open the **Security** tab and choose **Report a vulnerability**. Please don't open a public issue for it.

Say what you ran, what happened and what should have happened. Expect a first reply within a week. Once a fix ships, the advisory is published and credits you, unless you'd rather not be named.

## What counts

- A table, view or tenant query that should fail a check and passes.
- A licence that covers more than the one query it names.
- `as_user` leaving its role or claims in place after the block, or committing anything.

A check that fails something it shouldn't is a bug, not a vulnerability: open an issue.

## Supported versions

Only the latest release gets fixes.
