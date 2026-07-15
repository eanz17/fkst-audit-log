# Retired custom issue solver

This directory preserves the retired `issue-proxy.solution_request` delivery
endpoint and its tests. The custom `issue-watcher` and `issue-solver` packages
remain under `packages/` for source history, but are intentionally excluded
from `fkst.workspace.toml` and `scripts/run.sh`.

Production repair is owned by the official fkst GitHub devloop and consensus
packages running from the Aevatar host workspace. Nothing below this archive
directory is scanned as an active fkst package root.
