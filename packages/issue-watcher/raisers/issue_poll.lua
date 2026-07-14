-- Deterministic discovery heartbeat. The cron always ticks; the collect
-- department no-ops unless ISSUE_SOLVE_ENABLED=1. Mirrors the audit-watcher
-- sweep/poll raisers.
return {
  type = "cron",
  interval = "10m",
  produces = "issue_poll_tick",
}
