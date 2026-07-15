-- Replays issue requests acknowledged during dry-run after the write posture is
-- enabled. Pending request bodies live in the issue-proxy cache, not the event.
return {
  type = "cron",
  interval = "5m",
  produces = "issue_reconcile_tick",
}
