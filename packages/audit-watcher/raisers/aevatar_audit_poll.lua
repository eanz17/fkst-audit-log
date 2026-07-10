-- Optional Aevatar audit trail poller. The cron always emits a tick, but the
-- collect department only calls NyxID when AEVATAR_AUDIT_ENABLED=1.
return {
  type = "cron",
  interval = "1m",
  produces = "aevatar_audit_poll_tick",
}
