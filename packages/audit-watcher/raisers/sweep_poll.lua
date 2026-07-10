-- Cron fallback: re-derives unprocessed tail growth for files already seen via
-- file_watch, in case a filesystem notification window was missed.
return {
  type = "cron",
  interval = "10m",
  produces = "audit_sweep_tick",
}
