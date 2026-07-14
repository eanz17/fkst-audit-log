-- Deterministic stability scan heartbeat. The cron always ticks; the detect
-- department no-ops unless STABILITY_DETECT_ENABLED=1.
return {
  type = "cron",
  interval = "5m",
  produces = "stability_scan_tick",
}
