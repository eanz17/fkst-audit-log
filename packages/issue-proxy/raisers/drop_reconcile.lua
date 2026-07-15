-- A level-triggered reconciliation keeps drop closure independent from the
-- official devloop event graph. Every candidate is fresh-read and revalidated.
return {
  type = "cron",
  interval = "5m",
  produces = "drop_reconcile_tick",
}
