-- Watches host-root-relative `watch/*.log` for creation or (len, mtime) change.
-- The engine emits { path = "<absolute path>" } per changed file and rescans
-- all existing matches on supervise startup (crash recovery re-derivation).
return {
  type = "file_watch",
  glob = "watch/*.log",
  produces = "audit_file_changed",
}
