# syslogd-rs

## 0.1.0 — 2026-11-15

- Memory-safe rsyslog-compatible syslog daemon in Rust
  (`syslogd-rs` binary).
- Parses a documented subset of `rsyslog.conf` (including
  `/etc/rsyslog.d/*.conf` expansion) with strict fail-closed
  `--check` (`-N1`) and `--compat` rsyslog-parity modes.
- Ingress: systemd `syslog.socket` adoption, `/dev/log`, kernel
  log, UDP, TCP (per-frame RFC 6587 framing), TLS with
  `x509/name` / `x509/certvalid` verification; no plaintext
  fallback on TLS ports.
- Routing: rsyslog semantics (all rules fire in merged include
  order, `&` continuations, `~` discard, full selector grammar
  including documented gotchas).
- Templates: property replacer plus byte-exact `RSYSLOG_*`
  built-ins; dynafile paths require `secpath-replace`.
- Actions: files (static + dynamic), file-creation attributes,
  fixed-slot stdout, `:omusrmsg:` (wall), discard, and TCP/UDP/
  TLS forwarding with octet-counted framing.
- Repeat suppression, control-character escaping, oversized
  message accounting, TLS client SAN checks, file symlink
  rejection (`O_NOFOLLOW`), and internal metrics
  (SIGUSR2 / shutdown summary).
- SIGHUP hot-reloads the ruleset without restarting listeners.
- `syslogng2rsyslog` converter for common syslog-ng patterns.
- Packaging: Debian and RPM contracts, a single systemd service
  unit (`syslog.socket` required, `StandardOutput=null`),
  journald forward drop-in, and `tools/migrate.sh` with an
  explicit, rollback-capable cutover.
