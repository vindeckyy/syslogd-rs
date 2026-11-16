# syslogd-rs

[![CI](https://github.com/vindeckyy/syslogd-rs/actions/workflows/ci.yml/badge.svg)](https://github.com/vindeckyy/syslogd-rs/actions/workflows/ci.yml)
[![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-stable-orange.svg)](rust-toolchain.toml)

A memory-safe syslog daemon in Rust that behaves like `rsyslogd`.
It parses a documented subset of `rsyslog.conf` and speaks the
same wire protocols, but it refuses anything it cannot honor
instead of silently dropping rules.

## Why

Host logging is infrastructure. A `rsyslogd` replacement that
silently skips unsupported rules loses messages in production.
`syslogd-rs` fails closed in strict mode: before it takes over
a logging path, `--check` rejects any construct it cannot
execute with `file:line`. `--compat` reproduces rsyslog's own
warn-and-continue behavior when you need parity testing.

## Features

- **Ingress**: systemd `syslog.socket` adoption, `/dev/log`,
  kernel log (`/proc/kmsg`), UDP, TCP (per-frame RFC 6587
  detection), TLS with `x509/name` / `x509/certvalid`.
- **Routing**: rsyslog semantics — all rules fire in merged
  include order unless `stop`, `&` continuations, `~` discard,
  full legacy selector grammar including the documented
  gotchas.
- **Actions**: files (static and dynamic `?template`),
  forwarding (TCP/UDP/TLS, octet-counted framing), `:omusrmsg:`
  to all logged-in users, stdout, discard.
- **Safety**: dynamic paths require `secpath-replace`,
  outputs reject symlinked paths with `O_NOFOLLOW`, fail-closed
  TLS (no plaintext fallback), `$RepeatedMsgReduction`
  honoring, control-char escaping, `PrivDropToUser/Group`.

## Quick start

```sh
syslogd-rs -N1 -f /etc/rsyslog.conf        # strict check
syslogd-rs -n -iNONE -f /etc/rsyslog.conf  # run
```

Or install the package (side-by-side; `Conflicts: rsyslog`):

```sh
syslogd-rs -N1 -f /etc/rsyslog.conf   # must pass first
apt install ./syslogd-rs_0.1.0_amd64.deb
systemctl enable --now syslogd-rs
# or: tools/migrate.sh ./syslogd-rs_0.1.0_amd64.deb
```

Exit codes: 0 ok, 1 config/parse, 2 bind/listener (including
`tls_cert_missing`), 3 internal.

## Configuration subset

Full grammar, template options, and unsupported-construct
semantics: [docs/CONFIG_SUBSET.md](docs/CONFIG_SUBSET.md).

| Area | Supported in v1 |
| --- | --- |
| Inputs | imuxsock, imklog, imudp, imtcp |
| Outputs | omfile, omfwd, omusrmsg(\*), omstdout, discard |
| TLS | `StreamDriver.Mode="1"` listeners + forward, `x509/name` / `x509/certvalid` |
| Templates | property replacer + `RSYSLOG_*` built-ins, `secpath-replace` required on dyn paths |
| Modules not supported | imjournal, imrelp, immark, omrelp, omjournal, DB outputs, disk queues, pipes, `^program`, full RainerScript |

Anything outside the matrix is a strict parse error with a
`file:line` diagnostic.

## Metrics

Atomic counters, printed on SIGUSR2 and at shutdown:
`msgs_in`, `dup_suppressed`, `action_dropped`, `file_errors`,
`fwd_errors`, `oversize`, `tls_auth_fail`, `parse_errors`.

## Deployment

- Single service unit with `Requires=syslog.socket` and
  `Alias=syslog.service`, so existing systemd tooling works.
- `StandardOutput=null` and `Type=notify` (`READY=1` after bind).
- SIGHUP hot-reloads the ruleset without restarting listeners.
- Manual pages: `man/syslogd-rs.8`, `man/syslogng2rsyslog.1`.

## Development

```sh
cargo test --offline          # unit tests
cargo fmt --all -- --check    # formatting
cargo clippy -- -D warnings   # lints
```

Fixture gates (stock Debian and RHEL configs, plus negative
cases in `tests/fixtures/bad/`):

```sh
cd tests/fixtures
"$PWD/target/debug/syslogd-rs" -N1 -f debian-rsyslog.conf
"$PWD/target/debug/syslogd-rs" -N1 -f rhel-rsyslog.conf
```

## Security

See [SECURITY.md](SECURITY.md). TLS client certificates are
verified against the configured CA; `x509/name` additionally
checks the SAN against `PermittedPeer`. Output paths are never
followed through symlinks.

## syslog-ng users

`syslogng2rsyslog` converts the common syslog-ng patterns to
the supported subset and exits non-zero on anything else.

## License

MIT. See [LICENSE](LICENSE).
