# Security Policy

## Supported versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |
| < 0.1.0 | :x:                |

## Reporting a vulnerability

Do not open a public issue for security reports.

Send a description, reproduction steps, and impact assessment to:

** maintainer: open a private security advisory on this repository **
or email the maintainer contact listed in `README.md`.

You will receive an acknowledgement within 72 hours. Once a fix is
available, a security advisory and a patched release are published,
and credit is given to the reporter unless anonymity was requested.

## Scope

In scope: `syslogd-rs` and `syslogng2rsyslog` binaries and their
configuration handling, TLS verification, file write paths, and
drop-in replacement behavior.

Out of scope: vulnerabilities in upstream rsyslog, third-party
software acting as a syslog client, and malware delivered by an
attacker who already has root execution on the logging host.
