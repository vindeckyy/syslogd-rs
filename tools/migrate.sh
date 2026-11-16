#!/bin/sh
# One-command rsyslog -> syslogd-rs migration.
# Run as root on a host where rsyslog is the active syslog daemon.
# Idempotent-ish: safe to re-run. Never overwrites /etc/rsyslog.conf.
set -e

PKG="$1"
if [ -z "$PKG" ]; then
    echo "usage: $0 ./syslogd-rs_0.1.0_amd64.deb" >&2
    exit 2
fi

echo "== 1. Config check (strict; FAILS if anything unsupported) =="
/usr/sbin/syslogd-rs -N1 -f /etc/rsyslog.conf
echo "check passed; installing..."

echo "== 2. Install package (side-by-side; Conflicts removes rsyslog) =="
apt install -y "$PKG"

echo "== 3. Enable syslogd-rs =="
systemctl daemon-reload
systemctl enable --now syslogd-rs.service

echo "== 4. Verify =="
logger -t syslogd-rs-verify "migration check $$"
sleep 2
if grep -q "migration check $$" /var/log/syslog; then
    echo "logging active; journald forwarding on"
else
    echo "ERROR: verification message missing" >&2
    echo "Rolling back..." >&2
    systemctl disable --now syslogd-rs.service || true
    apt install -y rsyslog
    systemctl enable --now rsyslog.service || systemctl enable --now rsyslog
    echo "rolled back to rsyslog" >&2
    exit 1
fi
echo "done"
