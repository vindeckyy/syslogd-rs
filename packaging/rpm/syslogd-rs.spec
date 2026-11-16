Name:           syslogd-rs
Version:        0.1.0
Release:        1%{?dist}
Summary:        memory-safe rsyslog-compatible syslog daemon
License:        MIT
Requires:       bsdutils
Conflicts:      rsyslog, syslog-ng

%description
A Linux syslog daemon in Rust that parses a documented subset of
rsyslog.conf and routes systemd journal, kernel, and network syslog
messages with rsyslog rule semantics.

%install
install -D -m 0755 target/x86_64-unknown-linux-gnu/release/syslogd-rs %{buildroot}/usr/sbin/syslogd-rs
install -D -m 0755 target/x86_64-unknown-linux-gnu/release/syslogng2rsyslog %{buildroot}/usr/sbin/syslogng2rsyslog
install -D -m 0644 deploy/systemd/syslogd-rs.service %{buildroot}/usr/lib/systemd/system/syslogd-rs.service
install -D -m 0644 deploy/journald/50-syslogd-rs.conf %{buildroot}/etc/systemd/journald.conf.d/50-syslogd-rs.conf

%post
# Deliberately no daemon-reload enable/start here. Cutover is an
# explicit operator step (tools/migrate.sh) so a broken config can
# never take down the host's only syslog daemon.
:

%files
/usr/sbin/syslogd-rs
/usr/sbin/syslogng2rsyslog
/usr/lib/systemd/system/syslogd-rs.service
/etc/systemd/journald.conf.d/50-syslogd-rs.conf

%changelog
* Sun Nov 15 2026 syslogd-rs maintainers <dev@syslogd-rs> - 0.1.0-1
- Initial release.
