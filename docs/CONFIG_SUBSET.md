# Configuration subset

`syslogd-rs` reads `rsyslog.conf` syntax with a frozen, documented
subset. Anything outside the subset is a parse error in strict mode
(the default for `-N1/--check`) and a warning in `--compat`.

## Selectors

Legacy selector lines only (RainerScript `if/then/call/ruleset` are
not supported):

```
facility.priority /path
facility.priority @@host[:port]     TCP forward
facility.priority @host[:port]      UDP forward
facility.priority :omusrmsg:*       wall (all users)
&:omusrmsg:*                      continuation
~                                 discard alias (deprecated by rsyslog)
stop                              stop processing further rules
```

Facilities: `*`, `kern user mail daemon auth syslog lpr news uucp
cron authpriv ftp local0-7` (`security` aliases `auth`).
Priority: `*`, `emerg..debug` (and deprecated `warn/error/panic`
aliases), `N` (0-7), `=name` exact, `!name` exclude. Multi-facility
lists apply to the last priority only (rsyslog behavior); later
`;` selectors overwrite earlier ones for the same facility; a
`!`-only chain selects nothing.

## Legacy directives

`$ModLoad imuxsock|imklog|imudp|imtcp`, `$UDPServerRun N`,
`$InputTCPServerRun N`, `$IncludeConfig glob`,
`$ActionFileDefaultTemplate`, `$ActionForwardDefaultTemplate`,
`$ActionFileEnableSync on|off`, `$RepeatedMsgReduction on|off`,
`$FileOwner/Group/CreateMode`, `$DirCreateMode` (+
`$DirOwner/Group`), `$Umask`, `$PrivDropToUser/Group`,
`$WorkDirectory`, `$MaxMessageSize`, `$EscapeControlCharactersOnReceive`,
`$ControlCharacterEscapePrefix`, `$DefaultNetstreamDriver*`,
`$template name,"..."`.

Unrecognized `$...` directives are strict errors; `--compat`
warns and skips them.

## RainerScript objects

Supported: `module(load=...)`,
`input(type="imudp"|"imtcp" ...)`, `action(type=...)` for
`omfile`, `omfwd` (incl. `StreamDriver.Mode="1"` TLS with
`x509/name` or `x509/certvalid`, `PermittedPeer`, CA/cert/key
files), `omusrmsg` (`users="*"` only), `omstdout`, `omdiscard`,
plus `template(name=... type="string" string="...")` and
`include(file=/config=)`.

Unsupported (strict error, compat warn-and-ignore is never used
for loss-critical ones): `imjournal`, `imrelp`, `immark`,
`omrelp`, `omjournal`, `omstdout`-adjacent modules (`ommysql`,
`ompgsql`), `queue.type="Disk"` (no durable spool), BSD property
blocks, `$outchannel`, pipes, `^program`, `/dev/*` actions,
TLS `fingerprint`/`anon` auth modes.

## Templates

Property replacer with substrings (`%prop:from:to%`) and the
options `sp-if-no-1st-sp`, `drop-last-lf`, `lowercase`,
`uppercase`, `secpath-replace`, `date-rfc3339`. Other options are
strict errors.

Templates must be defined before use (rsyslog order semantics):
in strict mode a use-before-define is an error; in `--compat`
the action is skipped, matching rsyslog.

Dynamic file paths (`?template` / `dynaFile`) must apply
`secpath-replace` to any user-controlled property
(`hostname`, `programname`, `fromhost-ip`, `syslogtag`,
`app-name`, `msg`, `rawmsg`) to prevent path traversal outside
the configured destination tree.

Built-in templates match rsyslog's documented reserved names:
`RSYSLOG_TraditionalFileFormat`, `RSYSLOG_FileFormat`,
`RSYSLOG_TraditionalForwardFormat`, `RSYSLOG_SysklogdFileFormat`,
`RSYSLOG_ForwardFormat`, `RSYSLOG_SyslogProtocol23Format`,
`RSYSLOG_SyslogRFC5424Format`, `RSYSLOG_DebugFormat`,
`RSYSLOG_WallFmt`, `RSYSLOG_StdUsrMsgFmt`.
