# 07. Configuration and operations

## Example `frdpd.toml`

```toml
[server]
listen = "0.0.0.0:3389"
security = "nla"
tls_cert = "/etc/frdpd/tls.crt"
tls_key = "/etc/frdpd/tls.key"
# 0 or omitted means unlimited accepted peer workers.
# max_connections = 64

[auth]
mode = "pam-sssd"
pam_service = "frdpd"
auth_socket = "/run/frdp-authd/authd.sock"
# Kerberos identity fields are validated, but kerberos=true fails closed until
# the integrated CredSSP/SPNEGO acceptor path is implemented.
# ntlm_fallback = false
# kerberos = false
# keytab = "/etc/frdpd/frdpd.keytab"
# accepted_spn = "TERMSRV/rdp01.example.com"

[session]
session_socket = "/run/frdp-sesmand/sesmand.sock"
# Cap active plus reconnect-retained sessions; 0 or omission means unlimited.
# max_sessions = 64
# Optional POSIX guards for new session-agent children; 0 or omission means unlimited.
# max_processes = 256
# memory_max_mb = 4096
# Also apply those limits through a transient per-session systemd scope.
# Keep false where no system manager/system bus is available.
# systemd_scope = false
# Optional per-session CPU capacity; 100 is one CPU. Requires systemd_scope=true.
# cpu_quota_percent = 100
# agent_heartbeat_interval_ms = 5000
# agent_heartbeat_timeout_ms = 500
# agent_heartbeat_failures = 3

# [channels]
# Channel filtering defaults to blocklist mode with empty lists.
# static_mode = "blocklist"
# static_deny = ""
# dynamic_mode = "blocklist"
# dynamic_deny = ""
# Dynamic channel lists feed the DVC authorization callback, but remain preparatory
# while drdynvc and useful dynamic handlers stay disabled.
# Use allowlist mode to permit only exact channel names:
# static_mode = "allowlist"
# static_allow = "cliprdr"
# Allowing a name only permits negotiation; runtime gates still deny handlers
# that are not implemented yet, including arbitrary static channels, rdpsnd
# audio output, and rdpdr device redirection.

# [clipboard]
# mode = "disabled"
# direction = "disabled"
# max_text_bytes = 65536

# [audit]
# enabled = false
# Structured audit sinks are not implemented yet; enabled = true fails closed
# until runtime enforcement exists.
```

## PAM

Install or review the dedicated PAM service `/etc/pam.d/frdpd` from `server/frdp/pam/frdpd` and do not mix it with `login` or `sshd` without review. Verify:

- `pam_sss.so` in auth/account/session;
- `pam_limits.so` for resource limits;
- no `pam_systemd.so` when `[session].logind_session = true`; this is a mandatory operator
  precondition because `frdp-sesmand` owns the login1 registration and does not parse PAM stacks;
- correct behavior for expired passwords, locked accounts, and denied groups.

The NLA password-backed flow is non-interactive. The normal `frdp-authd` broker path sets the password
through the PAM conversation callback and answers at most one password prompt with the CredSSP/NLA
password because CredSSP/NLA is not a general-purpose prompt
transport. The PAM service should use modules/options that request at most the standard hidden password,
such as `try_first_pass` or an equivalent SSSD profile. MFA, password-change, or extra prompt flows
require a separate UX design and fail closed until explicitly implemented.

Example non-interactive baseline:

```text
auth      required   pam_env.so
auth      sufficient pam_sss.so try_first_pass
auth      required   pam_deny.so
account   required   pam_sss.so
session   required   pam_limits.so
session   required   pam_sss.so
password  sufficient pam_sss.so use_authtok
```

Normal startup requires both helper sockets: `frdp-authd` owns PAM authentication/account checks and
`frdp-sesmand` launches one PAM-owner process per managed session plus the desktop agent. The owner retains
the PAM handle if the manager exits. After confirming manager death through `pidfd`, it allows one
same-UID replacement manager to take ownership within 10 seconds; concurrent takeover is rejected, and
all later commands are pinned to the selected PID. Chained takeover is forbidden, while an ambiguous
response can be retried idempotently by that same PID. Incomplete commands are bounded to
250 ms while the owner monitors the manager, and expiry or death of the replacement starts retrying agent
cleanup immediately before PAM close. Restart recovery performs this takeover before either importing
an eligible `DISCONNECTED` session or stopping an ineligible scope/process group, so validation and slow
teardown cannot consume the takeover window. Imported sessions retain their session id, display,
agent PID, PAM/SSSD state, and authenticated agent control channel. The owner writes a synchronized close
receipt before durable cleanup. The packaged helper units listen on
`/run/frdp-authd/authd.sock` and `/run/frdp-sesmand/sesmand.sock`. The old peer-worker direct PAM
fallback has been removed; use `frdpd --pam-auth-test` for local PAM smoke checks without starting the
full helper topology.

For host login1 integration, set `logind_session = true` in `[session]` and keep
`systemd_scope = false`. The blocked child first applies its POSIX limits, drops to the final
UID/GID/group vector, and acknowledges that identity. The manager then registers its PID as a remote
X11 session, passes `XDG_SESSION_ID` and `XDG_RUNTIME_DIR` through the remaining launch barrier, and
gives the login1 FIFO to the durable PAM owner. Startup/reload and session creation fail closed when
login1 is unavailable. Normal close calls `ReleaseSession`; manager-crash recovery obtains a duplicate
of the owner-held FIFO only after takeover, validates the authoritative login1 identity and properties,
and imports an eligible disconnected session. Failed validation closes the FIFO after process
termination and before PAM close. This mode requires a PAM stack without `pam_systemd.so`.

The installed Ubuntu lifecycle gate exercises this mode with both local PAM and Samba AD/SSSD. It
checks the exact login1 leader, UID, remote-X11 class/type/service, and runtime directory, detaches the
client, kills `frdp-sesmand`, and requires the replacement manager to import and reconnect the same
session id, display, agent PID, and login1 id. Explicit close must then remove the login1 record,
process group, and runtime artifacts.

## SSSD operations

Baseline checks:

```bash
sssctl domain-status corp.example.com
getent passwd user@corp.example.com
id user@corp.example.com
kinit user@CORP.EXAMPLE.COM
kvno TERMSRV/rdp01.example.com
```

Common problems:

- clock skew;
- incorrect DNS canonical name;
- missing SPN;
- keytab with stale kvno;
- access provider denying the user;
- ambiguous short names.

## Keytab rotation

1. Create or update the service account / machine account SPN.
2. Issue a new keytab.
3. Set permissions to `0600 root:frdpd` or root-only.
4. Restart the authentication broker without stopping existing desktop sessions, if the architecture supports it.
5. Verify `kvno TERMSRV/fqdn` and successful Kerberos login.
6. Remove old keys according to AD policy.

## systemd units

Installed unit examples:

- `frdpd.service`;
- `frdp-authd.service`;
- `frdp-sesmand.service`;
- per-user transient units for `frdp-session-agent`.

The helper units are required for normal listener startup. The shipped `frdpd.service` pulls in and
orders `frdp-authd.service` and `frdp-sesmand.service`; all three units read
`/etc/frdpd/frdpd.toml`, the shipped config points at the helper default sockets,
and `FRDPD_ARGS` can stay empty for the canonical helper topology.

`frdp-sesmand.service` preserves `/run/frdp-sesmand` across automatic restarts and uses
`KillMode=process`, allowing the per-session PAM owners and disconnected desktop process groups to
survive a main-process failure long enough for the single replacement-manager takeover. On a normal
service stop, `frdp-sesmand` still closes every tracked session itself; if replacement takeover does not
complete within the owner deadline, the owner terminates the process group and closes PAM/login1.

The Debian preview package deliberately leaves all three units disabled and stopped after installation.
Provision the TLS certificate and key, review `/etc/pam.d/frdpd`, validate SSSD/NSS access, and configure
the protected NTLM SAM path before exposing the listener. Then enable the listener only; its systemd
dependencies start both helper units for each boot:

```bash
systemctl enable --now frdpd.service
```

Do not enable either helper as a standalone boot service. Before the first enable, use
`systemd-analyze verify` and the local PAM smoke path where appropriate, then confirm all three units
and their journals after startup.

On package upgrade, only units that are already running are restarted after the new files are configured.
Package removal stops the listener and both helpers even when they were started manually.

The shipped unit hardening baseline is enforced by `TestFreeRDPFrdpSystemd`.
The listener unit includes:

```ini
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
LockPersonality=true
MemoryDenyWriteExecute=true
UMask=0077
LimitNOFILE=1024
```

The auth broker shares that strict baseline without bind-service capabilities,
and additionally declares `RuntimeDirectory=frdp-authd` plus explicit write
access to `/run/frdp-authd` and `/run/frdp-auth-token`.

For `sesmand`, restrictions intentionally account for PAM, logind, user session startup, cgroups, and runtime
directories. The shipped unit keeps `PrivateTmp=true`, `ProtectSystem=full`, kernel/log/clock/hostname/realtime/personality
restrictions, `SystemCallArchitectures=native`, and explicit write access only to `/run/frdp-sesmand` plus
`/run/frdp-auth-token`. It also sets `TasksMax=4096` as a baseline process-count guard for the session
manager and its launched desktop agent process groups. Per-session agents always receive configured
POSIX `RLIMIT_NPROC` and `RLIMIT_AS` guards. With `[session].systemd_scope = true`, the manager holds
each child behind a launch barrier while it creates a transient `frdp-session-<uuid>.scope`, moves the
child PID into it, maps the same limits to `TasksMax` and `MemoryMax`, applies an optional static
`CPUQuotaPerSecUSec`, and confirms active state. Startup,
reload, asynchronous unit creation, and session creation fail closed when requested ownership cannot be
established. Reloaded process, memory, and CPU limits are applied as one rollback-protected batch to all
existing scoped sessions; a rollback failure stops the manager so normal cleanup closes the sessions.
Existing non-scoped sessions retain their POSIX limits, and scope ownership itself remains a launch-time
choice. Durable metadata drives restart cleanup; stale bus handles reconnect, and bounded stop falls back
to cgroup-v2 `cgroup.kill` plus the process-group guard. Leave the setting disabled without a system
manager/system bus. Metadata V3 records per-session PAM ownership; restart recovery requests close from
the surviving owner and consumes its synchronized receipt before removing session artifacts. A live or
uncertain owner blocks startup, while proven-stale owner sockets are removed after metadata reconciliation.
Valid orphan close receipts also authorize same-inode removal of the corresponding dead agent socket, and
display reservations are globally reconciled against their recorded manager PID/start time on startup. A
durable `pam-<session>.failed` marker or a stale owner endpoint without a valid close receipt blocks startup
for operator investigation; neither is interpreted as successful PAM cleanup.
Operators can replace the complete cgroup tuple for one existing scoped session without restarting it:

```sh
frdpctl set-session-limits <session-id> \
  --max-processes 256 --memory-max-mb 2048 --cpu-quota-percent 100
```

All three options are mandatory; `0` means unlimited for that property. The command is rejected for an
unknown session, a session created without `systemd_scope`, or a value outside the configuration bounds.
The manager applies the tuple atomically from the operator's perspective: a failed update restores that
session's complete previous cgroup tuple, and an unconfirmed rollback stops the manager so normal cleanup
runs. A successful `frdpctl reload` deliberately resets every existing scoped session, including runtime
overrides, to the tuple in `frdpd.toml`. POSIX `RLIMIT_NPROC` and `RLIMIT_AS` remain launch-time guards and
are not changed by this command.

SELinux and AppArmor draft profiles install as inactive examples under `/usr/share/frdpd/security`. They are
not loaded automatically and must be reviewed, adapted, and validated for the target distribution before use.

## Logging and audit

Events should be written to journald in a structured format:

- `connection.accepted`;
- `tls.negotiated`;
- `nla.started`;
- `auth.success` / `auth.failure`;
- `pam.account.denied`;
- `session.created` / `session.reconnected` / `session.closed`;
- `channel.opened` / `channel.denied`.

It is forbidden to log passwords, raw CredSSP blobs, Kerberos tickets, keytab paths with sensitive parameters, or clipboard contents.
Current `frdpd` peer/channel/session logs escape client-supplied hostnames, authenticated usernames, static channel names, and IPC-supplied session ids, display names, agent socket paths, and session-manager error strings, but the structured journald schema above is still planned work.

## Troubleshooting checklist

1. Verify DNS, NTP, and reachability to DC/KDC.
2. Verify SPN/keytab with `kvno`.
3. Check SSSD status and NSS lookup.
4. Test the PAM stack with a local test helper.
5. Verify the TLS certificate chain.
6. Compare the client authentication mechanism: Kerberos vs NTLM.
7. Check the static/dynamic channel filter mode and exact channel lists.
8. Check Xorg/Xvfb startup logs and the user runtime directory.

## Upgrade policy

- Pin the FreeRDP version in the release branch.
- Test FreeRDP/OpenSSL/Kerberos security updates in staging.
- Make configuration schema migrations forward-compatible only.
- Before upgrade, save `/etc/frdpd`, the PAM service, the SSSD configuration snapshot, and package versions.
- Rollback must restore the binary, configuration schema, and systemd units together.
