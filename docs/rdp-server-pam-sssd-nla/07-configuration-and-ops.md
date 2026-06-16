# 07. Configuration and operations

## Example `frdpd.toml`

```toml
[server]
listen = "0.0.0.0:3389"
security = "nla"
tls_cert = "/etc/frdpd/tls.crt"
tls_key = "/etc/frdpd/tls.key"
# max_connections is omitted until the daemon enforces connection caps.

[auth]
mode = "pam-sssd"
pam_service = "frdpd"
# auth_socket = "/run/frdp-authd/authd.sock"
# Kerberos-first fields are intentionally omitted until the daemon enforces them.
# Do not configure kerberos, ntlm_fallback, keytab, or accepted_spn in the current parser.

# [session]
# session_socket = "/run/frdp-sesmand/sesmand.sock"

# [channels]
# Deny all client-requested static virtual channels by default.
# static_allow = "" accepts no channels. Example allow-list syntax:
# static_allow = "cliprdr,rdpsnd"
# Allowing a name only permits negotiation; clipboard/audio handlers are not implemented yet.

# The current parser still rejects [audit] instead of silently ignoring policy.
```

## PAM

Install or review the dedicated PAM service `/etc/pam.d/frdpd` from `server/frdp/pam/frdpd` and do not mix it with `login` or `sshd` without review. Verify:

- `pam_sss.so` in auth/account/session;
- `pam_limits.so` for resource limits;
- `pam_systemd.so` if logind integration is required;
- correct behavior for expired passwords, locked accounts, and denied groups.

The NLA password-backed flow is non-interactive. The in-process `frdpd` path and the `frdp-authd`
broker path set the password as `PAM_AUTHTOK` and answer PAM password prompts with the CredSSP/NLA
password because CredSSP/NLA is not a general-purpose prompt
transport. The PAM service should use modules/options that consume the existing authentication token,
such as `use_first_pass` or an equivalent SSSD profile. MFA or extra prompt flows require a separate UX
design.

Example non-interactive baseline:

```text
auth      required   pam_env.so
auth      sufficient pam_sss.so use_first_pass
auth      required   pam_deny.so
account   required   pam_sss.so
session   required   pam_limits.so
session   optional   pam_systemd.so
session   required   pam_sss.so
password  sufficient pam_sss.so use_authtok
```

For early integration testing, `frdpd --no-pam-session` keeps the PAM flow to authentication and account
checks only. Use this mode when the optional `frdp-authd` and `frdp-sesmand` IPC paths own authentication
and PAM sessions; do not use it for a production desktop path until the helpers are the canonical/default
owners. The packaged helper units listen on `/run/frdp-authd/authd.sock` and
`/run/frdp-sesmand/sesmand.sock`.

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

The helper units are installed but not required by the listener unit while helper IPC remains optional.
Enable/order them with `frdpd.service` when `auth_socket` and `session_socket` are configured, and set
`FRDPD_ARGS=--no-pam-session` in `/etc/frdpd/frdpd.env`. The helper topology is therefore installable but
not the canonical/default runtime path yet.

Hardening:

```ini
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LockPersonality=true
MemoryDenyWriteExecute=true
```

For `sesmand`, restrictions must account for the need to create user sessions, cgroups, and runtime directories.

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

## Troubleshooting checklist

1. Verify DNS, NTP, and reachability to DC/KDC.
2. Verify SPN/keytab with `kvno`.
3. Check SSSD status and NSS lookup.
4. Test the PAM stack with a local test helper.
5. Verify the TLS certificate chain.
6. Compare the client authentication mechanism: Kerberos vs NTLM.
7. Check group-based channel policy.
8. Check Xorg/Xvfb startup logs and the user runtime directory.

## Upgrade policy

- Pin the FreeRDP version in the release branch.
- Test FreeRDP/OpenSSL/Kerberos security updates in staging.
- Make configuration schema migrations forward-compatible only.
- Before upgrade, save `/etc/frdpd`, the PAM service, the SSSD configuration snapshot, and package versions.
- Rollback must restore the binary, configuration schema, and systemd units together.
