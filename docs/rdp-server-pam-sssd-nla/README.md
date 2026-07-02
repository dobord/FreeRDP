# FreeRDP-based xrdp alternative: project material set

**Preparation date:** 2026-06-11
**Goal:** describe the architecture of a Linux RDP server based on FreeRDP with enterprise authentication through PAM/SSSD and NLA/CredSSP support with Kerberos.

## Document set

| File | Purpose |
|---|---|
| [01-executive-summary.md](01-executive-summary.md) | Short decision record, key conclusions, recommended MVP, and project boundaries. |
| [02-architecture.md](02-architecture.md) | Component architecture, processes, IPC, graphics, RDP channels, and resilience. |
| [03-authentication-pam-sssd-nla-krb5.md](03-authentication-pam-sssd-nla-krb5.md) | Deep dive into NLA/CredSSP, Kerberos, PAM, SSSD, login flows, and hardening. |
| [04-comparison-with-xrdp.md](04-comparison-with-xrdp.md) | Pros/cons compared with xrdp and decision matrix. |
| [05-system-requirements.md](05-system-requirements.md) | Operating systems, packages, AD/Kerberos prerequisites, network, sizing, and security. |
| [06-implementation-plan.md](06-implementation-plan.md) | Step-by-step implementation plan, milestones, risks, and acceptance criteria. |
| [07-configuration-and-ops.md](07-configuration-and-ops.md) | Configuration examples, systemd, PAM, SSSD, operations, and audit. |
| [07-kerberos-guide.md](07-kerberos-guide.md) | SPN, keytab, DNS, and Kerberos-first deployment guide. |
| [08-hardening-and-testing.md](08-hardening-and-testing.md) | Sanitizer, strict-warning, fuzzing, protocol regression, load, MAC, systemd, and supply-chain hardening notes. |
| [08-sources.md](08-sources.md) | Sources and documentation links. |
| [09-implementation-issues.md](09-implementation-issues.md) | Current implementation issues with severity and confidence ratings. |
| [09-runbooks.md](09-runbooks.md) | Operator runbooks for AD join, keytab rotation, login troubleshooting, and service diagnostics. |
| [10-configuration-reference.md](10-configuration-reference.md) | Current `frdpd.toml` fields, defaults, and fail-closed unsupported policy. |
| [11-packaging.md](11-packaging.md) | Packaging layout, install paths, systemd/PAM/MAC artifacts, and current DEB/RPM status. |
| [12-readiness-and-test-strategy.md](12-readiness-and-test-strategy.md) | Current readiness assessment, highest-value implementation order, and executable test strategy. |
| [13-threat-model.md](13-threat-model.md) | Draft threat model for FRDP helper topology, trust boundaries, current controls, and validation gates. |

## Main recommendation

Build a separate server stack, not an xrdp fork:

1. **RDP protocol/security layer** - FreeRDP server API (`freerdp_listener`, `freerdp_peer`) with mandatory TLS and NLA support.
2. **Authentication broker** - an isolated component for CredSSP/Kerberos/PAM/SSSD that minimizes password and ticket-material lifetime in memory.
3. **Session manager** - a custom `sesman` equivalent responsible for PAM session lifecycle, `systemd-logind`, cgroups, reconnect, limits, and launching the user desktop backend.
4. **Display/session backend** - MVP on headless Xorg/Xvfb or Xorg dummy, followed later by an optional Wayland/wlroots backend.
5. **Per-user agent** - a user process for graphics, input, clipboard/audio/device channels, and policy enforcement.

`freerdp-shadow-cli` is useful for a quick "publish the current screen" prototype, but it does not satisfy the requirements of a full multi-user xrdp alternative: custom lifecycle, authorization, display allocation, reconnect, and user-session isolation are required.

## Assumptions

- The main target environment is corporate Linux joined to an AD/LDAP/Kerberos realm through SSSD.
- Main clients are Windows `mstsc.exe`, Microsoft Remote Desktop, and FreeRDP/Remmina.
- The "NLA/CredSSP+Krb5" requirement means RDP NLA support where CredSSP runs over TLS and uses SPNEGO/Kerberos or NTLM; the preferred path is Kerberos, while NTLM may be enabled only explicitly and narrowly.
- For the first production version, password verification through PAM/SSSD inside NLA is recommended. Kerberos-only prevalidated logon without password transfer is possible as a separate security-reviewed milestone because the standard PAM stack usually expects a password or another `authtok`.

## Successful MVP criteria

The MVP must provide:

- Windows `mstsc.exe` connection with NLA;
- domain-user login through PAM/SSSD;
- creation of a headless Xorg session;
- reconnect to an existing session;
- text clipboard plus baseline audio output;
- centralized audit in journald/syslog;
- configurable allowlist/blocklist filtering for risky redirection channels;
- reproducible `.deb`/`.rpm` packages and systemd units.

Replacing xrdp feature-for-feature in the first version is not practical: xrdp is mature, widely packaged, and already has a broad set of channels and backends. The point of the new solution is not "another xrdp", but a controlled enterprise RDP daemon with an NLA/Kerberos-first model and modern separation of security, session, and display layers.
