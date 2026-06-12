# 05. System requirements

## Supported operating systems

Minimum production target:

- Debian 12/13 or Ubuntu Server 24.04 LTS/26.04 LTS;
- RHEL 9/10 compatible distributions;
- systemd, journald, logind;
- PAM, SSSD, MIT Kerberos or Heimdal according to the build matrix;
- SELinux or AppArmor profile.

Fedora, Arch, openSUSE Tumbleweed, and containerized lab environments are acceptable for development, but the production baseline should be limited to a small set of LTS platforms.

## Build requirements

- CMake/Ninja.
- A C compiler supporting the standard required by the current FreeRDP version.
- FreeRDP 3.x source tree, including server components.
- OpenSSL.
- PAM development headers.
- Kerberos/GSSAPI development headers.
- SSSD client/NSS/PAM packages.
- systemd development headers for logind/cgroup integration.
- Optional: FFmpeg/GStreamer/OpenH264 for codec experiments.

## Runtime packages

- `sssd`, `sssd-ad`, `sssd-ldap`, `sssd-krb5` according to the selected profile;
- `krb5-user` or equivalent;
- `xorg`, `xserver-xorg-core`, `xvfb`, or `xserver-xorg-video-dummy` for the MVP;
- desktop environment: XFCE/MATE as a lightweight baseline;
- PulseAudio or PipeWire according to the selected audio model;
- `auditd` for security events;
- `logrotate` or a journald retention policy.

## Network

- TCP 3389 or an alternate port behind a gateway/load balancer.
- DNS forward/reverse resolution for Kerberos SPNs.
- Access to AD DC/KDC/LDAP/Global Catalog.
- NTP/chrony: clock skew must match Kerberos policy.
- TLS certificate chain trusted by clients.

## Active Directory / Kerberos prerequisites

- Host joined to the domain or service account with SPNs.
- SPNs `TERMSRV/host` and `TERMSRV/fqdn`.
- Keytab with current keys.
- SSSD domain configuration and access provider rules.
- Test groups: `linux-rdp-users`, `linux-rdp-admins`, `linux-rdp-deny`.

## Hardware sizing

| Profile | CPU | RAM | Notes |
|---|---:|---:|---|
| Lab 1-5 users | 2-4 vCPU | 4-8 GB | XFCE, no video-heavy workload |
| Pilot 25 users | 8-16 vCPU | 32-64 GB | monitor encode latency and memory per session |
| Production 100 users | 32+ vCPU | 128+ GB | requires load testing, channel restrictions, codec tuning |

Sizing strongly depends on the desktop environment, browser use, codec mode, monitor resolution, and drive/audio redirection.

## Security baseline

- Mandatory NLA.
- TLS 1.2+; preferably TLS 1.3 where the FreeRDP/OpenSSL path supports it.
- Disable legacy RDP security.
- Prefer Kerberos, disable NTLM by default.
- Dedicated PAM service `frdpd`.
- Authentication broker with no core dumps and no password logs.
- Keytab readable only by root or the authd user.
- systemd hardening for daemons.
- Channel allowlists by group.
- Audit logs for every auth/session/channel decision.

## Operational requirements

- CI build matrix for supported distributions.
- Automated Windows client interoperability lab.
- Fuzzing for RDP parsers/channel parsers.
- Load-test profile for concurrent users.
- Release process with signed packages and rollback instructions.
