# AI Context Guide for `server/frdpd`

## Project Intent

This project is intended to become a Linux RDP server built on the FreeRDP server-side API, not an xrdp fork. The target product is an enterprise RDP daemon with mandatory NLA/CredSSP, Kerberos-first authentication, PAM/SSSD as the account and session policy boundary, managed per-user desktop sessions, and deny-by-default channel policy.

`server/frdpd` is the canonical in-tree implementation path. Treat root-level `/frdpd`, `/frdp-authd`, `/frdp-sesmand`, and `/frdp-session-agent` as exploratory prototypes until they are integrated into CMake and the daemon topology.

## Intended Architecture

```text
RDP client
  -> frdpd listener
      -> FreeRDP peer worker
          -> frdp-authd
              -> CredSSP / SPNEGO / Kerberos / NTLM policy
              -> PAM service frdpd
              -> SSSD / NSS / Kerberos
          -> frdp-sesmand
              -> PAM session / logind / cgroups / reconnect
              -> frdp-session-agent
                  -> Xorg / Xvfb / future Wayland backend
                  -> framebuffer, input, encoders, channels
```

## Component Roles

- `frdpd` owns TCP/systemd-socket accept, FreeRDP peer creation, TLS/NLA policy, client capability discovery, correlation ids, rate limiting, and worker dispatch.
- `frdp-authd` owns sensitive authentication state, Kerberos acceptor work, PAM auth/account checks, NSS/SSSD lookup, principal normalization, and `AuthResult` generation.
- `frdp-sesmand` owns session registry, reconnect decisions, PAM session lifecycle, logind/cgroup integration, runtime directories, resource limits, and cleanup.
- `frdp-session-agent` runs as the target user and owns desktop backend startup, framebuffer capture, input dispatch, encoders, clipboard/audio/display-resize handling, and channel policy enforcement.

## Security Invariants

- No desktop resources before authentication succeeds.
- PAM/SSSD is the authoritative account/session policy boundary.
- NLA/CredSSP is not an arbitrary PAM prompt transport; keep PAM flows non-interactive unless a separate UX is explicitly designed.
- Passwords, tickets, and keytab-derived material must not enter logs, argv, core dumps, crash reports, or long-lived storage.
- Prefer Kerberos; allow NTLM only behind an explicit compatibility flag.
- Deny redirection channels by default; enable clipboard, audio, drive, printer, smartcard, USB, microphone, and camera only by policy.
- Every login/session/channel decision should carry a correlation id through logs and IPC.

## Current Implementation Boundary

- The CMake-integrated target is `server/frdpd`.
- `server/frdpd` currently contains the buildable FreeRDP listener/auth prototype, password-backed CredSSP-to-PAM adapter, username normalization, PAM authentication/account checks, and PAM session lifecycle.
- Separate authd/sesmand/session-agent IPC, reconnect, logind/cgroups, headless desktop startup, framebuffer capture, input routing, channel policy, and Kerberos-first production flow are roadmap items, not completed integrated behavior.
- Do not mark roadmap items complete because a standalone prototype exists outside the build.

## Critical Files

- `server/frdpd/frdpd.c` - FreeRDP listener, peer lifecycle, security settings, CLI options.
- `server/frdpd/frdpd_auth.c`, `server/frdpd/frdpd_auth.h` - FreeRDP identity to PAM request adapter.
- `server/frdpd/frdpd_pam.c`, `server/frdpd/frdpd_pam.h` - PAM auth/account/session helper and secret clearing.
- `server/frdpd/frdpd.h` - server and peer context structures.
- `server/frdpd/CMakeLists.txt` - canonical build integration.

## Read First

- `docs/rdp-server-pam-sssd-nla/02-architecture.md` - intended component architecture and IPC model.
- `docs/rdp-server-pam-sssd-nla/03-authentication-pam-sssd-nla-krb5.md` - security goals and auth flows.
- `docs/rdp-server-pam-sssd-nla/06-implementation-plan.md` - checked/unchecked roadmap status.
- `docs/rdp-server-pam-sssd-nla/09-implementation-issues.md` - known implementation issues with severity and confidence.
- `server/frdpd/README.md` - current executable behavior and smoke-test usage.

## Build Check

Use an out-of-tree build:

```bash
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF
cmake --build /tmp/opencode/freerdp-current-build --target frdpd -j2
```

For broad verification:

```bash
cmake --build /tmp/opencode/freerdp-current-build -j2
```

## Development Guidance

- Extend the canonical `server/frdpd` path unless the task is explicitly to integrate or retire standalone prototypes.
- Keep privilege boundaries explicit: listener, auth broker, session manager, and user agent must not casually share credential, PAM, or process ownership.
- Define lifecycle ownership before adding state: PAM handles, credentials, child processes, process groups, sockets, memfds, display numbers, runtime directories, and cleanup hooks.
- Fail closed on ambiguous user/domain/principal mapping.
- Keep changes small, buildable, and aligned with existing FreeRDP style.
