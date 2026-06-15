# AI Context Guide for `server/frdp/frdpd`

## Product Direction

This area is for a Linux RDP server built on the FreeRDP server-side API, not an xrdp fork. The target product is an enterprise RDP daemon with mandatory NLA/CredSSP, Kerberos-first authentication, PAM/SSSD as the account and session policy boundary, managed per-user desktop sessions, and deny-by-default channel policy.

Keep changes aligned with the in-tree FreeRDP server architecture. Avoid introducing parallel daemon paths, duplicated protocol stacks, or xrdp-specific assumptions unless a task explicitly requires that.

## Target Architecture

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

## Reference Material

- `docs/rdp-server-pam-sssd-nla/02-architecture.md` - intended component architecture and IPC model.
- `docs/rdp-server-pam-sssd-nla/03-authentication-pam-sssd-nla-krb5.md` - security goals and auth flows.
- `docs/rdp-server-pam-sssd-nla/05-system-requirements.md` - target system, domain, and client assumptions.
- `docs/rdp-server-pam-sssd-nla/08-hardening-and-testing.md` - hardening and test strategy.

Use status-oriented documents such as implementation plans, issue lists, and READMEs only as evidence for the specific task at hand. Do not treat draft documentation, standalone examples, or unverified prototypes as completed product behavior.

## Verification

Prefer out-of-tree builds and verify the narrowest relevant target first:

```bash
cmake -S . -B /tmp/opencode/freerdp-build -DWITH_SERVER=ON
cmake --build /tmp/opencode/freerdp-build --target <target> -j2
```

For broader verification, build the configured tree and run relevant tests or smoke checks:

```bash
cmake --build /tmp/opencode/freerdp-build -j2
ctest --test-dir /tmp/opencode/freerdp-build --output-on-failure
```

If a task changes authentication, sessions, privilege transitions, IPC, channel policy, or packaging, include a verification step that exercises that boundary. If a meaningful runtime check is not possible in the current environment, state the exact gap.

## Development Guidance

- Keep privilege boundaries explicit: listener, auth broker, session manager, and user agent must not casually share credential, PAM, or process ownership.
- Define lifecycle ownership before adding state: PAM handles, credentials, child processes, process groups, sockets, memfds, display numbers, runtime directories, and cleanup hooks.
- Fail closed on ambiguous user/domain/principal mapping.
- Keep documentation honest: distinguish design intent, draft material, prototype code, tested behavior, and integrated behavior.
- Do not mark roadmap items complete because a code sample or standalone helper exists; completion requires the task's stated integration and verification criteria.
- Keep changes small, buildable, and aligned with existing FreeRDP style.
