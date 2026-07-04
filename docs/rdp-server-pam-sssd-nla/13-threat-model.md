# 13. Threat model draft

Status: draft for the `server/frdp` PAM/SSSD/NLA prototype.

This model covers the planned FreeRDP-based server stack described in
`02-architecture.md` and the current implementation tracked in
`09-implementation-issues.md`. It is not a completed security review. It is a
working checklist for design, implementation, and test gates.

## Security objectives

- Only authenticated and authorized users can create or reconnect to desktop
  sessions.
- No desktop process, PAM session, display reservation, or agent socket is
  allocated before authentication and static channel policy checks pass.
- Passwords, tokens, key material, and PAM handles have the shortest practical
  lifetime and remain isolated from the network-facing listener where possible.
- Session-open authorization cannot be forged, replayed, or confused across
  users, sessions, remote hosts, or correlation ids.
- Redirection channels are denied by default and cannot bypass configured
  policy.
- Cleanup is deterministic enough that disconnects, helper crashes, and daemon
  restarts do not leave reachable unauthorized sessions or uncontrolled user
  processes.
- Audit events across listener, auth broker, session manager, and agent can be
  correlated for incident response.

## Assets

| Asset | Sensitivity | Notes |
|---|---:|---|
| CredSSP password material and PAM `authtok` | Critical | May exist in FreeRDP/SSPI internals, broker request buffers, PAM-owned memory, and temporary conversation responses. |
| Kerberos keytab, acceptor context, delegated tickets | Critical | Planned Kerberos-first path; current helper is only a skeleton. |
| Signed session-open tokens and HMAC secret | Critical | Authorizes `frdpd -> frdp-sesmand` session creation after auth success. |
| PAM handle/session state | High | Owns account/session policy and cleanup obligations. |
| POSIX uid/gid/group vector | High | Determines privilege drop and session ownership. |
| Agent control socket | High | Root-only channel for input, framebuffer, and resize requests. |
| Display reservation and Xvfb/Xorg runtime files | High | Collision or stale cleanup bugs can cross sessions. |
| TLS private key and runtime config | High | Controls network identity and security policy. |
| Clipboard/audio/device channel data | Medium to High | May exfiltrate corporate or user data. |
| Correlation ids and audit logs | Medium | Required for investigation; may include sensitive names/hosts after escaping. |

## Trust boundaries

1. **Remote RDP client -> `frdpd` listener.** Untrusted network input crosses
   TLS/NLA, capability, channel, graphics, and input parsers.
2. **FreeRDP peer worker -> `frdp-authd`.** The worker sends normalized auth
   data and password material over a local Unix socket.
3. **`frdp-authd` -> PAM/SSSD/NSS/Kerberos.** Local identity policy and
   provider state decide account validity.
4. **`frdpd` -> `frdp-sesmand`.** Session-open requests must be authorized by
   signed, short-lived, single-use tokens and verified POSIX account data.
5. **`frdp-sesmand` root context -> user session child.** UID/GID/groups,
   PAM session ownership, display reservations, and process groups cross the
   privilege boundary.
6. **`frdpd` -> per-session agent control socket.** Root-only IPC carries
   input, framebuffer, resize, and future channel messages.
7. **Agent -> X11/Xvfb and desktop applications.** Input/framebuffer and
   clipboard/audio behaviors can affect or expose the user desktop.
8. **Configuration/package/operator boundary.** Systemd units, PAM service
   files, TLS material, MAC profiles, and reload behavior shape runtime policy.

## Primary threats and controls

| Threat | Current controls | Open work |
|---|---|---|
| Credential theft from peer memory or crash dumps | Non-dumpable hardening, locked temporary password copies, explicit request wiping, auth broker required for normal startup, peer-owned auth identity cleared after auth callback, peer-worker PAM fallback removed | Audit lower-level CredSSP/SSPI/PAM ownership and complete Kerberos credential isolation |
| Forged or replayed session-open IPC | HMAC-signed short-lived V3 token, nonce consumption, uid/gid/group/account-state binding, legacy V1/V2 rejection before body decode | Richer account-policy payload and end-to-end login/reconnect tests |
| Helper socket spoofing or live-socket replacement | Absolute socket path validation, peer credential checks, live-socket collision guard, stale same-owner cleanup checks | Package/user ownership validation across distros and restart reconciliation |
| Pre-auth resource allocation | Normal helper topology opens sessions after auth and static channel policy checks | Real client E2E proof that denied logins and denied channels allocate no desktop resources |
| Channel-based data exfiltration | Static channel filter, guarded `drdynvc`, dynamic policy parser/hook, disabled-by-default clipboard policy parser | Runtime `cliprdr` implementation, DVC transport policy, audio/device handler policy and interoperability tests |
| Agent control abuse | Root peer credential validation, session/correlation id validation, bounded frame metadata, focused non-root rejection/root smoke coverage | Broader Xvfb input/frame tests, agent heartbeat/supervision, richer channel policy profile |
| Display/session collision or stale cleanup | FRDP-owned display reservation files, safe same-inode release policy tests, process-group cleanup | Persistent registry, restart reconciliation, logind/cgroup ownership |
| Parser or wire-format memory corruption | Explicit little-endian IPC codecs, payload size checks, focused fuzzers for config/auth-token/IPC/frame/input/display/session policy | Sustained corpora and broader selected RDP input fuzzing |
| Audit log injection or correlation loss | Correlation ids across auth/session/agent path, escaping for client and IPC supplied fields | Structured audit config and useful channel handler audit events |
| Configuration drift or unsafe reload | Fail-closed parsing for unsupported policy, `frdpctl reload` for session PAM-service reread | Full runtime reload policy for listener sockets, TLS material, channel/clipboard policy, and helper topology |

## Validation gates

Before this threat model can move from draft to reviewed status, the project
needs evidence for:

- successful and denied RDP login through the canonical helper topology with a
  real client;
- denied login and denied channel cases proving no desktop allocation;
- replay, tamper, stale-socket, and helper-crash tests at the IPC boundaries;
- disconnect/reconnect and manager-restart cleanup tests showing no orphan
  PAM session, display reservation, agent socket, or process group;
- text clipboard policy tests with real clients before enabling additional
  redirection channels;
- sanitizer, fuzz, and load/soak artifacts for the focused FRDP surface;
- package install validation for service ownership, socket directories, PAM
  files, TLS permissions, and inactive/enforcing MAC profiles;
- Kerberos/SPNEGO security review before installing or enabling
  `frdp-krb-authd`.

## Out of scope for this draft

- Formal cryptographic proof of the auth token construction.
- Complete Windows client interoperability matrix.
- Production Kerberos-only passwordless design.
- Device redirection beyond denied-by-default policy.
- Multi-tenant hosting and hostile local-root assumptions.
