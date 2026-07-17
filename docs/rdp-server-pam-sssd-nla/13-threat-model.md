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
| Agent heartbeat channel | High | Private inherited session-manager/agent `SOCK_SEQPACKET` socketpair, not exposed in the runtime directory. |
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
| Credential theft from peer memory or crash dumps | Non-dumpable hardening, locked temporary password copies, explicit request wiping, auth broker required for normal startup, protected/pinned and fully validated SAM input, plaintext/decrypted CredSSP `TSCredentials`, received `authInfo`, the settings password duplicate, parsed SAM/hash buffers, NTLM message fields, and inline NTLM keys wiped immediately after use, peer-owned auth identity cleared after auth callback, peer-worker PAM fallback removed | Audit remaining non-NTLM SSPI/PAM ownership and complete Kerberos credential isolation |
| Substitution between the NLA proof identity and delegated password credentials | Bounded comparison against the configured PAM-normalized identity, with ASCII-case-insensitive equivalent split/down-level/UPN syntax accepted; the authenticated proof may add a domain omitted by delegated FreeRDP password credentials, but a delegated domain remains mandatory in the proof and must match; embedded data, explicit-domain separators, empty, mixed, repeated, unterminated, or differently named retained domains fail closed | Add Unicode-aware case folding and explicit trusted NetBIOS-to-DNS domain mapping only with reviewed configuration and Windows-client interoperability evidence |
| Password spraying or credential stuffing through NLA | `frdp-authd` independently limits credential/account denials by NSS/SSSD-canonical account (ASCII case-fold fallback for unresolved names) and remote source before PAM using bounded 10-denial/120-second process-local tables; infrastructure errors fail closed without poisoning budgets, capacity exhaustion fails closed, successful auth clears only the account budget, and unit/deterministic live-helper tests cover enforcement | Add Unicode-aware fallback canonicalization, make limits configurable under reviewed bounds, add shared/distributed enforcement and retained metrics, and validate behavior across NAT/proxy topologies |
| Forged or replayed session-open IPC | HMAC-signed short-lived V3 token, nonce consumption, uid/gid/group/account-state binding, legacy V1/V2 rejection before body decode | Richer account-policy payload and end-to-end login/reconnect tests |
| Helper socket spoofing, replacement, slow-drip, flood, or outage | Absolute socket path validation, peer credential checks, live-socket collision guard, stale same-owner cleanup checks, role-bound health responses with an absolute exchange deadline and separate rate budget, fail-closed runtime requests, restart-on-failure units, live authd same-path recovery test | Package/user ownership validation and actual systemd recovery runs across distros |
| Pre-auth resource allocation | Normal helper topology opens sessions after auth and static channel policy checks | Real client E2E proof that denied logins and denied channels allocate no desktop resources |
| Channel-based data exfiltration | Static channel filter, policy-gated `drdynvc`, exact Display Control DVC authorization, disabled-by-default clipboard policy parser | Runtime `cliprdr`, audio/device handler policy, other useful DVC handlers and broader interoperability tests |
| Agent control or supervision abuse | Root peer credential validation on the data socket, strict session id and non-empty rotating correlation id validation, bounded frame metadata, private inherited heartbeat socketpair, atomic main-loop progress watchdog, nonce echo with absolute deadlines and consecutive-failure cleanup, focused non-root rejection and root live resize/frame/input/clipboard coverage | Direct authd supervision, richer channel policy profile, broader client/load evidence |
| Display backend executable/config replacement | Xorg dummy requires explicit absolute root-owned single-link regular files, rejects symlinks and group/world-writable components across the complete path, validates before startup/reload and again in the user agent immediately before launch, disables TCP, and snapshots policy into future session children; Xvfb is selected by name without a configurable executable path | Package-installed enforcing MAC validation and immutable/package-verification policy remain deployment work |
| Local X11 display access | Every backend receives a random per-session MIT-MAGIC-COOKIE-1 through an unlinked `0600` authority inode, exposes no reusable pathname, and disables TCP; root-live coverage proves that the session can connect with the retained authority descriptor while another local UID without the cookie is rejected | Processes in the same Unix UID trust domain and privileged local processes remain able to inspect or control that user's session |
| Display/session collision or stale cleanup | FRDP-owned display reservations, versioned atomic metadata with V2 scope ownership, V3 PAM ownership and V1 compatibility, provisional pre-fork artifact ownership, pidfd-pinned PID/start-time/effective-UID plus PGID verification for non-scoped sessions, pidfd-directed leader stop while signaling a group, inode-bound socket/reservation cleanup, receipt-backed orphan socket cleanup, global PID/start-time reservation reconciliation, fail-closed malformed state, per-session PAM owners with synchronized close receipts and live/uncertain endpoint rejection, a live sesmand `SIGKILL`/restart reconciliation gate, optional fail-closed transient systemd scopes, and alternative explicit login1 registration whose FIFO is retained by the PAM owner across manager failure | Restart cleans rather than restores sessions; installed/provider login1 crash evidence plus individual runtime quota policy remain required, and an indefinitely blocked PAM close intentionally blocks reconciliation rather than claiming cleanup |
| Parser or wire-format memory corruption | Explicit little-endian IPC codecs, payload size checks, focused fuzzers for config/auth-token/IPC/frame/input/display/session policy | Sustained corpora and broader selected RDP input fuzzing |
| Audit log injection or correlation loss | Correlation ids across auth/session/agent path, escaping for client and IPC supplied fields | Structured audit config and useful channel handler audit events |
| Configuration drift or unsafe reload | Fail-closed parsing for unsupported policy, `frdpctl reload` for session PAM-service reread, and atomic `frdpd` `SIGHUP` publication of config-sourced peer admission plus channel/clipboard policy with CLI override priority, existing-peer retention, and last-valid retention on parse failure | Runtime reload policy for listener sockets, TLS material, authentication/NTLM state, helper topology, and other non-policy fields |

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
