# 12. Readiness assessment and executable test strategy

Assessment date: 2026-06-21.

This assessment covers the implementation in `server/frdp` on the
`project/freerdp-pam-sssd-nla-server` branch. Percentages are engineering
readiness estimates, not code-coverage measurements. A feature is counted as
ready only when its intended runtime path exists, fails closed, and is exercised
by an automated test at the appropriate boundary.

## Executive assessment

The branch is a substantial protocol and lifecycle prototype, but it is not yet
a production RDP service. It has enough implementation to begin real client and
identity-provider testing now. Further large feature work should be gated on
making the current canonical helper topology repeatably green.

| Area | Readiness | Current evidence | Production blocker |
|---|---:|---|---|
| Build integration | 65% | `WITH_FRDPD` builds the listener, helpers, agent, control CLI and focused tests | The branch is far behind and diverged from `master`; package builds and a supported dependency matrix are not green |
| Password-backed NLA and PAM | 60% | Integrated FreeRDP server callbacks, CredSSP identity extraction, PAM auth/account handling, locked temporary secret buffers, auth broker IPC required for normal startup, in-process fallback hidden behind a development build option | Windows client and domain interoperability need repeatable evidence; development fallback builds can still process credentials in the peer worker |
| Privilege-separated topology | 60% | `frdp-authd`, `frdp-sesmand`, per-user agent, Unix sockets, peer credential checks, process hardening, correlation IDs, normal startup requiring both helper sockets, live helper-topology startup smoke coverage, and no default in-process PAM fallback | Authenticated identity is passed as mutable strings without a cryptographically bound, single-use authorization object |
| Session lifecycle | 45% | PAM session ownership, uid/gid drop, Xvfb agent startup, close requests and cleanup exist | No reconnect, durable registry, logind/cgroup ownership, crash reconciliation, atomic display reservation or resource quotas |
| Desktop data path | 35% | Input injection, raw/XDamage tile capture, bounded output scheduling, basic resize and opportunistic NSCodec exist | No production RFX/RDPGFX policy, limited text/IME behavior, no systematic performance or resolution interoperability evidence |
| Virtual channels | 20% | Static-channel filtering and a DVC authorization hook fail closed | No useful clipboard/audio handlers; `drdynvc` is deliberately guard-denied; no runtime channel tests |
| Kerberos-first path | 10% | A build-only GSSAPI helper skeleton and architecture documentation exist | No CredSSP/SPNEGO token transport, configured keytab/SPN validation, SSSD principal mapping, account/session binding or security review |
| Operations and packaging | 25% | Example systemd units, PAM file, configuration, install rules and draft MAC policy files exist | No completed DEB/RPM build, active SELinux/AppArmor validation, upgrade/rollback, socket activation, metrics or operational SLOs |
| Automated verification | 46% | Unit tests, helper-process component tests, live helper-topology startup smoke coverage and Docker Compose profiles for local PAM, Samba AD and FreeIPA are present | Compose profiles must become green and stable; no Windows `mstsc`, reconnect, load, fuzzing, leak or crash-recovery gates yet |
| Overall production readiness | **25–30%** | A testable MVP skeleton with meaningful security boundaries | Several correctness, lifecycle, interoperability and operability gates remain open |

## Highest-value implementation order

### Gate 0 — Establish a trustworthy baseline

Do not add another large subsystem until all of the following are true:

1. The focused CTest suite builds and passes in a clean Ubuntu container.
2. The local Compose profile proves valid NLA/PAM login, denied login, managed
   session creation and cleanup through a real `xfreerdp` client.
3. ASan/UBSan and compiler-warning builds cover `server/frdp` and the IPC tests.
4. The branch is rebased or recreated on a pinned, supported FreeRDP revision;
   the current large divergence from `master` must not be allowed to hide API
   breakage.
5. CI preserves complete build, daemon and client logs on every failure.

### Gate 1 — Make the security architecture canonical

1. Require `frdp-authd` and `frdp-sesmand` for normal server startup.
2. Remove in-process PAM authentication/session ownership from the peer worker,
   or retain it only behind an explicitly insecure development build option.
3. Replace the `auth success -> user string -> session open` handoff with a
   short-lived, single-use authorization object containing canonical uid/gid,
   groups, account decision, correlation ID, remote endpoint and expiry.
4. Bind the session request to the authenticated peer and consume the object
   exactly once in `frdp-sesmand`.
5. Version and serialize IPC explicitly instead of relying on native C struct
   layout and host endianness.
6. Add stale-socket detection that cannot unlink the pathname of a live helper,
   bounded request sizes and per-peer rate limits.

Exit criterion: the peer worker cannot authenticate or open a user session
without both brokers, and replaying or modifying a session request fails.

### Gate 2 — Complete lifecycle correctness

1. Introduce a persistent session state model with explicit states such as
   `AUTHENTICATED`, `STARTING`, `ACTIVE`, `DISCONNECTED`, `STOPPING`, `DEAD`.
2. Reserve display IDs atomically and reconcile X sockets/processes after a
   manager restart.
3. Implement reconnect policy and prove that reconnect attaches to exactly the
   intended session.
4. Use logind/systemd scopes and cgroup limits for process ownership, cleanup,
   CPU, memory and process-count enforcement.
5. Add heartbeat/supervision for the agent and deterministic recovery from
   agent, Xvfb, authd and sesmand crashes.

Exit criterion: kill/restart tests leave no orphan desktop or PAM session and
reconnect behavior is deterministic.

### Gate 3 — Make the desktop useful and bounded

1. Add a measured graphics policy: RFX and/or RDPGFX first, raw bitmap only as a
   bounded fallback.
2. Add frame pacing, back-pressure, dirty-region coalescing and memory limits.
3. Complete keyboard layout, Unicode supplementary-plane and IME-safe input.
4. Implement text clipboard as the first useful channel with strict size,
   direction and policy limits; add baseline audio output only after clipboard
   policy and runtime tests are stable.
5. Test resize, multimonitor negotiation and repeated connect/disconnect under
   real clients.

Exit criterion: a normal desktop workload remains responsive and memory-bounded
for an extended session, and denied channels cannot be opened or used.

### Gate 4 — Enterprise authentication and release engineering

1. Implement the Kerberos acceptor path from the actual CredSSP/SPNEGO token,
   configured SPN/keytab and SSSD-backed principal mapping.
2. Add joined-host FreeIPA with `id_provider=ipa`, keytab validation and explicit
   HBAC; add strict Samba AD GPO policy after the baseline AD profile is stable.
3. Complete DEB and RPM builds, service users/directories, permissions,
   post-install validation and upgrade tests.
4. Validate SELinux and AppArmor policies in enforcing mode.
5. Run an external client matrix including current Windows `mstsc`, at least one
   older supported Windows client and FreeRDP clients from a different build.

Exit criterion: release artifacts install on supported distributions and pass
identity, client and policy matrices without development-only flags.

## Test architecture

### Unit tests

Unit tests should be deterministic, unprivileged and complete in seconds.
They should cover:

- configuration parsing, duplicate keys, length boundaries and fail-closed
  unsupported policy;
- user/domain normalization, PAM conversation behavior and error mapping using a
  testable PAM adapter boundary;
- channel policy exact matching and malformed `CHANNEL_DEF` input;
- IPC encode/decode, versioning, length arithmetic, partial reads/writes,
  endianness and zeroization;
- session-state transitions, reconnect selection and cleanup decisions with
  process/PAM/logind adapters mocked;
- display allocation and collision handling;
- frame rectangle/stride/size validation and scheduler budgets.

Private static functions that contain policy should be moved into small modules
instead of testing them by including daemon implementation files.

### Component tests

Component tests start real binaries while replacing only external systems that
are not the component under test. The focused CTest target now starts real
`frdp-authd` and `frdp-sesmand` processes and sends malformed and valid control
messages. Extend it with:

- a purpose-built PAM test module with deterministic success, account denial,
  session-open failure and audit recording;
- concurrent clients, slowloris payloads and truncated messages;
- peer UID rejection and server peer-credential validation;
- live-socket/stale-socket startup behavior;
- broker crash during auth and manager crash during open/close;
- agent protocol frame/input/resize bounds against Xvfb;
- sanitizer and Valgrind/LSan variants.

### Docker Compose E2E

The Compose harness under `server/frdp/test/e2e` defines four profiles:

- `component`: clean container build plus focused CTest;
- `local`: actual TLS/NLA/CredSSP, local PAM, helper IPC and managed Xvfb
  lifecycle;
- `samba`: provisioned Samba AD DC, machine join via `adcli`, SSSD AD, PAM and
  real RDP client;
- `freeipa`: official FreeIPA server, LDAP identity plus Kerberos password auth
  through SSSD, PAM and real RDP client.

Each RDP profile checks an enabled user, wrong password, disabled/locked account,
full connection, appearance in `frdpctl list-sessions`, and cleanup after client
disconnect. The Samba and FreeIPA profiles are intentionally separate because
they represent different identity and policy behavior, not interchangeable
LDAP fixtures.

The current FreeIPA profile is a reproducible baseline, not final IPA policy
coverage: it does not yet enroll the FRDP host or enforce HBAC through the IPA
provider. The current Samba profile joins the host but keeps GPO access control
permissive until authentication and lifecycle behavior are stable.

### External lab E2E

Some requirements should not be forced into a single Docker host:

- Windows `mstsc` client/build matrix;
- Kerberos-only and ticket-renewal scenarios with real DNS/time behavior;
- joined FreeIPA host, HBAC and keytab rollover;
- AD GPO allow/deny and trust/forest scenarios;
- reconnect across daemon restart;
- clipboard/audio policy and interoperability;
- network loss, packet delay, bandwidth limits and TLS certificate rotation;
- multi-session load, long soak, memory growth and crash recovery.

Publish machine-readable results with server/client versions, provider version,
configuration hash and correlation IDs so failures can be reproduced.

## Required CI gates

| Gate | Trigger | Required now | Target maximum |
|---|---|---:|---:|
| Formatting, compile warnings, unit tests | Every FRDP change | Yes | 10 minutes |
| Container component tests | Every FRDP change | Yes | 20 minutes |
| Local PAM RDP E2E | Every FRDP change | Yes after first stable green | 30 minutes |
| Samba AD E2E | Nightly/manual, then required for auth changes | Yes for release candidates | 45 minutes |
| FreeIPA E2E | Nightly/manual, then required for auth changes | Yes for release candidates | 60 minutes |
| Sanitizers/fuzz corpus | Nightly | Yes before MVP tag | 45 minutes |
| Windows client matrix | External nightly/release | Yes before MVP tag | Lab-defined |
| Soak/load/crash recovery | Scheduled/release | Yes before production claim | Lab-defined |

Flaky identity-provider tests must not be silently retried until green. Preserve
first-failure logs, classify infrastructure versus product failures, and only
then allow one diagnostic retry.

## MVP definition of done

The implementation can be called an MVP only when all statements below are
supported by repeatable evidence:

- mandatory NLA with password-backed PAM/SSSD succeeds and fails correctly;
- auth and session brokers are required and credentials are not retained by the
  listener beyond the authentication exchange;
- an authenticated user receives a usable X desktop with keyboard, mouse,
  resize, bounded graphics updates and text clipboard;
- disconnect cleanup is deterministic and reconnect policy is explicit;
- Samba AD and joined FreeIPA policy profiles pass, including denied accounts;
- current Windows `mstsc` and an independently built FreeRDP client pass;
- package install, restart, upgrade and uninstall leave correct permissions and
  no orphan sessions;
- enforcing MAC profiles, resource limits, audit correlation and documented
  operational recovery are verified.

Until these gates are green, describe the branch as an experimental, testable
server prototype rather than a production-ready Linux RDP service.
