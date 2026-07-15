# 12. Readiness assessment and executable test strategy

Assessment date: 2026-07-13.

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
| Build integration | 65% | `WITH_FRDPD` builds the listener, helpers, agent, control CLI and focused tests; the generated installed sample follows the default-on or explicit-off NTLM build contract | The branch is far behind and diverged from `master`; package builds and a supported dependency matrix are not green |
| Password-backed NLA and PAM | 85% | Integrated FreeRDP server callbacks, build-time optional (default-on) NTLM proof verification through a protected WinPR SAM, fail-closed proof binding to the configured PAM-normalized identity across equivalent split/down-level/UPN forms with malformed, embedded-data and ambiguous rejection tests; the proof may add a domain omitted by matching delegated FreeRDP password credentials, while any delegated domain remains mandatory and equal in the proof. Proof binding extracts only user/domain without duplicating the delegated password, mandatory PAM auth/account handling follows through the auth broker, and post-account `PAM_USER` plus canonical NSS/SSSD `pw_name` bind auth-response V2, groups, token and managed-session handoff. Independent bounded account/source failure budgets, focused normalization/conversation/lifecycle coverage, locked temporary secrets, immediate credential-staging cleanup, required auth broker IPC, and green real-client local-PAM, Samba AD/SSSD, and joined FreeIPA/SSSD profiles cover accepted/wrong/disabled-or-policy-denied logins with exact fresh server-side outcomes. FreeIPA additionally proves OTP host enrollment, a root-only host keytab, IPA identity/auth/access providers with Kerberos validation, and explicit HBAC allow/deny behavior; managed graphical sessions and AD supplementary-group membership through NSS/SSSD are also covered | Failure budgets are process-local and a previously unseen alias can still reach PAM once; SAM provisioning remains a separate password-equivalent secret store; mapping different NetBIOS and DNS/UPN domain names and Unicode-aware case folding still require explicit trusted policy; remaining SSPI/PAM-owned credential lifetime, Windows `mstsc`, Kerberos-first CredSSP, IPA keytab rollover, distributed abuse prevention, and broader domain-policy interoperability evidence remain absent |
| Privilege-separated topology | 78% | `frdp-authd`, `frdp-sesmand`, per-user agent, Unix sockets, peer credential checks including root-gated live cross-UID rejection and post-rejection helper survival for both helper roles, process hardening, correlation IDs, role-bound bounded startup health checks, fail-closed helper outages, restart-on-failure unit policy, direct crash/restart coverage, root-gated transient-systemd `SIGKILL`/same-socket recovery for both helper roles, signed single-use session-open auth tokens bound to POSIX uid/gid/bounded supplementary groups/account state, fixed-window per-peer helper IPC rate limits, live-helper socket collision protection, explicit auth broker, session control responses, and no in-process PAM fallback | Installed distro-unit crash/restart with active sessions, prolonged outage policy, legacy V1/V2 compatibility IDs, and richer account-policy payload remain open |
| Session lifecycle | 72% | PAM session ownership, covered identity drop, Xvfb agent startup, shared PID/start-time/effective-UID identity reads, versioned atomic session metadata committed before lifecycle responses, durable detach/reconnect state updates, inode-bound agent-socket/display-reservation cleanup, bounded agent heartbeat supervision, provider-backed manager crashes inside PAM open/close with bounded clients and restart reconciliation, a live stopped-agent cleanup gate, a live `SIGKILL`/same-runtime restart cleanup gate, and real `xfreerdp` local-PAM plus Samba AD/SSSD reconnect with stable session id/display/agent PID now exist | Restart intentionally cleans rather than restores sessions; the replacement process cannot close the lost PAM handle, and direct authd supervision, logind/cgroup ownership, full PAM reconciliation, production quota management, reconnect across restart, and Windows-client evidence remain absent |
| Desktop data path | 35% | Input injection, raw/XDamage capture, bounded output scheduling, policy-gated Display Control transport, conversion/bounds and agent IPC coverage, a real-client `800x600` layout request, forced framebuffer capture smoke, and opportunistic NSCodec exist | Fixed-mode Xvfb cannot apply geometry changes; no production RFX/RDPGFX policy, alternate resizable backend, systematic performance, or resize-churn evidence exists |
| Virtual channels | 55% | Static/dynamic filtering, pre-create DVC authorization, conditional `drdynvc` transport, a Display Control handler, policy-gated text-only `cliprdr`, bounded explicit clipboard IPC/X11 selection handling, focused tests, and live-client Display Control plus bidirectional Unicode clipboard evidence exist | No audio, file/image clipboard, device redirection or broader live-client channel matrix |
| Kerberos-first path | 19% | A build-only GSSAPI helper skeleton, standalone no-core hardening, keytab environment selection, host-based acceptor-name import, delegated-credential flag rejection, base64 token decoding, fail-closed simple principal normalization and bounded group lookup coverage, Kerberos identity config validation with daemon fail-closed startup for enabled Kerberos mode, and architecture documentation exist | No CredSSP/SPNEGO token transport from `frdpd`, SSSD enterprise principal mapping, account/session binding or integrated security review |
| Operations and packaging | 34% | Example systemd units, PAM file, configuration, install rules, draft MAC policy files with SELinux module/package and AppArmor parser validation when available, starter node_exporter/Prometheus/Grafana monitoring examples with focused validation, including session utilization export for capacity alerts, Debian and RPM preview package smoke evidence, and package signing/reproducible-build notes exist | No dependency-checked target-distro RPM CI, release signing repository, active SELinux/AppArmor enforcement review, upgrade/rollback, socket activation, dashboard import evidence, native metrics or operational SLOs |
| Automated verification | 85% | Unit tests, helper-process component tests, live helper-topology startup smoke coverage, prerequisite-gated Xvfb/PAM live V3 open/list/detach/implicit-reconnect/hard-close plus sesmand `SIGKILL`/restart reconciliation coverage, metadata codec/store and same-inode recovery tests, malformed/slow helper-client coverage, focused ASan+UBSan and strict-warning gates including default-on/explicit-off NTLM build variants, systemd/tmpfiles/monitoring verification, ASan/UBSan-backed parser/policy fuzzers, and green real-client local-PAM, Samba AD/SSSD, and joined FreeIPA/HBAC Compose profiles proving disconnect/reconnect identity with retained-client logs/listings/XWD artifacts. Weekly Samba and FreeIPA jobs request two clean harness repetitions with per-attempt artifacts | Successful repeated provider CI history still needs to accumulate; no Windows `mstsc`, IPA keytab rollover, reconnect across restart, full PAM crash reconciliation, graphical session load/soak, sustained fuzz corpus, broader selected RDP input fuzzing, full-session protocol regression, or Valgrind/LSan variant matrix yet |
| Overall production readiness | **25–30%** | A testable MVP skeleton with meaningful security boundaries | Several correctness, lifecycle, interoperability and operability gates remain open |

## Highest-value implementation order

### Gate 0 — Establish a trustworthy baseline

Do not add another large subsystem until all of the following are true:

1. The focused CTest suite builds and passes in a clean Ubuntu container.
2. The local Compose profile proves valid NLA/PAM login, denied login, managed
   session creation and cleanup through a real `xfreerdp` client.
3. Keep strict-warning coverage green for the focused `server/frdp` build/test
   surface.
4. The branch is rebased or recreated on a pinned, supported FreeRDP revision;
   the current large divergence from `master` must not be allowed to hide API
   breakage.
5. Keep CI log artifacts complete enough to diagnose build, daemon and client
   failures without rerunning the profile.

### Gate 1 — Make the security architecture canonical

1. Require `frdp-authd` and `frdp-sesmand` for normal server startup.
2. Keep in-process PAM authentication/session ownership out of the peer worker.
3. Replace the `auth success -> user string -> session open` handoff with a
   short-lived, single-use authorization object containing canonical uid/gid,
   groups, account decision, correlation ID, remote endpoint and expiry.
4. Bind the session request to the authenticated peer and consume the object
   exactly once in `frdp-sesmand`.
5. Version and serialize IPC explicitly instead of relying on native C struct
   layout and host endianness.
6. Add stale-socket detection that cannot unlink the pathname of a live helper,
   bounded request sizes and per-peer rate limits. The live-helper socket
   collision guard exists for current helper listener startup, auth/session
   helper IPC now rejects oversized request payloads, and auth/session helpers
   enforce a fixed-window per-peer UID request limit.

Current status: the normal password-backed helper path now uses an HMAC-signed,
short-lived V3 session-open token bound to user, remote host, correlation id,
POSIX uid/gid, bounded supplementary groups, account-present state, nonce and
expiry; `frdp-sesmand` rejects legacy V1/V2 session-open requests before body decode, rejects
mismatched group payloads, and consumes accepted token nonces once. The common
IPC header, auth broker request/response payloads including canonical-user auth-response V2, canonical V3 session-open
handoff payloads, session close requests, shared session responses, session
list/reload responses, and agent input/frame/resize metadata now use explicit
little-endian/fixed-field wire formats, while richer account-policy payloads
remain open. Session list/reload requests are header-only control messages,
legacy V1/V2 open message IDs remain unsupported compatibility residue, and
frame pixel bytes remain a bounded raw tail after explicit agent frame metadata.

Exit criterion: the peer worker cannot authenticate or open a user session
without both brokers, and replaying or modifying a session request fails.

### Gate 2 — Complete lifecycle correctness

1. Introduce a persistent session state model with explicit states such as
   `AUTHENTICATED`, `STARTING`, `ACTIVE`, `DISCONNECTED`, `STOPPING`, `DEAD`.
2. Persist display ID reservations and reconcile FRDP/X display state after a
   manager restart.
3. Implement reconnect policy and prove that reconnect attaches to exactly the
   intended session.
4. Use logind/systemd scopes and cgroup limits for process ownership, cleanup,
   CPU, memory and process-count enforcement.
5. Complete helper supervision and deterministic crash recovery. Agent
   nonce-echo heartbeat on a private responder thread gated by a 10-second
   main-loop progress watchdog, with absolute deadlines, due-aware one-probe
   round-robin scheduling, and consecutive-failure cleanup is
   implemented, Xvfb exit is observed through the agent lifecycle, and
   sesmand restart reconciliation is covered. Role-bound helper health,
   fail-closed outages, restart-on-failure units, and authd same-socket crash
   recovery are covered. Lost PAM-handle reconciliation and logind/cgroup
   ownership remain open.

Exit criterion: kill/restart tests leave no orphan desktop or PAM session and
reconnect behavior is deterministic.

### Gate 3 — Make the desktop useful and bounded

1. Add a measured graphics policy: RFX and/or RDPGFX first, raw bitmap only as a
   bounded fallback.
2. Add frame pacing, back-pressure, dirty-region coalescing and memory limits.
3. Complete keyboard layout, Unicode supplementary-plane and IME-safe input.
4. Keep the implemented text-only clipboard channel bounded by explicit size,
   direction and policy limits, and add baseline audio output after clipboard
   runtime tests are stable across the wider client matrix.
5. Test resize, multimonitor negotiation and repeated connect/disconnect under
   real clients.

Exit criterion: a normal desktop workload remains responsive and memory-bounded
for an extended session, and denied channels cannot be opened or used.

### Gate 4 — Enterprise authentication and release engineering

1. Implement the Kerberos acceptor path from the actual CredSSP/SPNEGO token,
   configured SPN/keytab and SSSD-backed principal mapping.
2. Add FreeIPA keytab rollover and broader topology/policy scenarios; add strict
   Samba AD GPO policy after the baseline AD profile is stable.
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
- user/domain normalization, PAM status mapping, PAM conversation behavior, and
  deterministic PAM auth/account/session lifecycle branches now have focused
  CTest coverage through a testable PAM adapter boundary; real provider-module
  coverage remains open;
- channel policy exact matching and malformed `CHANNEL_DEF` input;
- IPC encode/decode, versioning, length arithmetic, partial reads/writes,
  endianness and zeroization;
- WinPR SAM entry reset, strict LM/NT hash syntax, repeatable full-store
  validation, startup rejection of empty/comments-only/malformed stores, and
  repeated lookup recovery after a malformed partially parsed entry;
- RC4 compatibility under both the normal OpenSSL provider and the compiled-in
  WinPR backend, with sanitizer coverage for the release paths;
- agent input event type, flag and parameter bounds before XTest injection;
- in-memory session-state transition, cleanup-decision, disconnect-rollback and tri-state
  reconnect-selection policy have focused CTest coverage, normal disconnect
  detaches to a disconnected in-memory session, authorized explicit session-id
  requests can attach back to it, and an empty-session-id login implicitly
  selects the newest unambiguous disconnected session for the authenticated
  user/UID identity before creating a new one; the prerequisite-gated live
  helper test covers open/list/detach/implicit reattach/hard-close and cleanup
  with stable session metadata; local-PAM, Samba AD/SSSD, and the FreeIPA
  baseline Compose profiles now repeat the detach/reattach path with two real
  `xfreerdp` clients and
  require one stable session id/display/agent PID, while reconnect across
  restart and logind/cgroup cleanup adapters remain open;
- display reservation path bounds, collision handling and safe same-inode cleanup;
- frame rectangle/stride/size validation and scheduler budgets.

Private static functions that contain policy should be moved into small modules
instead of testing them by including daemon implementation files.

### Component tests

Component tests start real binaries while replacing only external systems that
are not the component under test. The focused CTest target now starts real
`frdp-authd` and `frdp-sesmand` processes, sends malformed and valid control
messages, and covers truncated header/body clients that close the connection.
With the optional `libpam-wrapper` test dependency present, the focused test
also starts the real `frdp-authd` against isolated `pam_set_items` and
`pam_matrix` stacks. It proves password conversation, post-account `PAM_USER`
canonicalization into the NSS identity and authorization response, account
denial, canonical failure-budget sharing across two aliases with pre-PAM
blocking after the aggregate threshold, and separate fail-closed classification
of unavailable PAM identity infrastructure. A test-only PAM module additionally records the real
`frdp-sesmand` account/credential/session phase trace, rejects
`pam_open_session`, and proves the failed signed V3 open leaves no session,
agent socket, display reservation, or durable metadata. The same module can
block inside `pam_authenticate()` after recording entry; killing the real
`frdp-authd` then proves the waiting auth client receives a bounded IPC
failure. A separately compiled blocking session module does the same for a
real `frdp-sesmand` killed inside `pam_open_session()` and proves no desktop or
durable session resources were allocated before that point. A close-blocking
variant opens a real Xvfb-backed session, kills the manager inside
`pam_close_session()`, and proves restart reconciliation removes the durable
`STOPPING` state and remaining runtime artifacts. Extend it with:

The provider-backed case is omitted from AddressSanitizer builds because
`pam_wrapper` loads libpam with `RTLD_DEEPBIND`, which ASan rejects; the rest of
the focused FRDP suite remains covered by ASan/UBSan.

- additional concurrent clients and slowloris timeout variants; broader truncated-message boundary variants are now covered for implemented auth/session/list/reload IPC control families;
- peer UID rejection now has a root-gated live component test for both auth and session helpers; non-root CTest runs skip that branch, so privileged CI execution remains required to retain this evidence;
- live-socket/stale-socket startup behavior;
- broker crash during in-flight PAM authentication and manager crashes during in-flight PAM session open/close have deterministic component coverage; a root-gated transient-systemd test proves both helper roles restart after `SIGKILL` with a replacement socket and valid role health, while installed distro-unit execution with active sessions remains a deployment-level gate;
- agent protocol input runtime behavior against Xvfb beyond focused input-policy coverage, plus broader frame behavior beyond the root-run forced tile capture smoke;
- SELinux module/package validation, AppArmor parser validation and tmpfiles rule parsing are now covered when the host tools are available; sanitizer and Valgrind/LSan variants remain open.

### Docker Compose E2E

The Compose harness under `server/frdp/test/e2e` defines four profiles:

- `component`: clean container build plus focused CTest;
- `local`: actual TLS/NLA/CredSSP, local PAM, helper IPC and managed Xvfb
  lifecycle;
- `samba`: provisioned Samba AD DC, machine join via `adcli`, SSSD AD, PAM and
  real RDP client;
- `freeipa`: official FreeIPA server, OTP host enrollment, root-only keytab,
  `sssd-ipa`, explicit HBAC allow/deny policy, PAM and real RDP client.

Focused CTest coverage now syntax-checks the harness shell scripts, verifies
the expected Compose profiles/services and fixture files remain present, and
uses a Docker-free runner fixture to enforce single-run layout, repeated
fail-fast behavior and incomplete-attempt preservation.

Each RDP profile starts with fresh profile containers, volumes, and artifacts,
checks an enabled user,
cleans its successful auth-only session, and proves that wrong-password and
disabled/locked-account or HBAC-policy attempts leave no managed session or durable session
runtime artifact. A successful profile also requires the current server log to
contain exactly three PAM accepts, one wrong-password NTLM MIC rejection before
PAM, two named denied-user PAM/SSSD outcomes from that probe's connection
path, and no NTLM proof/delegated-identity mismatch. It then checks a full connection, appearance
in `frdpctl list-sessions`, reconnect identity, and final cleanup. The Samba and
FreeIPA profiles are intentionally separate because
they represent different identity and policy behavior, not interchangeable
LDAP fixtures.

`FRDP_E2E_REPETITIONS` repeats every selected profile from clean Compose
volumes, stops at the first failed attempt, and retains each run in a separate
artifact directory. Scheduled Samba and FreeIPA workflow jobs set it to two,
while manual provider dispatches remain single-run by default. Two consecutive
local-PAM real-client lifecycle runs have passed through this mode; configured
repetition is not a substitute for accumulated successful CI history or
long-running graphical load evidence.

The FreeIPA profile enrolls the FRDP host, validates its root-only host keytab,
uses the IPA providers with Kerberos validation, disables the default
`allow_all` HBAC rule, and proves an explicit allow plus enabled-user denial.
Keytab rollover and broader IPA topology/policy cases remain external matrix
work. The Samba profile joins the host but keeps GPO access control permissive
until authentication and lifecycle behavior are stable.

### External lab E2E

Some requirements should not be forced into a single Docker host:

- Windows `mstsc` client/build matrix;
- Kerberos-only and ticket-renewal scenarios with real DNS/time behavior;
- FreeIPA keytab rollover and broader topology/policy scenarios;
- AD GPO allow/deny and trust/forest scenarios;
- reconnect across daemon restart;
- clipboard interoperability beyond the current FreeRDP client and baseline audio policy;
- network loss, packet delay, bandwidth limits and TLS certificate rotation;
- multi-session load, long soak, memory growth and crash recovery.
  A small retained-client auth-only load probe exists at
  `server/frdp/test/e2e/scripts/rdp-load-probe.sh`; it does not replace
  graphical session load, soak, memory-growth or crash-recovery testing.

Publish machine-readable results with server/client versions, provider version,
configuration hash and correlation IDs so failures can be reproduced.

## Required CI gates

| Gate | Trigger | Required now | Target maximum |
|---|---|---:|---:|
| Formatting, compile warnings, unit tests, default-on/explicit-off NTLM build contract | Every FRDP change | Yes | 10 minutes |
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
