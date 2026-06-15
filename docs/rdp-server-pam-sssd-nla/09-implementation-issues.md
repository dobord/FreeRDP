# 09. Implementation issues

Analysis date: 2026-06-15.

Build and syntax checks used for this pass:

```bash
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF
cmake --build /tmp/opencode/freerdp-current-build --target frdpd -j2
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-authd/frdp-authd.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-sesmand/frdp-sesmand.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-session-agent/frdp-session-agent.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-krb-authd/frdp-krb-authd.c
cc -fsyntax-only -Wall -Wextra tools/frdpctl/frdpctl.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-authd/frdp-authd.c server/frdp/ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra server/frdp/config/frdp-config.c server/frdp/frdpd/frdpd-ipc-demo.c server/frdp/ipc/frdp-ipc.c
```

The integrated `server/frdp/frdpd` target builds successfully and now includes the partial configuration
parser. The helper prototype sources in `server/frdp/frdp-authd`, `server/frdp/frdp-sesmand`,
`server/frdp/frdp-session-agent`, `server/frdp/frdp-krb-authd`, and `tools/frdpctl` are not part of that
build or the canonical runtime topology.

## Implemented since the previous issue pass

- The root-level `/frdpd` implementation is no longer present, so the earlier divergence/TLS-only/blocking-accept issues for that path are retired.
- `frdp-authd` now checks `mmap()` failure with `MAP_FAILED`; the remaining locked-memory concern is tracked in FRDP-010.
- `frdp-authd` no longer calls `initgroups()` in the broker process.
- `frdpd` now accepts `--config` and applies implemented `frdpd.toml` server/auth fields before CLI overrides; unsupported Kerberos/NTLM policy fields are rejected instead of being silently accepted.
- `frdp-config` now uses bounded string copies and strict integer/boolean parsing for fields it understands.
- `frdp-authd` IPC now rejects overlong/non-terminated auth fields, unsafe socket paths, and peers with a different effective UID on Linux; its socket is created with `0600` permissions.
- `frdp-sesmand` now includes `<grp.h>` and passes a strict syntax-only check.
- The standalone `frdp-sesmand` prototype now keeps the PAM handle for the session lifetime, runs `initgroups()` in the child after `fork()`, and records a process group for cleanup.
- The standalone `frdp-session-agent` now fails fast when `Xvfb` exec fails instead of entering an infinite sleep loop.

## Remaining issues

| ID | Issue | Severity | Confidence | Evidence | Impact | Recommended action |
|---|---|---:|---:|---|---|---|
| FRDP-001 | Helper prototypes are not connected to CMake, install rules, IPC, or the integrated `server/frdp/frdpd` daemon. | 90% | 100% | `server/frdp/frdpd/CMakeLists.txt` builds the integrated daemon and config parser, but repository `CMakeLists.txt` files do not reference `server/frdp/frdp-authd`, `server/frdp/frdp-sesmand`, `server/frdp/frdp-session-agent`, `server/frdp/frdp-krb-authd`, or `tools/frdpctl`. | Prototype code can drift untested and may be mistaken for working MVP functionality. | Add proper targets/tests/install rules for helpers or retire/quarantine them as non-runtime examples. |
| FRDP-002 | No implemented IPC connects `frdpd`, `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, and `frdp-krb-authd`. | 90% | 95% | `server/frdp/frdpd/frdpd.c` calls `frdpd_authenticate_identity()` directly in the peer `Logon` callback; no code path invokes the helper daemons. | The intended multi-process security and lifecycle architecture is not operational. | Define the IPC protocol and wire one end-to-end authenticated session path before expanding features. |
| FRDP-003 | The integrated `frdpd` opens PAM sessions inside the peer worker instead of delegating auth/session lifecycle to separated auth/session processes. | 85% | 95% | `server/frdp/frdpd/frdpd.c:126-139` stores the PAM handle in `frdpdPeerContext`; `server/frdp/frdpd/frdpd_pam.c:187-199` opens the session directly. | The daemon worker keeps long-lived PAM state, has no per-user UID/GID transition, and does not establish the intended privilege boundary. | Move PAM auth/account/session ownership into the authd/sesmand design, and add explicit credential/session lifecycle ownership. |
| FRDP-004 | PAM credential lifecycle is incomplete for a login session. | 75% | 90% | `server/frdp/frdpd/frdpd_pam.c` calls `pam_authenticate()`, `pam_acct_mgmt()`, and `pam_open_session()`, but does not call `pam_setcred()` for establish/delete credential phases. | PAM modules that rely on credential setup/cleanup may not behave like a real login. | Add `pam_setcred(PAM_ESTABLISH_CRED)` before session open and matching cleanup on close, with failure handling and tests. |
| FRDP-005 | No desktop data path is implemented in the integrated daemon. | 90% | 100% | `server/frdp/frdpd/frdpd.c:181-245` input/update callbacks discard keyboard, mouse, refresh, and suppress-output events. | A client may authenticate and connect to a protocol stub, but there is no usable desktop. | Wire the authenticated peer to a session agent/backend, then implement framebuffer capture, update scheduling, and input forwarding. |
| FRDP-006 | Channel policy and useful virtual channels are not implemented. | 80% | 95% | The plan requires clipboard/audio/channel policy, but `server/frdp/frdpd` contains no integrated channel policy engine and no clipboard/audio handling. | Risky redirection cannot be enforced centrally, and MVP clipboard/audio requirements are not met. | Add deny-by-default channel policy before enabling any redirection channel; then implement text clipboard and baseline audio explicitly. |
| FRDP-007 | Client interoperability and AD/SSSD lab validation are not represented by automated tests or checked artifacts. | 70% | 90% | The client matrix and AD/SSSD lab deliverables remain unchecked; no `frdpd` tests were found. | Build success can hide NLA/client/PAM/SSSD interoperability failures. | Add lab scripts and smoke tests for accepted login, denied login, client connection attempts, and domain user normalization. |
| FRDP-008 | `server/frdp/frdpd` consumes only a subset of `frdpd.toml`. | 55% | 100% | `server/frdp/frdpd/frdpd.c` applies `listen`, implemented `security=nla`, `tls_cert`, `tls_key`, `mode=pam-sssd`, and `pam_service`; `server/frdp/config/frdp-config.c` rejects unsupported Kerberos/NTLM, `max_connections`, `session`, `channels`, and `audit` fields. | Kerberos policy, connection caps, sessions, channel policy, and audit config remain unavailable until enforcement exists, but they no longer appear as silently accepted active policy. | Extend config parsing and application incrementally, failing closed on invalid values and documenting unsupported fields until they are wired. |
| FRDP-009 | Packaging files still reference helper binaries that are not built or installed by CMake. | 70% | 100% | `packaging/rpm/frdpd.spec:37-42` lists helper binaries and `frdpctl` that are not built by CMake; only `server/frdp/frdpd` is integrated as a target. | Packages are likely to fail or install incomplete helper topology. | Add real CMake targets/install rules for helpers or remove them from package manifests until integrated. |
| FRDP-010 | `frdp-authd` still has test-only command-line password ingress. | 70% | 100% | `server/frdp/frdp-authd/frdp-authd.c` still accepts `<username> <password>` positional arguments outside IPC mode. | Passwords can leak through process listings, shell history, crash telemetry, and audit systems if the test path is installed or used operationally. | Remove argv password support from production builds, or gate it behind an explicit test-only build option not installed in packages. |
| FRDP-011 | Audit correlation is not end-to-end. | 65% | 95% | `server/frdp/frdp-authd/frdp-authd.c:59-69` generates a local UUID per audit event; integrated `server/frdp/frdpd` does not generate or propagate a connection/session correlation id. | Logs from RDP accept, PAM auth, session startup, channel decisions, and cleanup cannot be reliably joined. | Generate a connection correlation id in `frdpd` and pass it through auth/session IPC, PAM messages, and channel/session logs. |
| FRDP-012 | `frdp-sesmand` is still a demonstration program, not an integrated session manager. | 85% | 100% | `server/frdp/frdp-sesmand/frdp-sesmand.c:151-156` creates a hard-coded `nobody` session on startup; there is no request protocol from authenticated RDP peers. | It cannot start real user sessions from `frdpd`, enforce reconnect decisions, or manage live desktop lifecycle. | Replace the demo `main()` with a service endpoint and request model tied to authenticated users/session ids. |
| FRDP-013 | Display allocation and resize behavior remain prototype-level. | 60% | 100% | `server/frdp/frdp-sesmand/frdp-sesmand.c:41` increments `next_display` in memory only; `server/frdp/frdp-session-agent/frdp-session-agent.c:32-38` still falls back to `:99` and `1024x768x24`. | Concurrent sessions can collide after restart or with external X servers; display resize is not represented. | Reserve display numbers atomically, persist/session-scope allocation state, and pass negotiated geometry/resize events through session metadata. |
| FRDP-014 | `frdp-session-agent` only launches Xvfb and waits for it. | 85% | 100% | `server/frdp/frdp-session-agent/frdp-session-agent.c:54-55` leaves framebuffer capture, input, clipboard, and audio as TODOs. | The session backend cannot render to the RDP client or receive user input. | Add the agent protocol and implement framebuffer/damage capture, input dispatch, encoder scheduling, and initial clipboard/audio features. |
| FRDP-015 | `frdp-krb-authd` is a skeleton, not a working Kerberos/CredSSP acceptor. | 85% | 100% | `server/frdp/frdp-krb-authd/frdp-krb-authd.c:36-56` accepts a token argument but does not decode it before `gss_accept_sec_context()`; `server/frdp/frdp-krb-authd/frdp-krb-authd.c:39-40` hard-codes the keytab path; mapping uses raw `getpwnam()` on the displayed principal. | Kerberos-first authentication cannot be validated, and principal-to-account mapping is likely wrong for real AD principals. | Implement SPNEGO token ingestion from CredSSP, configured keytab/SPN handling, SSSD-backed principal mapping, and PAM account/session integration. |
| FRDP-016 | Integrated secret hardening is partial. | 75% | 90% | `server/frdp/frdpd` zeroizes temporary password copies but does not disable core dumps, lock secret buffers, or isolate secret handling into a short-lived broker. | Password material can remain exposed in daemon memory/core dumps longer than intended. | Add process-level no-core hardening, scoped locked secret buffers where practical, and move credential handling into the auth broker path. |

## Build observations

- The integrated `frdpd` target builds successfully in `/tmp/opencode/freerdp-current-build`.
- The standalone prototypes and newly touched config/IPC files pass syntax-only checks; `frdp-krb-authd` emits a warning about a set-but-unused `maj_stat` variable in `display_status()`.
- The build emits existing FreeRDP deprecation warnings unrelated to the new PAM/SSSD/NLA prototype.
- No package build, PAM login, AD/SSSD lab, or RDP client interoperability test was run in this pass.
