# 09. Implementation issues

Analysis date: 2026-06-15.

Build and syntax checks used for this pass:

```bash
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF
cmake --build /tmp/opencode/freerdp-current-build --target frdpd frdp-authd frdp-sesmand frdp-session-agent frdpd-ipc-demo frdpctl frdp-krb-authd -j2
cmake --build /tmp/opencode/freerdp-current-build --target frdpd frdp-authd frdpd-ipc-demo -j2
cmake -S . -B /tmp/opencode/freerdp-frdp-install-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF
cmake --build /tmp/opencode/freerdp-frdp-install-build --target frdpd frdp-authd frdp-sesmand frdp-session-agent frdpctl frdp-krb-authd -j2
cmake --install /tmp/opencode/freerdp-frdp-install-build --component server --prefix /tmp/opencode/freerdp-install-frdp
cmake -S . -B /tmp/opencode/freerdp-frdp-package-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF -DCMAKE_INSTALL_PREFIX=/usr -DCMAKE_INSTALL_SYSCONFDIR=/etc
DESTDIR=/tmp/opencode/freerdp-package-root cmake --install /tmp/opencode/freerdp-frdp-package-build --component server
rpmspec --define "_topdir /tmp/opencode/frdp-rpmbuild" -P /tmp/opencode/frdp-rpmbuild/SPECS/frdpd.spec
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-authd/frdp-authd.c server/frdp/ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-sesmand/frdp-sesmand.c server/frdp/ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-session-agent/frdp-session-agent.c
cc -fsyntax-only -Wall -Wextra server/frdp/config/frdp-config.c server/frdp/frdpd/frdpd-ipc-demo.c server/frdp/ipc/frdp-ipc.c
# frdp-authd IPC negative-path smoke: frdpd-ipc-demo returns Authentication result: failure for invalid credentials.
# frdp-sesmand IPC startup smoke: --socket creates a 0600 Unix socket in a 0700 runtime directory.
```

The integrated `server/frdp/frdpd` target builds successfully and now includes the partial configuration
parser. The helper prototype sources in `server/frdp/frdp-authd`, `server/frdp/frdp-sesmand`,
`server/frdp/frdp-session-agent`, `server/frdp/frdp-krb-authd`, and `tools/frdpctl` now have CMake targets
under `WITH_FRDPD`, but they are not part of the canonical runtime topology.

Package build verification is still blocked in this environment: `rpmbuild -bb --nodeps` reaches `%build`
but the host RPM macro set does not provide `%cmake`, and `packaging/debian` currently contains only a draft
`control` file without `rules` or `changelog` for `dpkg-buildpackage`.

## Implemented since the previous issue pass

- The root-level `/frdpd` implementation is no longer present, so the earlier divergence/TLS-only/blocking-accept issues for that path are retired.
- `frdp-authd` now checks `mmap()` failure with `MAP_FAILED`; the remaining locked-memory concern is tracked in FRDP-016.
- `frdp-authd` no longer calls `initgroups()` in the broker process.
- `frdpd` now accepts `--config` and applies implemented `frdpd.toml` server/auth fields before CLI overrides; unsupported Kerberos/NTLM policy fields are rejected instead of being silently accepted.
- `frdp-config` now uses bounded string copies and strict integer/boolean parsing for fields it understands.
- `frdp-authd` IPC now rejects overlong/non-terminated auth fields, unsafe socket paths, and peers with a different effective UID on Linux; its socket is created with `0600` permissions.
- `frdp-sesmand` now includes `<grp.h>` and passes a strict syntax-only check.
- The standalone `frdp-sesmand` prototype now keeps the PAM handle for the session lifetime, runs `initgroups()` in the child after `fork()`, and records a process group for cleanup.
- The standalone `frdp-session-agent` now fails fast when `Xvfb` exec fails instead of entering an infinite sleep loop.
- `server/frdp` now builds and installs `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, and `frdpctl`; it also builds `frdpd-ipc-demo`, builds but does not install the `frdp-krb-authd` prototype when GSSAPI is available, and installs `frdpd.toml`.
- `server/frdp` now installs a dedicated non-interactive PAM service example at `/etc/pam.d/frdpd` through the CMake `server` component.
- `server/frdp` now installs `frdpd`, `frdp-authd`, and `frdp-sesmand` systemd service examples plus inactive SELinux/AppArmor draft policy examples through the CMake `server` component.
- Integrated `frdpd` now calls `pam_setcred(PAM_ESTABLISH_CRED)` after successful auth/account checks and `pam_setcred(PAM_DELETE_CRED)` during cleanup.
- Integrated `frdpd`, `frdp-authd`, and `frdp-sesmand` fail closed if core dumps/non-dumpable process hardening cannot be applied before handling credentials or sessions.
- `frdp-authd` no longer accepts passwords through positional command-line arguments; it only exposes the local `--socket` IPC server mode.
- `frdp-sesmand` no longer creates a hard-coded `nobody` session on startup; the standalone helper requires an explicit `--open-session <user>` request and `FRDP_SESMAND_ALLOW_STANDALONE=1` development opt-in.
- `frdpd` can now route password-backed auth/account checks through `frdp-authd` over IPC when `auth_socket` or `--auth-socket=<absolute-path>` is configured.
- `frdp-authd` IPC requests now carry the remote host in addition to the normalized user and password; PAM service selection remains broker-side and is configured with `frdp-authd --pam-service`.
- Integrated `frdpd` now generates a per-peer correlation id, includes it on accept/auth/logon/activate/disconnect logs, and sends it in optional `frdp-authd` IPC auth requests; `frdp-authd` uses a valid incoming id for syslog audit events and falls back to a local UUID when the request omits or sends an invalid id.
- `frdp-sesmand` now exposes a guarded local `--socket` IPC server; integrated `frdpd` can open and close managed sessions through optional `session_socket` / `--session-socket=<absolute-path>` when PAM session opening is disabled.
- Shared FRDP IPC clients now set send/receive timeouts and use `MSG_NOSIGNAL` when available so disconnected IPC peers return errors instead of terminating the process with `SIGPIPE`.
- Optional session IPC now passes session ids and correlation ids into `frdp-session-agent`, which includes them in startup and display-backend exit logs.
- `frdp-session-agent` now confirms Xvfb backend `exec()` via a close-on-exec readiness pipe, and `frdp-sesmand` fails session creation if the agent exits immediately after startup.

## Remaining issues

| ID | Issue | Severity | Confidence | Evidence | Impact | Recommended action |
|---|---|---:|---:|---|---|---|
| FRDP-001 | Helper binaries are built and optional auth/session IPC paths exist, but the default runtime topology is not yet canonical. | 55% | 100% | `server/frdp/CMakeLists.txt` builds helper targets and install rules under `WITH_FRDPD`; `server/frdp/frdpd/frdpd_auth.c` can call `frdp-authd` over IPC when `auth_socket` is configured; `server/frdp/frdpd/frdpd.c` can call `frdp-sesmand` over IPC when `session_socket` is configured. The default path still permits in-process PAM auth/session and no RDP desktop data path is connected. | Built helper binaries can still drift from production behavior until the helper IPC path becomes the default and is covered by end-to-end tests. | Make `frdp-authd` and `frdp-sesmand` the canonical runtime path, then remove the peer-worker PAM session fallback. |
| FRDP-002 | IPC now connects `frdpd` to auth and session helpers, but Kerberos helper IPC and the desktop data path are not implemented. | 60% | 95% | `server/frdp/frdpd/frdpd_auth.c` sends `FRDP_IPC_AUTH_REQUEST_V2` to `frdp-authd`; `server/frdp/frdpd/frdpd.c` sends `FRDP_IPC_SESSION_REQUEST` and `FRDP_IPC_SESSION_CLOSE_REQUEST` to `frdp-sesmand`; no code path invokes `frdp-krb-authd`, and `frdp-session-agent` has no framebuffer/input protocol. | The intended multi-process auth/session lifecycle is partially operational, but Kerberos-first auth and a usable desktop remain unavailable. | Add Kerberos helper IPC later; first connect frdpd to the session-agent framebuffer/input protocol after managed session creation. |
| FRDP-003 | The integrated `frdpd` still has an in-process PAM fallback and can open PAM sessions inside the peer worker. | 70% | 95% | Without `auth_socket`, `server/frdp/frdpd/frdpd_auth.c` still calls `frdpd_pam_authenticate()` directly. Without `session_socket`, `server/frdp/frdpd/frdpd_pam.c` can still open the PAM session directly. With `session_socket`, session ownership is delegated to `frdp-sesmand` and `frdpd` requires `--no-pam-session`. | The daemon worker can still keep long-lived PAM state in fallback mode, and the intended privilege boundary is not the default. | Make `frdp-authd` plus `frdp-sesmand` the canonical default and remove the in-process peer-worker PAM session path. |
| FRDP-005 | No desktop data path is implemented in the integrated daemon. | 90% | 100% | `server/frdp/frdpd/frdpd.c:181-245` input/update callbacks discard keyboard, mouse, refresh, and suppress-output events. | A client may authenticate and connect to a protocol stub, but there is no usable desktop. | Wire the authenticated peer to a session agent/backend, then implement framebuffer capture, update scheduling, and input forwarding. |
| FRDP-006 | Channel policy and useful virtual channels are not implemented. | 80% | 95% | The plan requires clipboard/audio/channel policy, but `server/frdp/frdpd` contains no integrated channel policy engine and no clipboard/audio handling. | Risky redirection cannot be enforced centrally, and MVP clipboard/audio requirements are not met. | Add deny-by-default channel policy before enabling any redirection channel; then implement text clipboard and baseline audio explicitly. |
| FRDP-007 | Client interoperability and AD/SSSD lab validation are not represented by automated tests or checked artifacts. | 70% | 90% | The client matrix and AD/SSSD lab deliverables remain unchecked; no `frdpd` tests were found. | Build success can hide NLA/client/PAM/SSSD interoperability failures. | Add lab scripts and smoke tests for accepted login, denied login, client connection attempts, and domain user normalization. |
| FRDP-008 | `server/frdp/frdpd` consumes only a subset of `frdpd.toml`. | 45% | 100% | `server/frdp/frdpd/frdpd.c` applies `listen`, implemented `security=nla`, `tls_cert`, `tls_key`, `mode=pam-sssd`, `pam_service`, optional absolute `auth_socket`, and optional absolute `[session].session_socket`; `server/frdp/config/frdp-config.c` rejects unsupported Kerberos/NTLM, `max_connections`, unknown session fields, `channels`, and `audit` fields. | Kerberos policy, connection caps, channel policy, and audit config remain unavailable until enforcement exists, but they no longer appear as silently accepted active policy. | Extend config parsing and application incrementally, failing closed on invalid values and documenting unsupported fields until they are wired. |
| FRDP-009 | Packaging remains draft-only and is not package-build verified. | 40% | 100% | `server/frdp/CMakeLists.txt` now installs the listed runtime helper binaries, `frdpd.toml`, the `frdpd` PAM service example, systemd service examples, and inactive SELinux/AppArmor draft policy examples; package-style CMake install was verified under `DESTDIR`, but no RPM/DEB package build has completed. Local RPM build is blocked by missing host `%cmake` RPM macros, Debian packaging lacks `rules`/`changelog`, and MAC profiles are not validated or activated. | Packages can still fail in CI, and installed draft policy examples are not sufficient production confinement. | Add RPM/DEB package build verification, distro-specific service scriptlet validation, and validated SELinux/AppArmor policy before treating packaging as complete. |
| FRDP-011 | Audit correlation is partial, not end-to-end. | 40% | 95% | `server/frdp/frdpd/frdpd.c` generates a per-peer id and logs accept/auth/logon/activate/disconnect with it; `server/frdp/frdpd/frdpd_auth.c` sends it in optional `FRDP_IPC_AUTH_REQUEST_V2`; `server/frdp/frdpd/frdpd.c` sends it in optional session open/close IPC; `server/frdp/frdp-authd/frdp-authd.c`, `server/frdp/frdp-sesmand/frdp-sesmand.c`, and `server/frdp/frdp-session-agent/frdp-session-agent.c` use ids in auth/session/agent audit events. Channel and structured audit config paths do not carry it yet. | Current auth/session/agent startup logs can be joined on optional IPC paths, but channel decisions still cannot be correlated end-to-end. | Carry the same id through channel policy logs and structured audit configuration before marking audit correlation complete. |
| FRDP-012 | `frdp-sesmand` has a session service endpoint, but reconnect and production lifecycle management are incomplete. | 60% | 100% | `server/frdp/frdp-sesmand/frdp-sesmand.c` exposes `--socket` for `FRDP_IPC_SESSION_REQUEST` and `FRDP_IPC_SESSION_CLOSE_REQUEST`; `server/frdp/frdpd/frdpd.c` can call it after authentication and schedules bounded close retries if disconnect cleanup IPC fails. Reconnect lookup, persistent session metadata, durable cleanup after prolonged manager outage, logind/cgroups, and agent protocol supervision remain missing. | Sessions can be opened and closed by authenticated peers on the optional path, but production reconnect/resource lifecycle requirements are not met. | Add reconnect semantics, persistent/session-scoped display allocation, durable cleanup/reconciliation, logind/cgroup integration, and agent protocol supervision. |
| FRDP-013 | Display allocation and resize behavior remain prototype-level. | 60% | 100% | `server/frdp/frdp-sesmand/frdp-sesmand.c:41` increments `next_display` in memory only; `server/frdp/frdp-session-agent/frdp-session-agent.c:32-38` still falls back to `:99` and `1024x768x24`. | Concurrent sessions can collide after restart or with external X servers; display resize is not represented. | Reserve display numbers atomically, persist/session-scope allocation state, and pass negotiated geometry/resize events through session metadata. |
| FRDP-014 | `frdp-session-agent` launches Xvfb with exec readiness, but has no RDP data protocol. | 80% | 100% | `server/frdp/frdp-session-agent/frdp-session-agent.c` verifies Xvfb `exec()` before logging backend startup, but framebuffer capture, input, clipboard, and audio remain TODOs. | The session backend can fail closed on missing Xvfb, but it still cannot render to the RDP client or receive user input. | Add the agent protocol and implement framebuffer/damage capture, input dispatch, encoder scheduling, and initial clipboard/audio features. |
| FRDP-015 | `frdp-krb-authd` is a build-only skeleton, not a working Kerberos/CredSSP acceptor. | 85% | 100% | `server/frdp/frdp-krb-authd/frdp-krb-authd.c:36-56` accepts a token argument but does not decode it before `gss_accept_sec_context()`; `server/frdp/frdp-krb-authd/frdp-krb-authd.c:39-40` hard-codes the keytab path; mapping uses raw `getpwnam()` on the displayed principal; `server/frdp/CMakeLists.txt` intentionally does not install it. | Kerberos-first authentication cannot be validated, and principal-to-account mapping is likely wrong for real AD principals. | Implement SPNEGO token ingestion from CredSSP, configured keytab/SPN handling, SSSD-backed principal mapping, and PAM account/session integration before installing/package-enabling it. |
| FRDP-016 | Integrated secret hardening is partial. | 65% | 90% | `server/frdp/frdpd`, `server/frdp/frdp-authd`, and `server/frdp/frdp-sesmand` fail closed if core dumps/non-dumpable process hardening cannot be applied, and `server/frdp/frdpd` zeroizes temporary password copies, but frdpd does not lock secret buffers or isolate secret handling into the short-lived auth broker path. | Password material can remain exposed in daemon memory longer than intended. | Add scoped locked secret buffers where practical and move credential handling into the auth broker path. |

## Build observations

- The integrated `frdpd` target and helper targets build successfully in `/tmp/opencode/freerdp-current-build`.
- The isolated `server` component install check succeeds for FRDP binaries/config when unrelated shadow/proxy server targets are disabled.
- The standalone prototypes and newly touched config/IPC files pass syntax-only checks.
- The build emits existing FreeRDP deprecation warnings unrelated to the new PAM/SSSD/NLA prototype.
- No package build, PAM login, AD/SSSD lab, or RDP client interoperability test was run in this pass.
