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
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-authd/frdp-authd.c server/frdp/ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra server/frdp/config/frdp-config.c server/frdp/frdpd/frdpd-ipc-demo.c server/frdp/ipc/frdp-ipc.c
# frdp-authd IPC negative-path smoke: frdpd-ipc-demo returns Authentication result: failure for invalid credentials.
```

The integrated `server/frdp/frdpd` target builds successfully and now includes the partial configuration
parser. The helper prototype sources in `server/frdp/frdp-authd`, `server/frdp/frdp-sesmand`,
`server/frdp/frdp-session-agent`, `server/frdp/frdp-krb-authd`, and `tools/frdpctl` now have CMake targets
under `WITH_FRDPD`, but they are not part of the canonical runtime topology.

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
- Integrated `frdpd` now calls `pam_setcred(PAM_ESTABLISH_CRED)` after successful auth/account checks and `pam_setcred(PAM_DELETE_CRED)` during cleanup.
- Integrated `frdpd`, `frdp-authd`, and `frdp-sesmand` fail closed if core dumps/non-dumpable process hardening cannot be applied before handling credentials or sessions.
- `frdp-authd` no longer accepts passwords through positional command-line arguments; it only exposes the local `--socket` IPC server mode.
- `frdp-sesmand` no longer creates a hard-coded `nobody` session on startup; the standalone helper requires an explicit `--open-session <user>` request and `FRDP_SESMAND_ALLOW_STANDALONE=1` development opt-in.
- `frdpd` can now route password-backed auth/account checks through `frdp-authd` over IPC when `auth_socket` or `--auth-socket=<absolute-path>` is configured.
- `frdp-authd` IPC requests now carry the remote host in addition to the normalized user and password; PAM service selection remains broker-side and is configured with `frdp-authd --pam-service`.
- Integrated `frdpd` now generates a per-peer correlation id, includes it on accept/auth/logon/activate/disconnect logs, and sends it in optional `frdp-authd` IPC auth requests; `frdp-authd` uses a valid incoming id for syslog audit events and falls back to a local UUID when the request omits or sends an invalid id.

## Remaining issues

| ID | Issue | Severity | Confidence | Evidence | Impact | Recommended action |
|---|---|---:|---:|---|---|---|
| FRDP-001 | Helper binaries are built and `frdp-authd` can be used for authentication, but the full runtime topology is not connected. | 80% | 100% | `server/frdp/CMakeLists.txt` builds helper targets and install rules under `WITH_FRDPD`; `server/frdp/frdpd/frdpd_auth.c` can call `frdp-authd` over IPC when `auth_socket` is configured, but `frdpd` still does not call `frdp-sesmand` or `frdp-session-agent`. | Built helper binaries can still drift from actual MVP behavior until an end-to-end session path exercises them. | Wire `frdpd -> frdp-authd -> frdp-sesmand -> frdp-session-agent` as a single authenticated session path before expanding helper features. |
| FRDP-002 | IPC currently connects only `frdpd` to `frdp-authd`; session and Kerberos helper IPC is not implemented. | 85% | 95% | `server/frdp/frdpd/frdpd_auth.c` sends `FRDP_IPC_AUTH_REQUEST_V2` to `frdp-authd`, while no code path invokes `frdp-sesmand`, `frdp-session-agent`, or `frdp-krb-authd`. | The intended multi-process session lifecycle architecture is not operational. | Extend the IPC protocol with authenticated session requests and wire one end-to-end session path before expanding features. |
| FRDP-003 | The integrated `frdpd` still has an in-process PAM fallback and opens PAM sessions inside the peer worker. | 80% | 95% | Without `auth_socket`, `server/frdp/frdpd/frdpd_auth.c` still calls `frdpd_pam_authenticate()` directly; `server/frdp/frdpd/frdpd_pam.c` opens the PAM session directly. With `auth_socket`, auth/account moves to `frdp-authd`, but it fails closed unless `--no-pam-session` is set because session ownership is not delegated to `frdp-sesmand`. | The daemon worker can still keep long-lived PAM state, has no per-user UID/GID transition, and does not establish the intended session privilege boundary. | Make `frdp-authd` the canonical auth path, move session ownership into `frdp-sesmand`, and remove the in-process peer-worker PAM path. |
| FRDP-005 | No desktop data path is implemented in the integrated daemon. | 90% | 100% | `server/frdp/frdpd/frdpd.c:181-245` input/update callbacks discard keyboard, mouse, refresh, and suppress-output events. | A client may authenticate and connect to a protocol stub, but there is no usable desktop. | Wire the authenticated peer to a session agent/backend, then implement framebuffer capture, update scheduling, and input forwarding. |
| FRDP-006 | Channel policy and useful virtual channels are not implemented. | 80% | 95% | The plan requires clipboard/audio/channel policy, but `server/frdp/frdpd` contains no integrated channel policy engine and no clipboard/audio handling. | Risky redirection cannot be enforced centrally, and MVP clipboard/audio requirements are not met. | Add deny-by-default channel policy before enabling any redirection channel; then implement text clipboard and baseline audio explicitly. |
| FRDP-007 | Client interoperability and AD/SSSD lab validation are not represented by automated tests or checked artifacts. | 70% | 90% | The client matrix and AD/SSSD lab deliverables remain unchecked; no `frdpd` tests were found. | Build success can hide NLA/client/PAM/SSSD interoperability failures. | Add lab scripts and smoke tests for accepted login, denied login, client connection attempts, and domain user normalization. |
| FRDP-008 | `server/frdp/frdpd` consumes only a subset of `frdpd.toml`. | 50% | 100% | `server/frdp/frdpd/frdpd.c` applies `listen`, implemented `security=nla`, `tls_cert`, `tls_key`, `mode=pam-sssd`, `pam_service`, and optional absolute `auth_socket`; `server/frdp/config/frdp-config.c` rejects unsupported Kerberos/NTLM, `max_connections`, `session`, `channels`, and `audit` fields. | Kerberos policy, connection caps, sessions, channel policy, and audit config remain unavailable until enforcement exists, but they no longer appear as silently accepted active policy. | Extend config parsing and application incrementally, failing closed on invalid values and documenting unsupported fields until they are wired. |
| FRDP-009 | Packaging remains draft-only and is not build-verified. | 60% | 100% | `server/frdp/CMakeLists.txt` now installs the listed runtime helper binaries and `frdpd.toml`, but no RPM/DEB package build has been run, and service/PAM policy installation is still incomplete. | Packages can still fail in CI or install a daemon without the required PAM/systemd policy files. | Add package build verification and install rules for PAM/systemd/security policy artifacts. |
| FRDP-011 | Audit correlation is partial, not end-to-end. | 50% | 95% | `server/frdp/frdpd/frdpd.c` generates a per-peer id and logs accept/auth/logon/activate/disconnect with it; `server/frdp/frdpd/frdpd_auth.c` sends it in optional `FRDP_IPC_AUTH_REQUEST_V2`; `server/frdp/frdp-authd/frdp-authd.c` uses valid ids for auth audit events. No `frdp-sesmand`, agent, channel, or structured audit config path carries it yet. | Current auth/connection logs can be joined on the optional auth IPC path, but session startup, channel decisions, and cleanup still cannot be correlated end-to-end. | Carry the same id through session-manager IPC, agent startup, channel policy logs, and structured audit configuration before marking audit correlation complete. |
| FRDP-012 | `frdp-sesmand` is still a standalone helper, not an integrated session manager service. | 85% | 100% | `server/frdp/frdp-sesmand/frdp-sesmand.c` can open an explicit `--open-session <user>` development helper path only with `FRDP_SESMAND_ALLOW_STANDALONE=1`, but there is no request protocol from authenticated RDP peers. | It cannot start real user sessions from `frdpd`, enforce reconnect decisions, or manage live desktop lifecycle. | Replace the standalone command path with a service endpoint and request model tied to authenticated users/session ids. |
| FRDP-013 | Display allocation and resize behavior remain prototype-level. | 60% | 100% | `server/frdp/frdp-sesmand/frdp-sesmand.c:41` increments `next_display` in memory only; `server/frdp/frdp-session-agent/frdp-session-agent.c:32-38` still falls back to `:99` and `1024x768x24`. | Concurrent sessions can collide after restart or with external X servers; display resize is not represented. | Reserve display numbers atomically, persist/session-scope allocation state, and pass negotiated geometry/resize events through session metadata. |
| FRDP-014 | `frdp-session-agent` only launches Xvfb and waits for it. | 85% | 100% | `server/frdp/frdp-session-agent/frdp-session-agent.c:54-55` leaves framebuffer capture, input, clipboard, and audio as TODOs. | The session backend cannot render to the RDP client or receive user input. | Add the agent protocol and implement framebuffer/damage capture, input dispatch, encoder scheduling, and initial clipboard/audio features. |
| FRDP-015 | `frdp-krb-authd` is a build-only skeleton, not a working Kerberos/CredSSP acceptor. | 85% | 100% | `server/frdp/frdp-krb-authd/frdp-krb-authd.c:36-56` accepts a token argument but does not decode it before `gss_accept_sec_context()`; `server/frdp/frdp-krb-authd/frdp-krb-authd.c:39-40` hard-codes the keytab path; mapping uses raw `getpwnam()` on the displayed principal; `server/frdp/CMakeLists.txt` intentionally does not install it. | Kerberos-first authentication cannot be validated, and principal-to-account mapping is likely wrong for real AD principals. | Implement SPNEGO token ingestion from CredSSP, configured keytab/SPN handling, SSSD-backed principal mapping, and PAM account/session integration before installing/package-enabling it. |
| FRDP-016 | Integrated secret hardening is partial. | 65% | 90% | `server/frdp/frdpd`, `server/frdp/frdp-authd`, and `server/frdp/frdp-sesmand` fail closed if core dumps/non-dumpable process hardening cannot be applied, and `server/frdp/frdpd` zeroizes temporary password copies, but frdpd does not lock secret buffers or isolate secret handling into the short-lived auth broker path. | Password material can remain exposed in daemon memory longer than intended. | Add scoped locked secret buffers where practical and move credential handling into the auth broker path. |

## Build observations

- The integrated `frdpd` target and helper targets build successfully in `/tmp/opencode/freerdp-current-build`.
- The isolated `server` component install check succeeds for FRDP binaries/config when unrelated shadow/proxy server targets are disabled.
- The standalone prototypes and newly touched config/IPC files pass syntax-only checks.
- The build emits existing FreeRDP deprecation warnings unrelated to the new PAM/SSSD/NLA prototype.
- No package build, PAM login, AD/SSSD lab, or RDP client interoperability test was run in this pass.
