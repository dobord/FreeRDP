# 09. Implementation issues

Analysis date: 2026-06-15.

Build checked with:

```bash
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF
cmake --build /tmp/opencode/freerdp-current-build -j2
```

The integrated CMake build succeeds. The standalone prototype sources in `/frdpd`, `/frdp-authd`,
`/frdp-sesmand`, and `/frdp-session-agent` are not part of that build.

| ID | Issue | Severity | Confidence | Evidence | Impact | Recommended action |
|---|---|---:|---:|---|---|---|
| FRDP-001 | Standalone prototype components are not connected to CMake, install rules, or the integrated `server/frdpd` daemon. | 90% | 100% | No `CMakeLists.txt` references for `frdp-authd`, `frdp-sesmand`, `frdp-session-agent`, or root `/frdpd`; full build only builds `server/frdpd`. | Code can drift untested and may be mistaken for working MVP functionality. | Add proper targets or move prototypes under `server/frdpd`; make CI build them or remove stale duplicates. |
| FRDP-002 | `frdp-sesmand` does not compile with strict syntax checks because `initgroups()` is used without declaring header `<grp.h>`. | 85% | 100% | `cc -fsyntax-only -Wall -Wextra frdp-sesmand/frdp-sesmand.c` reports implicit declaration at `frdp-sesmand/frdp-sesmand.c:69`. | Session manager cannot be safely promoted into the build as-is. | Include `<grp.h>` and add the target to CMake/CI to prevent recurrence. |
| FRDP-003 | There are two divergent `frdpd` implementations: integrated `server/frdpd` and standalone root `/frdpd`. | 85% | 100% | `server/frdpd/frdpd.c` uses FreeRDP peer APIs; `/frdpd/frdpd.c` is a raw OpenSSL TCP listener. | Architecture and roadmap status are ambiguous; fixes may land in the wrong daemon. | Pick one canonical daemon path and delete or quarantine the other. |
| FRDP-004 | Root `/frdpd` accepts TLS but does not implement RDP, CredSSP/NLA, authd IPC, or session handoff. | 85% | 95% | `/frdpd/frdpd.c:189-190` contains TODOs for NLA/CredSSP and session manager handoff. | It is not an RDP server MVP despite accepting TLS sockets. | Do not count root `/frdpd` toward NLA/RDP readiness; either wire FreeRDP APIs or retire it. |
| FRDP-005 | `frdp-authd` accepts passwords on the command line. | 80% | 100% | `/frdp-authd/frdp-authd.c:130-138` requires `<username> <password>` argv. | Passwords can leak through shell history, process lists, audit logs, and crash diagnostics. | Replace CLI secret input with IPC credentials, fd-passing, or protected stdin/test-only code guarded out of production builds. |
| FRDP-006 | `frdp-authd` checks `mmap()` failure incorrectly and ignores `mlock()` failure. | 75% | 95% | `/frdp-authd/frdp-authd.c:82-87` checks `if (!buf)` although `mmap()` returns `MAP_FAILED`; `mlock()` return is ignored. | Failure can lead to invalid memory use or false assumption that secrets are locked. | Check `buf == MAP_FAILED`, handle `mlock()` failures, and use a small secret-buffer helper with tests. |
| FRDP-007 | `frdp-authd` calls `initgroups()` inside the broker process after authentication. | 70% | 90% | `/frdp-authd/frdp-authd.c:108-116` performs account lookup and `initgroups(user, gid)`. | The broker process can mutate its supplementary groups based on the last authenticated user. | Move group setup to the per-user child/session context and keep authd privilege state stable. |
| FRDP-008 | `frdp-sesmand` opens and immediately ends a PAM session, then later tries to close a newly started PAM handle. | 80% | 95% | `/frdp-sesmand/frdp-sesmand.c:57-62` calls `pam_open_session()` then `pam_end()`; `/frdp-sesmand/frdp-sesmand.c:102-106` starts a new handle for `pam_close_session()`. | PAM session modules may not receive a coherent lifecycle; cleanup hooks can be skipped or misapplied. | Keep the PAM handle/session state for the lifetime of the session or use a designed helper that owns lifecycle explicitly. |
| FRDP-009 | `frdp-sesmand` changes supplementary groups in the parent manager before forking the agent. | 85% | 95% | `/frdp-sesmand/frdp-sesmand.c:65-80` calls `initgroups()` before `fork()` and only then `setgid()`/`setuid()` in the child. | The session manager can inherit user groups and lose predictable privilege boundaries. | Call `initgroups()`, `setgid()`, and `setuid()` only in the child after fork and before exec. |
| FRDP-010 | Session-agent process cleanup is incomplete and can orphan Xvfb. | 70% | 85% | `frdp-session-agent` forks Xvfb at `/frdp-session-agent/frdp-session-agent.c:26-39`; `frdp-sesmand` kills only the agent PID at `/frdp-sesmand/frdp-sesmand.c:98-100`. | Display server children can survive session cleanup. | Run the agent and backend in a process group or systemd scope and terminate the whole scope on logout/disconnect. |
| FRDP-011 | Xvfb display and geometry are hard-coded. | 55% | 100% | `/frdp-session-agent/frdp-session-agent.c:33` uses `:99` and `1024x768x24`. | Concurrent sessions collide and display resize cannot work. | Allocate per-session display numbers and pass display/geometry through session metadata. |
| FRDP-012 | If `Xvfb` exec fails, the child enters an infinite sleep loop and reports no explicit failure. | 65% | 95% | `/frdp-session-agent/frdp-session-agent.c:33-38` falls back to `while (1) sleep(60)`. | Sessions may appear alive without a desktop backend. | Fail fast and report backend startup errors to the session manager. |
| FRDP-013 | No implemented IPC connects `frdpd`, `frdp-authd`, `frdp-sesmand`, and `frdp-session-agent`. | 90% | 95% | Root `/frdpd` comments mention handoff TODOs; integrated `server/frdpd` authenticates directly with PAM and does not invoke standalone daemons. | The intended multi-process architecture is not yet operational. | Define the IPC protocol and wire a single end-to-end path before expanding features. |
| FRDP-014 | Root `/frdpd` handles TLS handshakes synchronously in the accept loop. | 60% | 95% | `/frdpd/frdpd.c:167-193` accepts one client and performs `SSL_accept()` inline. | Slow or malicious clients can block new accepts. | Move clients to worker threads/processes or an event loop with handshake timeouts. |
| FRDP-015 | Client interoperability and AD/SSSD lab validation are not represented by automated tests or checked artifacts. | 65% | 90% | Implementation plan matrix and lab deliverables remain unchecked; no test files were found for these flows. | Build success may hide protocol/lab incompatibilities. | Add documented lab scripts and at least smoke tests for PAM auth, denied users, and client connection attempts. |

## Build observations

- The integrated CMake project builds successfully in `/tmp/opencode/freerdp-current-build`.
- CMake still warns that SDL3 package configuration is unavailable; this is non-blocking because the build falls back to the SDL2 client target.
- The compiler emits existing FreeRDP deprecation warnings unrelated to the new PAM/SSSD/NLA prototype.
