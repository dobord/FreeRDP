# 06. Implementation plan

## Status convention

Checked items are complete enough to count in the current repository state. For implementation
items, this means the code is integrated into the repository CMake build unless the item explicitly
names a documentation deliverable. Unchecked items may still have standalone prototype code or draft
documentation, but they are not complete MVP behavior.

Current analysis date: 2026-06-16.

Verified commands:

```bash
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF
cmake --build /tmp/opencode/freerdp-current-build --target frdpd frdp-authd frdp-sesmand frdp-session-agent frdpd-ipc-demo frdpctl frdp-krb-authd -j2
cmake --build /tmp/opencode/freerdp-current-build --target frdpd frdp-authd frdpd-ipc-demo -j2
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_SERVER=ON -DWITH_FRDPD=ON -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF
cmake --build /tmp/opencode/freerdp-current-build --target frdpd frdp-sesmand frdp-session-agent -j2
cmake -S . -B /tmp/opencode/freerdp-frdp-install-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF -DWITH_SHADOW=OFF -DWITH_PROXY=OFF
cmake --build /tmp/opencode/freerdp-frdp-install-build --target frdpd frdp-authd frdp-sesmand frdp-session-agent frdpctl frdp-krb-authd -j2
cmake --install /tmp/opencode/freerdp-frdp-install-build --component server --prefix /tmp/opencode/freerdp-install-frdp
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-authd/frdp-authd.c server/frdp/ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-sesmand/frdp-sesmand.c server/frdp/ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra server/frdp/frdp-session-agent/frdp-session-agent.c
cc -fsyntax-only -Wall -Wextra server/frdp/config/frdp-config.c server/frdp/frdpd/frdpd-ipc-demo.c server/frdp/ipc/frdp-ipc.c
# frdp-authd IPC negative-path smoke: frdpd-ipc-demo returns Authentication result: failure for invalid credentials.
# frdp-sesmand IPC startup smoke: --socket creates a 0600 Unix socket in a 0700 runtime directory.
```

Implemented in the integrated `server/frdp/frdpd` path:

- CMake-gated `frdpd` target under `WITH_FRDPD`;
- installable dedicated PAM service example `server/frdp/pam/frdpd`;
- FreeRDP listener with one peer worker thread per accepted client;
- TLS certificate/key loading, NLA enabled by default, and opt-in TLS fallback;
- FreeRDP `Logon` callback bridged to password-backed PAM authentication/account checks;
- username/domain normalization for plain, downlevel, UPN, and auto modes;
- optional PAM session open/close tied to the integrated peer lifecycle;
- PAM credential establish/delete tied to the integrated authentication/session lifecycle;
- partial `--config` support for implemented `frdpd.toml` fields (`listen`, `security=nla`, `tls_cert`, `tls_key`, `pam_service`), with CLI overrides;
- optional `auth_socket` configuration and `--auth-socket=<path>` CLI override for routing password-backed auth/account checks through `frdp-authd` IPC when PAM session opening is disabled;
- optional `session_socket` configuration and `--session-socket=<path>` CLI override for opening and closing `frdp-sesmand` sessions over IPC when PAM session opening is disabled;
- shared IPC client operations use bounded socket send/receive timeouts and suppress `SIGPIPE` on disconnected peers;
- per-peer correlation ids on integrated `frdpd` accept/auth/logon/activate/disconnect logs, propagated to optional `frdp-authd` auth/account IPC audit events;
- session ids and correlation ids propagated through optional `frdp-sesmand` session IPC into `frdp-session-agent` startup/exit logs;
- `frdp-session-agent` verifies Xvfb `exec()`, X display open, and XTest availability before reporting agent readiness to `frdp-sesmand`;
- optional `frdp-sesmand` session IPC creates a root-owned per-session agent control socket and returns it to `frdpd` for keyboard/mouse event forwarding into the session agent;
- optional `frdp-sesmand` session IPC performs POSIX account lookup, child `initgroups()`/uid/gid drop, PAM session ownership, and agent process-group cleanup for managed sessions;
- `--pam-auth-test` smoke-test mode for the PAM helper path;
- process-level core dump disabling before credential handling;
- a minimal raw-tile framebuffer pump from `frdp-session-agent` to `frdpd` using FreeRDP bitmap updates, with XDamage-backed dirty/clean-tile responses, per-peer unchanged-tile suppression, and cache invalidation for refresh/suppress-output requests.

CMake-built helper binaries/prototypes that are not yet the default canonical runtime topology:

- `server/frdp/frdp-authd` (optional auth/account IPC path);
- `server/frdp/frdp-sesmand` (optional session IPC path);
- `server/frdp/frdp-session-agent` (launched by optional `frdp-sesmand` session requests; keyboard/mouse backend injection and raw framebuffer tile capture with XDamage-backed dirty-tile tracking exist, but compression, resize, and Unicode/text input are not implemented yet);
- `server/frdp/frdp-krb-authd` (build-only prototype, not installed by default);
- `tools/frdpctl`.

## Phase 0. Discovery and lab

Goal: confirm that the selected FreeRDP server API version is suitable for the MVP.

Deliverables:

- [x] build FreeRDP with server components;
- [x] minimal listener accepting RDP clients through the integrated `server/frdp/frdpd` target;
- [x] TLS/NLA server-side configuration path in the integrated `server/frdp/frdpd` target;
- [ ] Windows mstsc, Microsoft Remote Desktop, FreeRDP client matrix;
- [ ] AD/SSSD lab with test users and groups;
- [ ] threat model draft.

Exit criteria: a client connects to a stub server, the NLA negotiation path is understood, and the PAM/SSSD lab is reproducible.

## Phase 1. Authentication proof of concept

Deliverables:

- [x] `frdp-authd` helper target and local IPC server build under `WITH_FRDPD`;
- [x] optional integrated `server/frdp/frdpd` authentication/account check through `frdp-authd` IPC via absolute `auth_socket` with `--no-pam-session` when the session path is delegated;
- [ ] make `frdp-authd` the canonical/default auth path and remove in-process PAM auth from the peer worker;
- [x] PAM service `frdpd` installable example;
- [x] password-backed CredSSP -> PAM flow in `server/frdp/frdpd`;
- [x] PAM auth/account smoke-test CLI in `server/frdp/frdpd` (`--pam-auth-test`);
- [x] PAM credential establish/delete lifecycle in the integrated `server/frdp/frdpd` path;
- [x] NSS/SSSD uid/gid/groups lookup integrated with the authenticated session path (optional `frdp-sesmand` session IPC performs `getpwnam()`, `initgroups()`, and uid/gid drop before launching the agent);
- [x] audit events with correlation id integrated with the authenticated auth/session/agent path (channels and structured audit config are tracked separately);
- [x] fail-closed core dump/non-dumpable hardening in `server/frdp/frdpd`, `server/frdp/frdp-authd`, and `server/frdp/frdp-sesmand`;
- [ ] locked secret buffers and brokerized credential handling across the integrated auth/session path (partial locked-buffer handling exists only in standalone `frdp-authd`, which is not integrated).

Exit criteria: a domain user can authenticate through NLA/PAM; a denied user receives a clean failure; no desktop resources are allocated before authentication succeeds.

## Phase 2. Session manager MVP

Deliverables:

- [x] `frdp-sesmand` and `frdp-session-agent` helper targets build under `WITH_FRDPD`;
- [x] optional `frdp-sesmand` process integration through `frdpd --session-socket=<path>` / `[session].session_socket` with `--no-pam-session`;
- [x] session registry receives authenticated RDP peer open/close requests on the optional `session_socket` IPC path;
- [x] PAM session lifecycle in the integrated `server/frdp/frdpd` peer path;
- [x] standalone development `frdp-sesmand --open-session <user>` path performs PAM account, credential, session, process-group, and cleanup handling behind an explicit opt-in guard;
- [ ] logind/cgroup integration;
- [x] headless Xvfb launch integrated with optional `frdpd -> frdp-sesmand -> frdp-session-agent` session requests, including fail-closed backend `exec()`, X display, and XTest readiness checks;
- [ ] simple reconnect by user/session id;
- [x] cleanup on disconnect across `frdp-sesmand` agent process groups and PAM sessions (optional `session_socket` close requests terminate the agent process group and close PAM state; durable cleanup after prolonged `frdp-sesmand` outage remains tracked separately).

Exit criteria: the user receives a desktop session after successful authentication; reconnect works in a controlled scenario; logout cleans processes and runtime state.

## Phase 3. Desktop data path and channels

Deliverables:

- [x] framebuffer/damage capture (prototype: raw framebuffer tiles can be pulled from the agent and sent as bitmap updates, the agent can use XDamage to select dirty tiles or report clean tiles, and unchanged tiles are suppressed with per-peer hashes; compression and encoder scheduling are tracked separately);
- [x] minimal raw framebuffer tile transport from the managed session agent to FreeRDP bitmap updates;
- [ ] basic encoder scheduling;
- [x] keyboard/mouse input (partial: integrated callbacks forward input over optional agent control IPC and the agent injects scancode keyboard plus mouse events through XTest; Unicode/text input is not implemented yet);
- [ ] display resize;
- [ ] text clipboard;
- [ ] baseline audio output;
- [ ] channel policy engine.

Exit criteria: daily interactive desktop use is possible in the lab with Windows and FreeRDP clients.

## Phase 4. Kerberos-first production authentication

Deliverables:

- [x] SPN/keytab provisioning guide (`07-kerberos-guide.md`);
- [ ] GSSAPI/Kerberos acceptor path (standalone `frdp-krb-authd` skeleton exists but does not decode/use real CredSSP SPNEGO tokens);
- [ ] principal -> POSIX account mapping (standalone skeleton attempts raw `getpwnam()` on the displayed principal only);
- [ ] PAM account/session without a password where approved;
- [ ] NTLM fallback feature flag;
- [ ] security review of credential delegation assumptions.

Exit criteria: a domain-joined Windows client authenticates with Kerberos where possible; the NTLM-disabled test passes; account restrictions are enforced by SSSD/PAM.

## Phase 5. Hardening and test automation

Deliverables:

- [ ] ASAN/UBSAN builds;
- [ ] fuzzing harnesses for channel parsers and selected RDP inputs;
- [ ] protocol regression suite;
- [ ] load testing harness;
- [ ] SELinux/AppArmor profiles (draft examples install under `/usr/share/frdpd/security`, but are not validated or activated);
- [ ] systemd hardening (listener/auth/session unit examples install, but package builds and production hardening validation remain open);
- [ ] package signing and reproducible-build notes.

Exit criteria: the security baseline is accepted; no critical crashes are found during the fuzz/load-test window; packages install cleanly on target operating systems.

## Phase 6. Pilot and GA

Deliverables:

- [x] CMake install rules for FRDP runtime helper binaries, `frdpd.toml`, PAM service, systemd unit examples, and inactive MAC policy examples verified with the `server` component in an isolated build;
- [ ] deb/rpm packages (draft packaging files exist, RPM CMake flags are aligned with `WITH_FRDPD`, but actual package builds are not verified);
- [x] admin CLI `frdpctl` stub builds and installs under `WITH_FRDPD`;
- [ ] admin CLI `frdpctl` session IPC operations;
- [x] configuration reference, example, and partial parser integration for implemented daemon fields (`10-configuration-reference.md`, `server/frdp/config/frdpd.toml`);
- [x] runbooks for AD join, keytab rotation, and troubleshooting (`09-runbooks.md`);
- [ ] dashboards and alert rules;
- [x] migration/fallback plan to xrdp (basic documented fallback in `09-runbooks.md`; rollback testing remains part of exit criteria);
- [ ] GA support matrix (draft support notes exist only in documentation).

Exit criteria: pilot users complete acceptance scenarios; rollback is tested; the operations team can install, diagnose, and upgrade without developer assistance.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| FreeRDP server API instability | High | pin version, upstream tracking, compatibility layer |
| CredSSP/Kerberos interoperability issues | High | client matrix, packet-level regression, strict SPN tests |
| PAM prompts incompatible with NLA UX | Medium | constrain MVP to password flow, separate MFA design |
| Desktop backend complexity | High | start with Xorg/Xvfb, defer Wayland |
| Redirection data exfiltration | High | deny-by-default policy and audit |
| Performance under browser/video workload | Medium | codec tuning, resource limits, load tests |
| Prototype drift outside the canonical daemon path | High | either integrate prototypes into CMake/IPC or retire them quickly |
| Packaging/documentation ahead of executable behavior | Medium | verify packages in CI and label draft-only material explicitly |

## Milestone estimate

- Lab and authentication POC: 4-6 weeks.
- MVP desktop server: 8-12 weeks.
- Enterprise authentication and hardening: 8-12 weeks.
- Pilot readiness: 6-10 weeks.

These estimates assume 2-4 engineers with C/Linux/PAM/Kerberos/RDP experience.
