# 06. Implementation plan

## Status convention

Checked items are complete enough to count in the current repository state. For implementation
items, this means the code is integrated into the repository CMake build unless the item explicitly
names a documentation deliverable. Unchecked items may still have standalone prototype code or draft
documentation, but they are not complete MVP behavior.

Current analysis date: 2026-06-15.

Verified commands:

```bash
cmake -S . -B /tmp/opencode/freerdp-current-build -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF
cmake --build /tmp/opencode/freerdp-current-build --target frdpd -j2
cc -fsyntax-only -Wall -Wextra frdp-authd/frdp-authd.c
cc -fsyntax-only -Wall -Wextra frdp-sesmand/frdp-sesmand.c
cc -fsyntax-only -Wall -Wextra frdp-session-agent/frdp-session-agent.c
cc -fsyntax-only -Wall -Wextra frdp-krb-authd/frdp-krb-authd.c
cc -fsyntax-only -Wall -Wextra tools/frdpctl/frdpctl.c
cc -fsyntax-only -Wall -Wextra frdp-authd/frdp-authd.c ipc/frdp-ipc.c
cc -fsyntax-only -Wall -Wextra config/frdp-config.c server/frdpd/frdpd-ipc-demo.c ipc/frdp-ipc.c
```

Implemented in the integrated `server/frdpd` path:

- CMake-gated `frdpd` target under `WITH_FRDPD`;
- FreeRDP listener with one peer worker thread per accepted client;
- TLS certificate/key loading, NLA enabled by default, and opt-in TLS fallback;
- FreeRDP `Logon` callback bridged to password-backed PAM authentication/account checks;
- username/domain normalization for plain, downlevel, UPN, and auto modes;
- optional PAM session open/close tied to the integrated peer lifecycle;
- partial `--config` support for implemented `frdpd.toml` fields (`listen`, `security=nla`, `tls_cert`, `tls_key`, `pam_service`), with CLI overrides;
- `--pam-auth-test` smoke-test mode for the PAM helper path;
- no-op input/update callbacks that keep protocol plumbing in place but do not provide a desktop.

Standalone prototypes that compile syntactically but are not integrated into CMake, IPC, packaging, or
the canonical daemon topology:

- `frdp-authd`;
- `frdp-sesmand`;
- `frdp-session-agent`;
- `frdp-krb-authd`;
- `tools/frdpctl`.

## Phase 0. Discovery and lab

Goal: confirm that the selected FreeRDP server API version is suitable for the MVP.

Deliverables:

- [x] build FreeRDP with server components;
- [x] minimal listener accepting RDP clients through the integrated `server/frdpd` target;
- [x] TLS/NLA server-side configuration path in the integrated `server/frdpd` target;
- [ ] Windows mstsc, Microsoft Remote Desktop, FreeRDP client matrix;
- [ ] AD/SSSD lab with test users and groups;
- [ ] threat model draft.

Exit criteria: a client connects to a stub server, the NLA negotiation path is understood, and the PAM/SSSD lab is reproducible.

## Phase 1. Authentication proof of concept

Deliverables:

- [ ] `frdp-authd` prototype integrated into the build and IPC path (standalone syntax-checkable IPC server exists in `/frdp-authd`, but the integrated daemon does not call it);
- [ ] PAM service `frdpd` installable example;
- [x] password-backed CredSSP -> PAM flow in `server/frdpd`;
- [x] PAM auth/account smoke-test CLI in `server/frdpd` (`--pam-auth-test`);
- [ ] NSS/SSSD uid/gid/groups lookup integrated with the authenticated session path (standalone prototypes perform limited lookup/group setup only);
- [ ] audit events with correlation id integrated with the authenticated session path (standalone `frdp-authd` emits local audit events only);
- [ ] secret zeroization and no-core settings across all auth/session processes (partial zeroization in `server/frdpd`; standalone `frdp-authd` disables core dumps and hard-fails on `mlock()` failure but is not integrated).

Exit criteria: a domain user can authenticate through NLA/PAM; a denied user receives a clean failure; no desktop resources are allocated before authentication succeeds.

## Phase 2. Session manager MVP

Deliverables:

- [ ] `frdp-sesmand` process integrated into the build and daemon topology (standalone syntax-checkable source exists in `/frdp-sesmand`);
- [ ] session registry integrated with authenticated RDP peers (standalone in-memory demo registry exists only in `/frdp-sesmand`);
- [x] PAM session lifecycle in the integrated `server/frdpd` peer path;
- [ ] logind/cgroup integration;
- [ ] headless Xorg/Xvfb launch integrated with `frdpd` sessions (standalone `frdp-session-agent` launches Xvfb only when run through the standalone demo path);
- [ ] simple reconnect by user/session id;
- [ ] cleanup on disconnect/logout across agent process groups and PAM sessions (standalone process-group cleanup exists; canonical `server/frdpd` only closes PAM state).

Exit criteria: the user receives a desktop session after successful authentication; reconnect works in a controlled scenario; logout cleans processes and runtime state.

## Phase 3. Desktop data path and channels

Deliverables:

- [ ] framebuffer/damage capture;
- [ ] basic encoder scheduling;
- [ ] keyboard/mouse input (integrated callbacks are currently no-op placeholders);
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
- [ ] SELinux/AppArmor profiles (draft files exist under `packaging/selinux` and `packaging/apparmor`, not validated);
- [ ] systemd hardening (draft `packaging/systemd/frdpd.service` exists, not installed or validated as part of packages);
- [ ] package signing and reproducible-build notes.

Exit criteria: the security baseline is accepted; no critical crashes are found during the fuzz/load-test window; packages install cleanly on target operating systems.

## Phase 6. Pilot and GA

Deliverables:

- [ ] deb/rpm packages (draft packaging files exist, but helper binaries/config/systemd installation are not build-verified);
- [ ] admin CLI `frdpctl` (standalone stub exists, not integrated with CMake or session IPC);
- [x] configuration reference, example, and partial parser integration for implemented daemon fields (`10-configuration-reference.md`, `config/frdpd.toml`);
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
