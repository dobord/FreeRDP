# 06. Implementation plan

## Phase 0. Discovery and lab

Goal: confirm that the selected FreeRDP server API version is suitable for the MVP.

Deliverables:

- build FreeRDP with server components;
- minimal listener accepting RDP clients;
- TLS/NLA capability check;
- Windows mstsc, Microsoft Remote Desktop, FreeRDP client matrix;
- AD/SSSD lab with test users and groups;
- threat model draft.

Exit criteria: a client connects to a stub server, the NLA negotiation path is understood, and the PAM/SSSD lab is reproducible.

## Phase 1. Authentication proof of concept

Deliverables:

- `frdp-authd` prototype;
- PAM service `frdpd`;
- password-backed CredSSP -> PAM flow;
- NSS/SSSD uid/gid/groups lookup;
- audit events with correlation id;
- secret zeroization and no-core settings.

Exit criteria: a domain user can authenticate through NLA/PAM; a denied user receives a clean failure; no desktop resources are allocated before authentication succeeds.

## Phase 2. Session manager MVP

Deliverables:

- `frdp-sesmand` process;
- session registry;
- PAM session lifecycle;
- logind/cgroup integration;
- headless Xorg/Xvfb launch;
- simple reconnect by user/session id;
- cleanup on disconnect/logout.

Exit criteria: the user receives a desktop session after successful authentication; reconnect works in a controlled scenario; logout cleans processes and runtime state.

## Phase 3. Desktop data path and channels

Deliverables:

- framebuffer/damage capture;
- basic encoder scheduling;
- keyboard/mouse input;
- display resize;
- text clipboard;
- baseline audio output;
- channel policy engine.

Exit criteria: daily interactive desktop use is possible in the lab with Windows and FreeRDP clients.

## Phase 4. Kerberos-first production authentication

Deliverables:

- SPN/keytab provisioning guide;
- GSSAPI/Kerberos acceptor path;
- principal -> POSIX account mapping;
- PAM account/session without a password where approved;
- NTLM fallback feature flag;
- security review of credential delegation assumptions.

Exit criteria: a domain-joined Windows client authenticates with Kerberos where possible; the NTLM-disabled test passes; account restrictions are enforced by SSSD/PAM.

## Phase 5. Hardening and test automation

Deliverables:

- ASAN/UBSAN builds;
- fuzzing harnesses for channel parsers and selected RDP inputs;
- protocol regression suite;
- load testing harness;
- SELinux/AppArmor profiles;
- systemd hardening;
- package signing and reproducible-build notes.

Exit criteria: the security baseline is accepted; no critical crashes are found during the fuzz/load-test window; packages install cleanly on target operating systems.

## Phase 6. Pilot and GA

Deliverables:

- deb/rpm packages;
- admin CLI `frdpctl`;
- configuration reference;
- runbooks for AD join, keytab rotation, and troubleshooting;
- dashboards and alert rules;
- migration/fallback plan to xrdp;
- GA support matrix.

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

## Milestone estimate

- Lab and authentication POC: 4-6 weeks.
- MVP desktop server: 8-12 weeks.
- Enterprise authentication and hardening: 8-12 weeks.
- Pilot readiness: 6-10 weeks.

These estimates assume 2-4 engineers with C/Linux/PAM/Kerberos/RDP experience.
