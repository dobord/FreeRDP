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
DEB_BUILD_OPTIONS='nocheck parallel=1' dpkg-buildpackage -uc -us -b -j1
# Debian package smoke: frdpd_0.1.0-1_amd64.deb contains FRDP binaries, required FreeRDP/WinPR libraries, /etc/frdpd, PAM, systemd units, and inactive MAC policy examples.
cmake -S . -B /tmp/opencode/freerdp-frdp-asan-ubsan -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SAMPLE=OFF -DBUILD_TESTING=ON -DWITH_SANITIZE_ADDRESS=ON -DWITH_SANITIZE_UNDEFINED=ON
cmake --build /tmp/opencode/freerdp-frdp-asan-ubsan --target TestFreeRDPFrdp -j2
mkdir -p /tmp/opencode/freerdp-frdp-asan-ubsan/sanitizer-logs
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:allocator_may_return_null=1:log_path=/tmp/opencode/freerdp-frdp-asan-ubsan/sanitizer-logs/asan LSAN_OPTIONS=print_suppressions=0:log_path=/tmp/opencode/freerdp-frdp-asan-ubsan/sanitizer-logs/lsan UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:log_path=/tmp/opencode/freerdp-frdp-asan-ubsan/sanitizer-logs/ubsan ctest --test-dir /tmp/opencode/freerdp-frdp-asan-ubsan -R '^TestFreeRDPFrdp' --output-on-failure
cmake -S . -B /tmp/opencode/freerdp-frdp-strict-warnings -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang -DBUILD_TESTING=ON -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SHADOW=OFF -DWITH_PROXY=OFF -DWITH_SAMPLE=OFF -DWITH_MANPAGES=OFF -DWITH_WAYLAND=OFF -DWITH_SDL=OFF -DWITH_PULSE=OFF -DWITH_ALSA=OFF -DWITH_CUPS=OFF -DWITH_PCSC=OFF -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_FUSE=OFF -DWITH_OPENCL=OFF -DCHANNEL_URBDRC=OFF -DWITH_FRDPD_STRICT_WARNINGS=ON
cmake --build /tmp/opencode/freerdp-frdp-strict-warnings --target TestFreeRDPFrdp
ctest --test-dir /tmp/opencode/freerdp-frdp-strict-warnings -R '^TestFreeRDPFrdp' --output-on-failure
cmake -S . -B /tmp/opencode/freerdp-frdp-fuzz -GNinja -DCMAKE_BUILD_TYPE=RelWithDebInfo -DCMAKE_C_COMPILER=clang -DCMAKE_CXX_COMPILER=clang++ -DBUILD_FUZZERS=ON -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SHADOW=OFF -DWITH_PROXY=OFF -DWITH_SAMPLE=OFF -DWITH_MANPAGES=OFF -DWITH_WAYLAND=OFF -DWITH_SDL=OFF -DWITH_PULSE=OFF -DWITH_ALSA=OFF -DWITH_CUPS=OFF -DWITH_PCSC=OFF -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_FUSE=OFF -DWITH_OPENCL=OFF -DCHANNEL_URBDRC=OFF
cmake --build /tmp/opencode/freerdp-frdp-fuzz --target TestFuzzFreeRDPFrdpConfig TestFuzzFreeRDPFrdpAuthToken TestFuzzFreeRDPFrdpIpcCodec TestFuzzFreeRDPFrdpFramePolicy TestFuzzFreeRDPFrdpInputPolicy TestFuzzFreeRDPFrdpDisplayPolicy TestFuzzFreeRDPFrdpSessionLifecycle
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpConfig -runs=128 -max_len=1024
printf 'FRDPalice' > /tmp/opencode/frdp-auth-token-fuzz-seed.bin
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpAuthToken /tmp/opencode/frdp-auth-token-fuzz-seed.bin -runs=1
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpAuthToken -runs=32 -max_len=512
printf 'FRDPipc-codec' > /tmp/opencode/frdp-ipc-codec-fuzz-seed.bin
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpIpcCodec /tmp/opencode/frdp-ipc-codec-fuzz-seed.bin -runs=1
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpIpcCodec -runs=32 -max_len=512
printf 'FRDPframe-policy' > /tmp/opencode/frdp-frame-policy-fuzz-seed.bin
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpFramePolicy /tmp/opencode/frdp-frame-policy-fuzz-seed.bin -runs=1
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpFramePolicy -runs=32 -max_len=256
printf 'FRDPinput-policy' > /tmp/opencode/frdp-input-policy-fuzz-seed.bin
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpInputPolicy /tmp/opencode/frdp-input-policy-fuzz-seed.bin -runs=1
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpInputPolicy -runs=32 -max_len=128
printf 'FRDPdisplay-policy' > /tmp/opencode/frdp-display-policy-fuzz-seed.bin
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpDisplayPolicy /tmp/opencode/frdp-display-policy-fuzz-seed.bin -runs=1
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpDisplayPolicy -runs=32 -max_len=128
printf 'FRDPsession-lifecycle' > /tmp/opencode/frdp-session-lifecycle-fuzz-seed.bin
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpSessionLifecycle /tmp/opencode/frdp-session-lifecycle-fuzz-seed.bin -runs=1
/tmp/opencode/freerdp-frdp-fuzz/Testing/TestFuzzFreeRDPFrdpSessionLifecycle -runs=32 -max_len=128
cmake -S . -B /tmp/opencode/freerdp-frdp-systemd-check -GNinja -DWITH_FRDPD=ON -DWITH_SERVER=ON -DWITH_SHADOW=OFF -DWITH_PROXY=OFF -DWITH_SAMPLE=OFF -DWITH_MANPAGES=OFF -DWITH_WAYLAND=OFF -DWITH_SDL=OFF -DWITH_PULSE=OFF -DWITH_ALSA=OFF -DWITH_CUPS=OFF -DWITH_PCSC=OFF -DWITH_FFMPEG=OFF -DWITH_SWSCALE=OFF -DWITH_FUSE=OFF -DWITH_OPENCL=OFF -DCHANNEL_URBDRC=OFF
rm -rf /tmp/opencode/frdp-systemd-root && mkdir -p /tmp/opencode/frdp-systemd-root/etc/systemd/system /tmp/opencode/frdp-systemd-root/usr/local/bin
cp /tmp/opencode/freerdp-frdp-systemd-check/server/frdp/frdpd.service /tmp/opencode/freerdp-frdp-systemd-check/server/frdp/frdp-authd.service /tmp/opencode/freerdp-frdp-systemd-check/server/frdp/frdp-sesmand.service /tmp/opencode/frdp-systemd-root/etc/systemd/system/
touch /tmp/opencode/frdp-systemd-root/usr/local/bin/frdpd /tmp/opencode/frdp-systemd-root/usr/local/bin/frdp-authd /tmp/opencode/frdp-systemd-root/usr/local/bin/frdp-sesmand
chmod 0755 /tmp/opencode/frdp-systemd-root/usr/local/bin/frdpd /tmp/opencode/frdp-systemd-root/usr/local/bin/frdp-authd /tmp/opencode/frdp-systemd-root/usr/local/bin/frdp-sesmand
for unit in sysinit.target basic.target network.target multi-user.target; do printf '[Unit]\nDescription=%s\n' "$unit" > "/tmp/opencode/frdp-systemd-root/etc/systemd/system/$unit"; done
systemd-analyze verify --root=/tmp/opencode/frdp-systemd-root frdpd.service frdp-authd.service frdp-sesmand.service
```

Implemented in the integrated `server/frdp/frdpd` path:

- CMake-gated `frdpd` target under `WITH_FRDPD`;
- installable dedicated PAM service example `server/frdp/pam/frdpd`;
- FreeRDP listener with one peer worker thread per accepted client;
- TLS certificate/key loading, NLA enabled by default, and opt-in TLS fallback;
- FreeRDP `Logon` callback bridged to password-backed PAM authentication/account checks;
- username/domain normalization for plain, downlevel, UPN, and auto modes;
- PAM credential establish/delete tied to the integrated authentication/session lifecycle;
- partial `--config` support for implemented `frdpd.toml` fields (`listen`, `security=nla`, `tls_cert`, `tls_key`, `pam_service`), with CLI overrides;
- canonical `auth_socket` configuration and `--auth-socket=<path>` CLI override for routing password-backed auth/account checks through `frdp-authd` IPC;
- config-driven `frdp-authd --config <path>` helper startup for reading `[auth].pam_service`;
- canonical `session_socket` configuration and `--session-socket=<path>` CLI override for opening and closing `frdp-sesmand` sessions over IPC;
- shared IPC client operations use bounded socket send/receive timeouts, suppress `SIGPIPE` on disconnected peers, and use explicit little-endian/fixed-field wire formats for the common IPC header, auth broker request/response payloads, canonical V3 session-open handoff payload, session close request payload, shared session response payload, session list/reload response payloads, and per-session agent input/frame/resize metadata payloads;
- signed, expiring auth-token handoff for managed session opens; `frdp-authd` issues an HMAC token over a length-prefixed payload after successful auth/account/group lookup, integrated `frdpd` forwards the broker-provided POSIX uid/gid/bounded supplementary-group/account state through `FRDP_IPC_SESSION_REQUEST_V3`, and `frdp-sesmand` verifies the token and consumes its nonce once before opening a session;
- helper listener startup rejects live Unix socket path collisions without unlinking the existing helper socket, while still removing same-node stale sockets;
- per-peer correlation ids on integrated `frdpd` accept/auth/logon/activate/disconnect logs, propagated to `frdp-authd` auth/account IPC audit events;
- session ids and correlation ids propagated through `frdp-sesmand` session IPC into `frdp-session-agent` startup/exit logs;
- `frdp-session-agent` verifies Xvfb `exec()`, X display open, and XTest availability before reporting agent readiness to `frdp-sesmand`;
- `frdp-sesmand` session IPC creates a root-owned per-session agent control socket and returns it to `frdpd` for keyboard/mouse event forwarding into the session agent;
- `frdp-sesmand` session IPC performs POSIX account/group lookup, applies the verified bounded supplementary-group payload with `setgroups()` before uid/gid drop, owns the PAM session, and cleans up agent process groups for managed sessions;
- `--pam-auth-test` smoke-test mode for the PAM helper path;
- process-level core dump disabling before credential handling;
- peer-owned FreeRDP auth identity is zero-freed immediately after `frdpd` copies the brokered authentication result into its own session context;
- a minimal framebuffer pump from `frdp-session-agent` to `frdpd`, with XDamage-backed dirty/clean-tile responses, per-peer unchanged-tile suppression, bounded tile pump scheduling, opportunistic minimum-color-loss/no-subsampling NSCodec `SurfaceBits` for negotiated smaller tiles with raw bitmap fallback, cache invalidation for refresh/suppress-output requests, and XRandR-backed resize requests from RDP monitor layout changes.

CMake-built helper binaries/prototypes in the canonical runtime topology:

- `server/frdp/frdp-authd` (normal auth/account IPC path);
- `server/frdp/frdp-sesmand` (normal session IPC path);
- `server/frdp/frdp-session-agent` (launched by normal `frdp-sesmand` session requests; keyboard/mouse/Unicode BMP text backend injection, raw framebuffer tile capture with XDamage-backed dirty-tile tracking, and XRandR-backed display resize exist, but IME/layout-safe text input and production channel features are not implemented yet);
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
- [x] threat model draft (`13-threat-model.md`; validation gates and final security review remain open).

Exit criteria: a client connects to a stub server, the NLA negotiation path is understood, and the PAM/SSSD lab is reproducible.

## Phase 1. Authentication proof of concept

Deliverables:

- [x] `frdp-authd` helper target and local IPC server build under `WITH_FRDPD`;
- [x] integrated `server/frdp/frdpd` authentication/account check through `frdp-authd` IPC via absolute `auth_socket` in the normal helper topology;
- [x] remove in-process PAM auth/session ownership from the peer-worker runtime; normal startup requires `frdp-authd`/`frdp-sesmand`, and the old direct PAM fallback build option/CLI path has been removed;
- [x] PAM service `frdpd` installable example;
- [x] password-backed CredSSP -> PAM flow in `server/frdp/frdpd`;
- [x] PAM auth/account smoke-test CLI in `server/frdp/frdpd` (`--pam-auth-test`);
- [x] PAM credential establish/delete lifecycle in the integrated `server/frdp/frdpd` path;
- [x] NSS/SSSD uid/gid/groups lookup integrated with the authenticated session path (`frdp-authd` looks up bounded supplementary groups, `frdp-sesmand` rechecks them, and the child applies the verified group payload with `setgroups()` before uid/gid drop);
- [x] short-lived signed authorization token binds the normal auth success path to managed session open, including authenticated user, remote host, correlation id, POSIX uid/gid, bounded supplementary groups, account-present state, nonce, and expiry; `frdp-sesmand` rejects legacy V1/V2 session-open requests before body decode and consumes accepted V3 token nonces once;
- [x] audit events with correlation id integrated with the authenticated auth/session/agent path (channels and structured audit config are tracked separately);
- [x] `frdpd` peer/channel/session logs escape client-supplied hostnames, authenticated usernames, static channel names, and IPC-supplied session ids, display names, agent socket paths, and session-manager error strings;
- [x] fail-closed core dump/non-dumpable hardening in `server/frdp/frdpd`, `server/frdp/frdp-authd`, and `server/frdp/frdp-sesmand`;
- [ ] locked secret buffers and brokerized credential handling across the integrated auth/session path (normal startup now uses the auth broker, temporary password copies are locked/wiped, the peer-owned FreeRDP auth identity is cleared after authentication, Remote Credential Guard ticket-logon buffers are wiped before release, and the old direct PAM fallback has been removed; remaining CredSSP internals remain tracked).

Exit criteria: a domain user can authenticate through NLA/PAM; a denied user receives a clean failure; no desktop resources are allocated before authentication succeeds.

## Phase 2. Session manager MVP

Deliverables:

- [x] `frdp-sesmand` and `frdp-session-agent` helper targets build under `WITH_FRDPD`;
- [x] `frdp-sesmand` process integration through `frdpd --session-socket=<path>` / `[session].session_socket` in the normal helper topology;
- [x] session registry receives authenticated RDP peer open/close requests on the `session_socket` IPC path;
- [x] PAM session lifecycle in the integrated `server/frdp/frdpd` peer path;
- [x] standalone development `frdp-sesmand --open-session <user>` path performs PAM account, credential, session, process-group, and cleanup handling behind an explicit opt-in guard;
- [ ] logind/cgroup integration;
- [x] headless Xvfb launch integrated with `frdpd -> frdp-sesmand -> frdp-session-agent` session requests, including fail-closed backend `exec()`, X display, and XTest readiness checks;
- [ ] simple reconnect by user/session id (partial: reconnect-selection policy for matching authenticated users to an explicit session id or the newest disconnected session now has focused CTest coverage; runtime attach/reuse behavior is still not implemented);
- [x] cleanup on disconnect across `frdp-sesmand` agent process groups and PAM sessions (`session_socket` close requests use covered cleanup-decision policy to terminate the agent process group, close PAM state, unlink runtime sockets, release display reservations, and mark the in-memory session state through the `ACTIVE` -> `STOPPING` -> `DEAD` path; durable cleanup after prolonged `frdp-sesmand` outage remains tracked separately).

Exit criteria: the user receives a desktop session after successful authentication; reconnect works in a controlled scenario; logout cleans processes and runtime state.

## Phase 3. Desktop data path and channels

Deliverables:

- [x] framebuffer/damage capture (prototype: raw framebuffer tiles can be pulled from the agent, the agent can use XDamage to select dirty tiles or report clean tiles, and unchanged tiles are suppressed with per-peer hashes);
- [x] minimal raw framebuffer tile transport from the managed session agent to FreeRDP bitmap updates;
- [x] basic framebuffer output scheduling (bounded raw-tile pump budget and shorter peer wait interval; production compression/encoder scheduling remains open);
- [x] opportunistic framebuffer tile compression (partial: `frdpd` advertises and enforces minimum-color-loss/no-subsampling NSCodec and sends `SET_SURFACE_BITS` only when the client negotiated it and the encoded tile is smaller than the raw tile; RFX/RDPGFX and production codec policy remain open);
- [x] keyboard/mouse/text input (partial: integrated callbacks forward input over optional agent control IPC and the agent injects scancode keyboard, Unicode BMP text, and mouse events through XTest/X11; IME/layout-safe text input and supplementary-plane Unicode are not implemented yet);
- [x] display resize (prototype: RDP monitor-layout changes are forwarded to the agent and applied through XRandR before `frdpd` updates peer geometry; the agent control-IPC resize path has focused Xvfb smoke coverage, and the same root-run smoke path now verifies a forced framebuffer tile capture, but real-client runtime interop and resize churn are not covered yet);
- [x] static channel policy engine (`frdpd` filters client-requested static virtual channels during capability processing with configurable blocklist/allowlist modes, defaults to empty blocklist mode, keeps `drdynvc` guard-denied until DVC transport and handlers are explicitly enabled, and has CTest coverage for config parsing plus `CHANNEL_DEF` validation; useful channel handlers remain open);
- [x] preparatory dynamic channel filter parsing and policy helper (`dynamic_mode` plus `dynamic_allow`/`dynamic_deny` support exact-match blocklist/allowlist semantics in config/tests, but useful dynamic-channel handlers remain open);
- [x] server-side WTS dynamic-channel authorization hook and `frdpd` VCM wiring (`frdpd` opens/checks/closes a WTS virtual-channel manager without auto-opening `drdynvc` and installs a policy callback that can deny a server-created DVC before the `CREATE_REQUEST` is sent, with focused core CTest coverage for the runtime deny path; `drdynvc` remains guard-denied and no useful handlers are enabled yet);
- [x] preparatory text clipboard policy parsing (`[clipboard].mode`, `direction`, and `max_text_bytes` fail closed with disabled defaults and focused CTest coverage; runtime `cliprdr` handling is still open);
- [ ] text clipboard;
- [ ] baseline audio output;
- [ ] `drdynvc` transport enablement, useful dynamic channel handlers, and client-interoperability DVC policy tests.

Exit criteria: daily interactive desktop use is possible in the lab with Windows and FreeRDP clients.

## Phase 4. Kerberos-first production authentication

Deliverables:

- [x] SPN/keytab provisioning guide (`07-kerberos-guide.md`);
- [ ] GSSAPI/Kerberos acceptor path (standalone `frdp-krb-authd` skeleton now disables core dumps, selects a keytab, can bind to a configured host-based acceptor name, base64-decodes its token argument before `gss_accept_sec_context()`, and rejects delegated-credential contexts; `frdpd.toml` validates Kerberos identity fields but startup still fails closed for `kerberos = true` because `frdpd` does not extract/pass real CredSSP SPNEGO tokens);
- [ ] principal -> POSIX account mapping (partial: standalone skeleton now rejects service/instance principals, can normalize simple `user@REALM` names before POSIX lookup, and performs bounded supplementary-group lookup after mapping with focused CTest coverage, but SSSD-backed enterprise principal mapping is not integrated with the daemon/session handoff);
- [ ] PAM account/session without a password where approved;
- [x] NTLM fallback feature flag (`ntlm_fallback = false` feeds CredSSP/Negotiate package selection with NTLM disabled and rejects non-Kerberos or unqueryable selected SSPI packages before PAM; full Kerberos identity/session integration remains separate);
- [ ] security review of credential delegation assumptions (partial: standalone helper now rejects `GSS_C_DELEG_FLAG` contexts and releases any delegated credential handle; integrated `frdpd` now rejects unsupported Remote Credential Guard ticket handoff, but the remaining CredSSP/Kerberos delegation policy still needs review).

Exit criteria: a domain-joined Windows client authenticates with Kerberos where possible; the NTLM-disabled test passes; account restrictions are enforced by SSSD/PAM.

## Phase 5. Hardening and test automation

Deliverables:

- [x] ASAN/UBSAN build and focused `server/frdp` CTest suite (`WITH_SANITIZE_ADDRESS=ON` plus `WITH_SANITIZE_UNDEFINED=ON`, with explicit leak detection runtime options), including focused sanitizer and strict-warning CI coverage in the FRDP workflow;
- [x] focused unit/CTest coverage for implemented static/dynamic channel config parsing, filter modes, capability validation, implemented server/auth/session/audit config fields plus fail-closed duplicate/unknown section handling, `max_connections` parsing, enforced `ntlm_fallback` parsing, Kerberos identity field validation with daemon fail-closed startup for enabled Kerberos mode, disabled audit stanza daemon startup acceptance plus enabled audit fail-closed startup, standalone Kerberos no-core hardening, keytab environment selection, acceptor-name import, delegated-credential rejection policy, token decoding, principal normalization and bounded group lookup, `frdpctl` CLI/session-IPC behavior including refusal to use insecure session-manager socket paths, PAM user/domain normalization, PAM status mapping, non-interactive PAM conversation behavior, and deterministic PAM auth/account/session lifecycle branches through a test-only PAM-ops harness, legacy V1/V2 session-open rejection before body decode, invalid V3 auth-token rejection, auth-token uid/gid/group/account-state tamper rejection, POSIX group mismatch rejection with a valid V3 token, delimiter-collision-resistant token serialization, explicit little-endian IPC header encoding, IPC peer-uid lookup, rate-limit primitive, and payload decoder argument validation, explicit auth broker request/response payload encoding, explicit canonical session V3 request/session close/session response payload encoding, explicit session list/reload response payload encoding, malformed reload payload rejection, explicit agent input/frame/resize metadata payload encoding, agent input event type/flag/parameter bounds, in-memory session state transition, cleanup-decision, and reconnect-selection policies, display reservation path/collision/safe-release behavior, systemd unit verification and hardening-directive contract checks when `systemd-analyze` is available, tmpfiles rule validation when `systemd-tmpfiles` is available, monitoring textfile/alert-rule validation when `bash` is available, and live auth/session helper survival after truncated boundary, slow complete, and timed-out incomplete IPC clients across the implemented auth/session/list/reload control families;
- [ ] fuzzing harnesses for channel parsers and selected RDP inputs (partial: focused `TestFuzzFreeRDPFrdpConfig` covers FRDP config parsing plus static/dynamic channel-policy helper inputs, `TestFuzzFreeRDPFrdpAuthToken` covers auth-token parser/verifier inputs, `TestFuzzFreeRDPFrdpIpcCodec` covers explicit IPC wire header/payload decoder boundaries, `TestFuzzFreeRDPFrdpFramePolicy` covers agent frame metadata and pump-budget policy, `TestFuzzFreeRDPFrdpInputPolicy` covers agent input event policy bounds, `TestFuzzFreeRDPFrdpDisplayPolicy` covers display-number and reservation-path policy bounds, and `TestFuzzFreeRDPFrdpSessionLifecycle` covers in-memory session state/cleanup/reconnect policies with CI smoke coverage; broader selected RDP input fuzzing and sustained corpus runs remain open);
- [ ] protocol regression suite (partial: `server/frdp/test/e2e/scripts/rdp-protocol-regression.sh` provides a retained-client auth-only NLA option matrix with per-case logs, `rdp-session-smoke.sh` provides a retained-client graphical session lifecycle probe, and the E2E harness scripts/fixtures have focused syntax/shape validation; broader codec/channel, reconnect, Windows-client, soak, and sustained interop regression coverage remains open);
- [ ] load testing harness (partial: `server/frdp/test/e2e/scripts/rdp-load-probe.sh` provides a configurable parallel auth-only RDP probe for retained E2E client environments, and `rdp-session-smoke.sh` covers one retained graphical lifecycle; full graphical session load/soak coverage remains open);
- [ ] SELinux/AppArmor profiles (draft examples install under `/usr/share/frdpd/security`; the SELinux example has module/package validation when `checkmodule` and `semodule_package` are available, and the AppArmor example has parser validation when `apparmor_parser` is available; activation and production confinement review remain open);
- [ ] systemd hardening (listener/auth/session unit examples install with baseline sandboxing directives, the shared auth-token runtime directory is provided through tmpfiles, and focused unit verify/tmpfiles/hardening-contract validation is available; dependency-checked distro CI and production hardening validation remain open);
- [x] package signing and reproducible-build notes (`11-packaging.md`; real release keys, distro RPM CI, install validation, and repository publication remain open).

Exit criteria: the security baseline is accepted; no critical crashes are found during the fuzz/load-test window; packages install cleanly on target operating systems.

## Phase 6. Pilot and GA

Deliverables:

- [x] CMake install rules for FRDP runtime helper binaries, `frdpd.toml`, PAM service, systemd unit examples, and inactive MAC policy examples verified with the `server` component in an isolated build;
- [x] package previews (root `debian/` metadata supports a verified server-only binary package smoke build with `dpkg-buildpackage`; `packaging/rpm/frdpd.spec` supports a verified server-only `rpmbuild -bb --nodeps` smoke build with local macros, while distro RPM CI and production distro policy verification remain open);
- [x] admin CLI `frdpctl` builds and installs under `WITH_FRDPD`;
- [x] admin CLI `frdpctl status` / `list-sessions` / `kill-session` operations over `frdp-sesmand` session IPC, with local CTest smoke coverage for request/response behavior;
- [x] admin CLI `frdpctl reload` session IPC operation, with local request/response CTest coverage;
- [x] real `frdp-authd --config` startup and `frdp-sesmand --config` reread/apply path behind `frdpctl reload` for PAM service selection;
- [ ] full runtime config reload coverage for listener sockets, TLS material, channel policy, clipboard policy, and helper topology;
- [x] configuration reference, example, and partial parser integration for implemented daemon fields, including `max_connections` and static/dynamic channel filter policy (`10-configuration-reference.md`, `server/frdp/config/frdpd.toml`);
- [x] runbooks for AD join, keytab rotation, and troubleshooting (`09-runbooks.md`);
- [ ] dashboards and alert rules (partial: starter node_exporter textfile collector, Prometheus alert examples, and a Grafana dashboard install under `/usr/share/frdpd/monitoring` with focused CTest validation; native authentication/frame metrics and pilot threshold tuning remain open);
- [x] migration/fallback plan to xrdp (basic documented fallback in `09-runbooks.md`; rollback testing remains part of exit criteria);
- [ ] GA support matrix (partial: `14-support-matrix.md` defines pilot candidates, unsupported capabilities, and required evidence before GA support claims; actual platform/client/package evidence remains open).

Exit criteria: pilot users complete acceptance scenarios; rollback is tested; the operations team can install, diagnose, and upgrade without developer assistance.

## Risks

| Risk | Severity | Mitigation |
|---|---:|---|
| FreeRDP server API instability | High | pin version, upstream tracking, compatibility layer |
| CredSSP/Kerberos interoperability issues | High | client matrix, packet-level regression, strict SPN tests |
| PAM prompts incompatible with NLA UX | Medium | constrain MVP to password flow, separate MFA design |
| Desktop backend complexity | High | start with Xorg/Xvfb, defer Wayland |
| Redirection data exfiltration | High | configurable channel filters, restrictive profiles, and audit |
| Performance under browser/video workload | Medium | codec tuning, resource limits, load tests |
| Prototype drift outside the canonical daemon path | High | either integrate prototypes into CMake/IPC or retire them quickly |
| Packaging/documentation ahead of executable behavior | Medium | verify packages in CI and label draft-only material explicitly |

## Milestone estimate

- Lab and authentication POC: 4-6 weeks.
- MVP desktop server: 8-12 weeks.
- Enterprise authentication and hardening: 8-12 weeks.
- Pilot readiness: 6-10 weeks.

These estimates assume 2-4 engineers with C/Linux/PAM/Kerberos/RDP experience.
