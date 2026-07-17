# 08. Hardening and test automation

This document outlines the hardening measures and test automation required for phase 5 of the implementation plan.

## ASAN/UBSAN builds

To detect memory corruption and undefined behaviour, build the project with Clang or GCC and enable the
address and undefined-behaviour sanitizers:

```bash
cmake -S . -B /tmp/freerdp-frdp-asan-ubsan \
  -DWITH_FRDPD=ON \
  -DWITH_SERVER=ON \
  -DWITH_SAMPLE=OFF \
  -DBUILD_TESTING=ON \
  -DWITH_SANITIZE_ADDRESS=ON \
  -DWITH_SANITIZE_UNDEFINED=ON
cmake --build /tmp/freerdp-frdp-asan-ubsan --target TestFreeRDPFrdp -j"$(nproc)"
mkdir -p /tmp/freerdp-frdp-asan-ubsan/sanitizer-logs
ASAN_OPTIONS=detect_leaks=1:halt_on_error=1:allocator_may_return_null=1:log_path=/tmp/freerdp-frdp-asan-ubsan/sanitizer-logs/asan LSAN_OPTIONS=print_suppressions=0:log_path=/tmp/freerdp-frdp-asan-ubsan/sanitizer-logs/lsan UBSAN_OPTIONS=halt_on_error=1:print_stacktrace=1:log_path=/tmp/freerdp-frdp-asan-ubsan/sanitizer-logs/ubsan ctest --test-dir /tmp/freerdp-frdp-asan-ubsan -R '^TestFreeRDPFrdp' --output-on-failure
```

These flags add `-fsanitize=address` and `-fsanitize=undefined` and link against the sanitizer
runtimes. Run the sanitised binaries in a dedicated environment; the sanitiser will abort on memory
errors and print a report. The explicit runtime options enable leak detection, fail fast on sanitizer
findings, and write sanitizer logs under `sanitizer-logs/` for CI artifact upload. Leave sanitizer
options disabled in production builds.

## Strict warning builds

The focused FRDP daemon, helper and test targets can be built with warnings treated as errors:

```bash
cmake -S . -B /tmp/freerdp-frdp-warnings -GNinja \
  -DCMAKE_BUILD_TYPE=RelWithDebInfo \
  -DCMAKE_C_COMPILER=clang \
  -DBUILD_TESTING=ON \
  -DWITH_FRDPD=ON \
  -DWITH_SERVER=ON \
  -DWITH_SHADOW=OFF \
  -DWITH_PROXY=OFF \
  -DWITH_SAMPLE=OFF \
  -DWITH_MANPAGES=OFF \
  -DWITH_WAYLAND=OFF \
  -DWITH_SDL=OFF \
  -DWITH_PULSE=OFF \
  -DWITH_ALSA=OFF \
  -DWITH_CUPS=OFF \
  -DWITH_PCSC=OFF \
  -DWITH_FFMPEG=OFF \
  -DWITH_SWSCALE=OFF \
  -DWITH_FUSE=OFF \
  -DWITH_OPENCL=OFF \
  -DCHANNEL_URBDRC=OFF \
  -DWITH_FRDPD_STRICT_WARNINGS=ON
cmake --build /tmp/freerdp-frdp-warnings --target TestFreeRDPFrdp
ctest --test-dir /tmp/freerdp-frdp-warnings -R '^TestFreeRDPFrdp' --output-on-failure
```

This opt-in gate applies to the FRDP build/test surface only; broader FreeRDP warning cleanup remains
tracked separately from the PAM/SSSD/NLA prototype.

## Fuzzing harnesses

Fuzz key protocol parsers and RDP channel handlers using LibFuzzer:

- Build fuzz targets for individual message parsers in `server/frdp/frdpd`, IPC/auth helpers, and channel modules. Use `BUILD_FUZZERS=ON` with Clang and enable ASan/UBSan so LibFuzzer detects memory and undefined-behavior faults in addition to process crashes. Focused targets include `TestFuzzFreeRDPFrdpConfig`, which feeds arbitrary TOML into `frdp_config_load` and exercises static/dynamic channel policy checks from successfully parsed inputs; `TestFuzzFreeRDPFrdpAuthToken`, which feeds arbitrary token strings into the auth-token verifier while also smoke-covering a generated valid-token path; `TestFuzzFreeRDPFrdpNtlmIdentity`, which exercises bounded NTLM proof binding against length-counted ANSI/Unicode delegated identities in every domain mode; `TestFuzzFreeRDPFrdpFramePolicy`, which feeds agent frame-response metadata and frame-pump budget values into the `frdpd` framebuffer policy helpers; and `TestFuzzFreeRDPFrdpInputPolicy`, which feeds raw and structured agent input events into the session-agent input policy helper.
- Seed the corpus with captured protocol packets.
- Run the fuzzers in CI to detect crashes.

For network-level fuzzing, integrate with AFL or clusterfuzz to generate malformed RDP streams.

## Protocol regression suite

Develop a regression suite that uses `xfreerdp` and `mstsc` clients to exercise supported features:

- `server/frdp/test/e2e/scripts/rdp-protocol-regression.sh` is the first retained-client
  probe. It runs auth-only NLA checks across a small geometry, color-depth and network-profile
  option matrix and preserves per-case logs under the configured artifact directory.
- Automated scripts to connect, authenticate via Kerberos/PAM, create sessions, transfer clipboard text, audio and files.
- Verify reconnect, session timeouts and denial of forbidden channels.
- Capture and compare framebuffers to detect rendering regressions.

Use containers or virtual machines in CI to run these tests.

## Load testing harness

Create a harness that spawns multiple RDP clients concurrently to measure CPU, memory and network usage:

- Use `xfreerdp` or a custom client to create N concurrent sessions.
- Monitor server metrics (CPU, memory, sessions, threads) and record throughput.
- Use these metrics to set defaults for `max_connections`, session limits and per-session resource quotas.

The deterministic local-PAM Compose gate currently opens two graphical
`xfreerdp` clients concurrently and proves unique session ids, displays and
agent PIDs. With `max_sessions = 2`, a third fully authenticated client is
denied before PAM session open while the two held sessions remain unchanged;
the gate then proves complete detach/cleanup. The separate retained-client load
script covers configurable parallel auth-only iterations. Neither gate yet
records CPU, RSS, network throughput, long-soak stability or memory growth.

## SELinux/AppArmor profiles

Write mandatory access control profiles to confine the RDP daemons:

- Define a minimal policy allowing network listening on port 3389, access to `/etc/frdpd` for keys and configuration, execution of `/usr/bin/Xvfb` and the distro raw Xorg server, read access to `/usr/share/frdpd/xorg-dummy.conf`, and only the required user-session resources. Keep the Xorg path aligned with the root-owned path configured in `frdpd.toml`.
- Deny access to arbitrary files and prevent the daemon from loading untrusted modules.
- Distribute example policies for both SELinux (`frdpd.te` and `frdpd.fc`) and AppArmor (`frdpd` profile) in `packaging/selinux` and `packaging/apparmor`; the SELinux policy is compiled/packaged in CTest when `checkmodule` and `semodule_package` are available, and the AppArmor profile is parser-validated when `apparmor_parser` is available, while activation and production confinement review remain open.

## Systemd hardening

The package ships focused systemd units under `packaging/systemd` and installs
them with the server component. `frdpd.service` requires the auth and session
helper units, and `TestFreeRDPFrdpSystemd` validates both `systemd-analyze
verify` and the expected sandboxing contract.

The listener unit keeps the bind-capable strict baseline:

```
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectKernelLogs=true
ProtectClock=true
ProtectHostname=true
ProtectControlGroups=true
RestrictRealtime=true
RestrictSUIDSGID=true
SystemCallArchitectures=native
LockPersonality=true
MemoryDenyWriteExecute=true
UMask=0077
LimitNOFILE=1024
```

The auth broker uses the same strict sandboxing baseline without bind-service
capabilities, and adds `RuntimeDirectory=frdp-authd` with write access limited
to `/run/frdp-authd` and `/run/frdp-auth-token`.

`frdp-sesmand.service` uses a narrower baseline that still accounts for PAM,
logind, user session startup, and runtime-directory responsibilities:
`PrivateTmp=true`, `ProtectSystem=full`, kernel/log/clock/hostname/realtime/personality
restrictions, `SystemCallArchitectures=native`, and explicit write access only
to `/run/frdp-sesmand` plus `/run/frdp-auth-token`. It also sets
`TasksMax=4096` as a coarse daemon-wide process-count guard. Per-session
`frdp-session-agent` launches can also receive configured POSIX
`RLIMIT_NPROC` and `RLIMIT_AS` guards. Optional fail-closed transient
per-session scopes add cgroup process ownership, accounting, `TasksMax`,
`MemoryMax`, and CPU capacity through `CPUQuotaPerSecUSec`; a
root/systemd-gated test verifies D-Bus reconnection, confirmed unit activation,
finite and unlimited property updates, the cgroup of both the agent and a
detached descendant, metadata-driven restart cleanup, and unit collection.
Config reload updates all existing scoped sessions as a rollback-protected
batch; inability to restore the previous limits stops the manager for normal
session cleanup. Per-session PAM owners retain `pam_handle_t` across a manager
crash, authenticate same-UID control peers on root-only `SOCK_SEQPACKET`
endpoints, monitor manager and agent pidfds, and persist a synchronized close
receipt. A failed close is persisted separately and never accepted as a receipt;
an endpoint without either proof remains an uncertainty. Metadata V3 recovery fails closed unless close is confirmed; startup
removes only inode-matched stale endpoints after metadata reconciliation. A
provisional `STARTING` record binds artifact ownership before `fork()`, then is
atomically replaced with PID/start-time identity while the child remains behind
the launch barrier. The complete process group is held stopped while the owner
applies TERM grace and KILL escalation, so a descendant cannot destroy the pidfd
anchor. Receipt-backed orphan socket cleanup and PID/start-time
display-reservation reconciliation cover the earlier artifact-creation window.
The close receipt is consumed only after artifact plus metadata removal succeeds.
systemd-logind registration and an individual per-session runtime quota API
remain open.

## Package signing and reproducible builds

To ensure supply‑chain integrity:

- Use `debsig-verify` or rpm GPG signatures to sign packages. Provide the public key via the project’s packaging repository.
- Document build steps to achieve reproducibility: pinned toolchain versions, deterministic timestamps (`SOURCE_DATE_EPOCH`) and sanitised build environment.
