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

- Build fuzz targets for individual message parsers in `server/frdp/frdpd`, IPC/auth helpers, and channel modules. Use `BUILD_FUZZERS=ON` with Clang to link against LibFuzzer. The first focused targets are `TestFuzzFreeRDPFrdpConfig`, which feeds arbitrary TOML into `frdp_config_load` and exercises static/dynamic channel policy checks from successfully parsed inputs; `TestFuzzFreeRDPFrdpAuthToken`, which feeds arbitrary token strings into the auth-token verifier while also smoke-covering a generated valid-token path; `TestFuzzFreeRDPFrdpFramePolicy`, which feeds agent frame-response metadata and frame-pump budget values into the `frdpd` framebuffer policy helpers; and `TestFuzzFreeRDPFrdpInputPolicy`, which feeds raw and structured agent input events into the session-agent input policy helper.
- Seed the corpus with captured protocol packets.
- Run the fuzzers in CI to detect crashes.

For network-level fuzzing, integrate with AFL or clusterfuzz to generate malformed RDP streams.

## Protocol regression suite

Develop a regression suite that uses `xfreerdp` and `mstsc` clients to exercise supported features:

- Automated scripts to connect, authenticate via Kerberos/PAM, create sessions, transfer clipboard text, audio and files.
- Verify reconnect, session timeouts and denial of forbidden channels.
- Capture and compare framebuffers to detect rendering regressions.

Use containers or virtual machines in CI to run these tests.

## Load testing harness

Create a harness that spawns multiple RDP clients concurrently to measure CPU, memory and network usage:

- Use `xfreerdp` or a custom client to create N concurrent sessions.
- Monitor server metrics (CPU, memory, sessions, threads) and record throughput.
- Use these metrics to set defaults for `max_connections`, session limits and per-session resource quotas.

## SELinux/AppArmor profiles

Write mandatory access control profiles to confine the RDP daemons:

- Define a minimal policy allowing network listening on port 3389, access to `/etc/frdpd` for keys and configuration, execution of `/usr/bin/Xvfb` and reading user home directories.
- Deny access to arbitrary files and prevent the daemon from loading untrusted modules.
- Distribute example policies for both SELinux (`frdpd.te` and `frdpd.fc`) and AppArmor (`frdpd` profile) in `packaging/selinux` and `packaging/apparmor`.

## Systemd hardening

Supply hardened unit files similar to:

```
[Unit]
Description=FreeRDP PAM/SSSD/NLA Server
After=network.target

[Service]
ExecStart=/usr/bin/frdpd
User=root
Group=root
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
NoNewPrivileges=true
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
AmbientCapabilities=CAP_NET_BIND_SERVICE
LimitNOFILE=1024
TimeoutStopSec=30s

[Install]
WantedBy=multi-user.target
```

These directives drop unnecessary privileges and isolate the process.

## Package signing and reproducible builds

To ensure supply‑chain integrity:

- Use `debsig-verify` or rpm GPG signatures to sign packages. Provide the public key via the project’s packaging repository.
- Document build steps to achieve reproducibility: pinned toolchain versions, deterministic timestamps (`SOURCE_DATE_EPOCH`) and sanitised build environment.
