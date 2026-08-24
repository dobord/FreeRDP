# FRDP component and end-to-end tests

This directory contains a Docker Compose testbed for the experimental `server/frdp` stack. It exercises the canonical multi-process topology instead of the in-process PAM fallback:

```text
xfreerdp
  -> TLS + NLA/CredSSP
      -> frdpd
          -> frdp-authd -> PAM -> local identity or SSSD
          -> frdp-sesmand -> PAM session -> frdp-session-agent -> Xorg dummy
```

## Profiles

| Profile | What is real | Assertions |
|---|---|---|
| `component` | Built FRDP binaries and focused CTest suite | Config/channel policy, IPC primitives, `frdpctl`, helper stop handling, malformed requests against real `frdp-authd` and `frdp-sesmand` processes |
| `local` | TLS, NLA/CredSSP, local `pam_unix`, helper IPC, managed Xorg dummy session | Valid authentication succeeds; wrong password and locked account fail; two concurrent graphical clients receive unique sessions, a third is rejected by the session admission cap, and both clean up; a full RDP client exchanges Unicode clipboard text, proves actual `800x600 -> 1024x768 -> 800x600` server-display churn, survives an atomic config-backed peer-limit reduction that rejects another client before PAM without disconnecting it, retains its connection-time channel policy across later `frdpd` `SIGHUP`, survives a graceful `frdpd` restart through stable-session reattach, proves that a CLI peer cap remains authoritative across another config reload, and removes that session |
| `samba` | Provisioned Samba AD DC, DNS/Kerberos/LDAP, `adcli` machine join, `sssd-ad`, enforcing GPO, PAM, RDP | GPO-allowed domain user success, wrong password failure, enabled AD user denied by GPO, NSS user lookup plus supplementary AD-group membership, managed RDP disconnect/reconnect lifecycle, active-session `frdp-sesmand` crash cleanup and fresh post-recovery login/reconnect |
| `freeipa` | Official FreeIPA server, host enrollment/keytab, `sssd-ipa`, HBAC, PAM, RDP | Allowed IPA user success, wrong password failure, valid user denied by HBAC, host-keytab validation and rollover, NSS lookup, managed RDP disconnect/reconnect lifecycle, active-session `frdp-sesmand` crash cleanup and fresh post-recovery login/reconnect |

The FreeIPA profile enrolls `frdpd.ipa.test` with a one-time host password,
requires the expected host principal in a root-only keytab, and runs SSSD with
the IPA identity, authentication and access providers plus Kerberos validation.
It rotates that host principal on the IPA server, requires a higher KVNO,
proves that the enrolled key no longer obtains a ticket, atomically installs
the new root-only keytab, and proves a new host ticket plus subsequent
PAM/SSSD-backed RDP logins.
It disables the default `allow_all` rule and permits only the enabled test user
for the `frdpd` PAM service on that host; a second enabled user proves HBAC
denial independently of password and disabled-account checks.

The Samba profile performs a machine join and uses the SSSD AD provider. It
creates the configurable `FRDP_TEST_GROUP` (`rdp-users` by default), adds the
allowed account, and requires the joined host to resolve that supplementary
group through NSS/SSSD before starting `frdpd`. The DC provisions and links an
enforcing security GPO whose remote-interactive right allows that group and
whose deny right names a second enabled account. SSSD maps the `frdpd` PAM
service to remote-interactive logon, runs in enforcing mode, and must allow the
group member and deny the policy-test account before the RDP probe starts.

The server containers receive `SYS_PTRACE` only so the test harness can copy
the running agent's otherwise unlinked Xauthority into the isolated control
volume for external geometry and clipboard assertions. Production services do
not receive this capability or expose an authority pathname.

## Running

Docker Compose v2 is required. Run from the repository root or this directory:

```bash
bash server/frdp/test/e2e/run.sh component
bash server/frdp/test/e2e/run.sh local
bash server/frdp/test/e2e/run.sh samba
bash server/frdp/test/e2e/run.sh freeipa
```

`all` executes the profiles sequentially:

```bash
bash server/frdp/test/e2e/run.sh all
```

Copy `.env.example` to `.env` to override the isolated test credentials or network addresses. Change the entire static address set together when `172.31.56.0/24` conflicts with a local route.

## Desktop selection

The server image installs exactly one X11 desktop selected at build time with
the `FRDP_DESKTOP_TYPE` Docker build argument. Compose forwards the environment
variable of the same name; `openbox` remains the small, fast default used by
ordinary CI runs.

| Value | Ubuntu package set | Session launcher |
|---|---|---|
| `openbox` | `openbox` | `openbox --sm-disable` |
| `xfce` | `xfce4` | `xfce4-session` |
| `mate` | `mate-desktop-environment-core` | `mate-session` |
| `lxqt` | `lxqt-core`, `openbox` | `startlxqt` |
| `plasma` | `plasma-desktop`, `plasma-workspace`, `kwin-x11` | `startplasma-x11` |
| `gnome` | `gnome-session` | `gnome-session --session=gnome` |

Each session receives its own XDG runtime, configuration, cache and state
directories. The desktop is launched under the authenticated account in a
private D-Bus session; the GNOME image also starts the system bus required by
`gnome-session`. The image records its installed type and rejects a
different runtime override instead of silently starting an incomplete desktop.
These are X11 sessions because the current managed display backend is Xorg
dummy; Wayland desktop sessions are outside this testbed's current scope.

Select a desktop and a distinct image tag when running one profile:

```bash
FRDP_DESKTOP_TYPE=xfce \
FRDP_E2E_IMAGE=frdpd-e2e:xfce \
  bash server/frdp/test/e2e/run.sh local
```

Run the complete real-RDP desktop matrix, or a named subset, with:

```bash
bash server/frdp/test/e2e/run-desktop-matrix.sh
bash server/frdp/test/e2e/run-desktop-matrix.sh xfce plasma gnome
```

Matrix artifacts are retained separately under
`desktop-matrix/<desktop>/artifacts/`. A successful run requires the selected
desktop's window manager, the deterministic `FRDP Test Desktop` marker window,
and a matching root-window type property before clipboard, resize, reconnect
and cleanup assertions continue.

## Manual desktop testing

Do not use `run.sh local` for an interactive session: that command starts the
automated RDP probe and stops the Compose application when the probe finishes.
Instead, build and start only the local FRDP server. Select one of `openbox`,
`xfce`, `mate`, `lxqt`, `plasma`, or `gnome`, and use a matching image tag so
images for different desktops remain unambiguous:

```bash
FRDP_DESKTOP_TYPE=xfce \
FRDP_E2E_IMAGE=frdpd-e2e:xfce \
docker compose \
  -f server/frdp/test/e2e/compose.yaml \
  --profile local \
  up -d --build frdpd-local
```

The desktop process is created only after a successful RDP login. On a Linux
Docker host, connect to the local profile's default static address with the
repository build of `xfreerdp`:

```bash
build-frdp-ntlm-default/client/X11/xfreerdp \
  /v:172.31.56.30 \
  /u:rdpuser \
  /p:'RdpPassw0rd!' \
  /cert:ignore \
  /sec:nla
```

If another build directory or an installed client is used, replace the
`xfreerdp` path accordingly. If `.env` overrides `FRDP_LOCAL_SERVER_IP`, pass
that address to `/v:`. The Compose network does not publish TCP port 3389 on
the host, so direct access to the bridge address is required.

Inspect server health and follow its logs with:

```bash
docker compose -f server/frdp/test/e2e/compose.yaml ps
docker compose -f server/frdp/test/e2e/compose.yaml logs -f frdpd-local
```

After testing, remove the containers, isolated network and session volumes:

```bash
docker compose \
  -f server/frdp/test/e2e/compose.yaml \
  --profile local \
  down --volumes --remove-orphans
```

Set `FRDP_E2E_KEEP=1` to keep containers and volumes after a failure:

```bash
FRDP_E2E_KEEP=1 bash server/frdp/test/e2e/run.sh samba
```

Set `FRDP_E2E_PROFILE_TIMEOUT=<seconds>` to cap each Compose profile run. The
default is 1800 seconds, and a timeout leaves the usual `compose-up.log`,
`compose.log`, `compose-ps.txt`, container logs, inspect JSON, and exit-code
artifact for diagnosis.

Set `FRDP_E2E_REPETITIONS=<count>` to run every selected profile repeatedly
from clean Compose volumes and a fresh profile artifact directory. A repeated
run stops on the first failure and stores each attempt under
`artifacts/<profile>/run-N/`, with completion status in
`repetition-summary.txt`. The default is one and retains the original artifact
layout. If the runner is interrupted, its EXIT/signal handler restores completed
attempts and preserves the current partial attempt as `incomplete-run-N`. The
first attempt builds the selected images; later attempts reuse those exact
images with `--no-build`.

Set `FRDP_AUTH_TIMEOUT=<seconds>` or `FRDP_E2E_TIMEOUT=<seconds>` to tune the
per-auth-only client timeout or managed-session wait loops used by
`rdp-probe.sh`.

## FreeIPA host requirements

The official FreeIPA image runs systemd. The Compose profile uses a read-only root filesystem, a `/data` volume, host cgroup namespace and a writable cgroup mount; it does not use `privileged`. A cgroups-v2 Docker host is strongly recommended. The profile is heavier than the local and Samba profiles and should have at least 4 CPUs and roughly 6–8 GiB of available memory.

The first FreeIPA start provisions the realm and can take several minutes. The
image health check then creates two enabled test principals and applies the
HBAC rule that allows only the primary account before the FRDP client starts.

## What the RDP probe checks

`rdp-probe.sh` uses the `xfreerdp` built from the same source tree and performs these checks:

1. `/auth-only` succeeds for the enabled user.
2. The managed session created by the successful probe is explicitly cleaned.
3. `/auth-only` fails for an incorrect password and leaves no managed session or durable session runtime artifact.
4. `/auth-only` fails for a locked, disabled, or provider-policy-denied account and leaves no managed session or durable session runtime artifact.
5. In the local profile, two graphical clients connect concurrently under `max_sessions = 2`. The manager must expose exactly two active records with unique session ids, displays and agent PIDs; a third client must authenticate once and be rejected by the session admission limit without changing either record. Stopping both clients, detaching both sessions and explicitly cleaning them must leave no registry or runtime artifacts.
6. A normal graphical connection under client-side Xvfb remains connected, appears as `active`, exposes the selected desktop plus deterministic xterm/xclock marker windows, verifies the desktop-type root property, transfers supplementary-plane Unicode clipboard text in both directions, and drives the managed Xorg dummy root through `800x600 -> 1024x768 -> 800x600` while each geometry is checked over X11.
7. In the local profile, `SIGHUP` first lowers `max_connections` to the held-peer count and rejects another client before PAM without disconnecting the held peer. A second reload restores the peer cap while publishing a deny-all static-channel policy to new peers without changing the held peer's clipboard policy snapshot. A malformed reload retains that policy, and restoring the original file makes the later reconnect possible.
8. In the local profile, the harness gracefully stops `frdpd`, requires its peer worker to detach the held session before the daemon exits, starts a new daemon PID while `frdp-sesmand` remains alive, and then connects the second client. Other profiles terminate the first client directly.
9. The restarted daemon uses `--max-connections=1` and supplies its TLS and helper-socket paths through CLI overrides. The second graphical client reattaches to the only matching session with the same session id, display and agent PID; reloading a sparse config that omits those static paths and raises the config-backed cap to `2` must succeed while still rejecting another peer before PAM without changing that session, proving startup-default reconstruction and CLI priority. Post-connect resynchronizes the retained `800x600` display to the new client's `1024x768` request before framebuffer pumping; its disconnect and explicit `kill-session` leave an empty registry.

The client mounts the session-manager socket volume. This allows it to observe the real manager registry and durable socket, metadata and display-reservation artifacts without inspecting server process memory. The local profile also mounts a control volume used to request atomic test-config replacement plus `SIGHUP` and, later, a supervised graceful `frdpd` restart; its authoritative server log must contain one peer rejected at the reloaded config-backed `max_connections = 1` cap before PAM, a second peer rejected after a config reload beneath the restarted daemon's CLI cap, one retained-policy parse failure, and two authenticated new-peer channel denials. The held session must remain unchanged through each reload, and neither denied channel peer may allocate another managed session. Before the main lifecycle it retains active, at-capacity and detached listings plus machine-readable evidence for two concurrent graphical sessions, stable reconnect of one of them while the session limit remains full, the rejected third session, and cleanup. The Samba and FreeIPA profiles mount separate isolated control volumes: after the baseline probe, the client atomically identifies an active SSSD-backed session, the server-side test supervisor kills that exact manager, and both sides require a replacement PID/socket inode, old-agent and runtime cleanup, client disconnect, and a fresh full login/reconnect cycle. Before each run, the harness clears `artifacts/<profile>/` so stale output cannot satisfy a check; `FRDP_E2E_ARTIFACTS` must resolve to a dedicated non-root directory named `artifacts`. Logs, session listings and an XWD capture of the client display are written there. The server starts a small deterministic desktop for each session agent under the authenticated account and with only the session display and Xauthority in its environment; the graphical probe requires its named xterm window before testing framebuffer-dependent behavior. A successful local profile requires exactly nine server-side PAM accepts: two concurrent graphical-load sessions, one reconnect at the full session limit, one session-admission probe rejected after authentication, the baseline authentication probe, initial graphical session, two single-attempt channel-policy denials after successful PAM, and post-restart reconnect. Both peer-cap rejections occur before PAM and therefore do not change that count. Samba and FreeIPA require six because their crash and post-recovery sessions also authenticate through SSSD. All require one NTLM MIC rejection for the wrong password before PAM, one named PAM/SSSD denial produced by the denied-user probe's connection path, and no NTLM proof/delegated-identity mismatch. Samba additionally requires the linked GPO fixture plus enforcing SSSD allow/deny evidence; FreeIPA requires explicit joined-host/keytab, increasing-KVNO rollover, old/new key rejection/acceptance, post-rollover PAM/SSSD RDP, and HBAC allow/deny evidence. Automatic client reconnect is explicitly disabled. The harness additionally preserves the rendered Compose model, timestamped aggregate logs, per-container logs, per-container inspect JSON and the component profile CTest `LastTest.log` when available.

## Useful direct commands

Render and validate the effective Compose model:

```bash
docker compose -f server/frdp/test/e2e/compose.yaml --profile local config
```

Inspect a retained failure:

```bash
docker compose -f server/frdp/test/e2e/compose.yaml --profile samba ps -a
docker compose -f server/frdp/test/e2e/compose.yaml --profile samba logs --no-color
docker compose -f server/frdp/test/e2e/compose.yaml exec frdpd-samba sssctl domain-status ad.test
docker compose -f server/frdp/test/e2e/compose.yaml exec frdpd-samba \
  frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock
```

Run a small auth-only load probe from a retained client/container shell:

```bash
FRDP_LOAD_CONCURRENCY=4 FRDP_LOAD_ITERATIONS=10 \
  bash /opt/frdp-e2e/scripts/rdp-load-probe.sh
```

Run the retained-client protocol regression probe, which exercises a small
auth-only NLA matrix across display depth, geometry and network profile
settings while preserving per-case logs:

```bash
bash /opt/frdp-e2e/scripts/rdp-protocol-regression.sh
```

Run a retained-client graphical session smoke probe, which opens a normal RDP
session, waits for it to become active in `frdpctl list-sessions`, negotiates
Display Control, resizes the client window, captures the client Xvfb root
window, disconnects and reconnects a second client to the same session
id/display/agent PID, and verifies final session cleanup:

```bash
bash /opt/frdp-e2e/scripts/rdp-session-smoke.sh
```

Clean all test state, including the FreeIPA data volume:

```bash
docker compose -f server/frdp/test/e2e/compose.yaml down --volumes --remove-orphans
```

## Coverage still required

This harness does not yet prove Kerberos-only CredSSP, ticket renewal or multi-master IPA behavior, restoration or reconnect across `frdp-sesmand` restart, installed-unit provider recovery, RDPGFX/RFX policy, clipboard interoperability beyond text with the bundled FreeRDP client, audio channels, systemd-logind registration, graphical session soak behavior, broad protocol regression coverage, or Windows `mstsc` interoperability. Per-session PAM-handle cleanup reconciliation and optional transient cgroup scopes have focused/component evidence, but still need broader installed/provider crash coverage. Those cases should be added as separate profiles or an external lab matrix rather than weakening the deterministic baseline tests.

All committed passwords are test-only defaults for an isolated Compose network. Do not expose provider ports or reuse these credentials outside the testbed.
