# FRDP component and end-to-end tests

This directory contains a Docker Compose testbed for the experimental `server/frdp` stack. It exercises the canonical multi-process topology instead of the in-process PAM fallback:

```text
xfreerdp
  -> TLS + NLA/CredSSP
      -> frdpd
          -> frdp-authd -> PAM -> local identity or SSSD
          -> frdp-sesmand -> PAM session -> frdp-session-agent -> Xvfb
```

## Profiles

| Profile | What is real | Assertions |
|---|---|---|
| `component` | Built FRDP binaries and focused CTest suite | Config/channel policy, IPC primitives, `frdpctl`, helper stop handling, malformed requests against real `frdp-authd` and `frdp-sesmand` processes |
| `local` | TLS, NLA/CredSSP, local `pam_unix`, helper IPC, managed Xvfb session | Valid authentication succeeds; wrong password and locked account fail; a full RDP client exchanges Unicode clipboard text in both directions, then creates, detaches, reconnects to, and removes one stable session |
| `samba` | Provisioned Samba AD DC, DNS/Kerberos/LDAP, `adcli` machine join, `sssd-ad`, PAM, RDP | Domain user success, wrong password failure, disabled AD user failure, NSS user lookup plus supplementary AD-group membership, managed RDP disconnect/reconnect lifecycle, active-session `frdp-sesmand` crash cleanup and fresh post-recovery login/reconnect |
| `freeipa` | Official FreeIPA server, host enrollment/keytab, `sssd-ipa`, HBAC, PAM, RDP | Allowed IPA user success, wrong password failure, valid user denied by HBAC, host-keytab validation, NSS lookup, managed RDP disconnect/reconnect lifecycle, active-session `frdp-sesmand` crash cleanup and fresh post-recovery login/reconnect |

The FreeIPA profile enrolls `frdpd.ipa.test` with a one-time host password,
requires the expected host principal in a root-only keytab, and runs SSSD with
the IPA identity, authentication and access providers plus Kerberos validation.
It disables the default `allow_all` rule and permits only the enabled test user
for the `frdpd` PAM service on that host; a second enabled user proves HBAC
denial independently of password and disabled-account checks.

The Samba profile does perform a machine join and uses the SSSD AD provider. It creates the configurable `FRDP_TEST_GROUP` (`rdp-users` by default), adds the allowed account, and requires the joined host to resolve that supplementary group through NSS/SSSD before starting `frdpd`. GPO access control is set to `permissive` so the test is deterministic while still exercising AD identity, password authentication and disabled-account handling.

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

`rdp-probe.sh` uses the `xfreerdp` built from the same source tree and performs six checks:

1. `/auth-only` succeeds for the enabled user.
2. The managed session created by the successful probe is explicitly cleaned.
3. `/auth-only` fails for an incorrect password and leaves no managed session or durable session runtime artifact.
4. `/auth-only` fails for a locked, disabled, or provider-policy-denied account and leaves no managed session or durable session runtime artifact.
5. A normal graphical connection under client-side Xvfb remains connected, appears as `active`, and transfers supplementary-plane Unicode clipboard text in both directions under the configured policy.
6. The connection becomes `disconnected` after client termination, and a second graphical client reattaches to the only matching session with the same session id, display and agent PID; its disconnect and explicit `kill-session` leave an empty registry.

The client mounts the session-manager socket volume. This allows it to observe the real manager registry and durable socket, metadata and display-reservation artifacts without inspecting server process memory. The Samba and FreeIPA profiles additionally mount separate isolated control volumes: after the baseline probe, the client atomically identifies an active SSSD-backed session, the server-side test supervisor kills that exact manager, and both sides require a replacement PID/socket inode, old-agent and runtime cleanup, client disconnect, and a fresh full login/reconnect cycle. Before each run, the harness clears `artifacts/<profile>/` so stale output cannot satisfy a check; `FRDP_E2E_ARTIFACTS` must resolve to a dedicated non-root directory named `artifacts`. Logs, session listings and an XWD capture of the client display are written there. A successful local profile requires exactly three server-side PAM accepts; Samba and FreeIPA require six because their crash and post-recovery sessions also authenticate through SSSD. All require one NTLM MIC rejection for the wrong password before PAM, two named PAM/SSSD denials produced by the denied-user probe's connection path, and no NTLM proof/delegated-identity mismatch. FreeIPA additionally requires explicit joined-host/keytab and HBAC allow/deny evidence in that authoritative log. Automatic client reconnect is explicitly disabled. The harness additionally preserves the rendered Compose model, timestamped aggregate logs, per-container logs, per-container inspect JSON and the component profile CTest `LastTest.log` when available.

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

This harness does not yet prove Kerberos-only CredSSP, restoration or reconnect across manager/daemon restart, installed-unit provider recovery, RDPGFX/RFX policy, clipboard interoperability beyond text with the bundled FreeRDP client, audio channels, logind/cgroups, full lost-PAM-handle reconciliation, FreeIPA keytab rollover, graphical session soak behavior, broad protocol regression coverage, or Windows `mstsc` interoperability. Those should be added as separate profiles or an external lab matrix rather than weakening the deterministic baseline tests.

All committed passwords are test-only defaults for an isolated Compose network. Do not expose provider ports or reuse these credentials outside the testbed.
