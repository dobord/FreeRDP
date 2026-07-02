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
| `local` | TLS, NLA/CredSSP, local `pam_unix`, helper IPC, managed Xvfb session | Valid authentication succeeds; wrong password and locked account fail; a full RDP client creates a session; disconnect removes it |
| `samba` | Provisioned Samba AD DC, DNS/Kerberos/LDAP, `adcli` machine join, `sssd-ad`, PAM, RDP | Domain user success, wrong password failure, disabled AD user failure, NSS lookup, managed RDP session lifecycle |
| `freeipa` | Official FreeIPA server image, LDAP identity, Kerberos password authentication through SSSD, PAM, RDP | IPA user success, wrong password failure, disabled IPA principal failure, NSS lookup, managed RDP session lifecycle |

The FreeIPA baseline deliberately uses SSSD's LDAP identity provider and Kerberos authentication provider with `krb5_validate=false`. It therefore validates real FreeIPA LDAP/KDC and PAM/SSSD behavior without requiring a host enrollment/keytab inside the FRDP container. A separate joined-host profile using `id_provider=ipa`, host keytab validation and explicit HBAC rules is still required before claiming production FreeIPA policy coverage.

The Samba profile does perform a machine join and uses the SSSD AD provider. GPO access control is set to `permissive` so the test is deterministic while still exercising AD identity, password authentication and disabled-account handling.

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

## FreeIPA host requirements

The official FreeIPA image runs systemd. The Compose profile uses a read-only root filesystem, a `/data` volume, host cgroup namespace and a writable cgroup mount; it does not use `privileged`. A cgroups-v2 Docker host is strongly recommended. The profile is heavier than the local and Samba profiles and should have at least 4 CPUs and roughly 6–8 GiB of available memory.

The first FreeIPA start provisions the realm and can take several minutes. The image health check then creates the enabled and disabled test principals before the FRDP client starts.

## What the RDP probe checks

`rdp-probe.sh` uses the `xfreerdp` built from the same source tree and performs four checks:

1. `/auth-only` succeeds for the enabled user.
2. `/auth-only` fails for an incorrect password.
3. `/auth-only` fails for a locked or disabled account.
4. A normal graphical connection under client-side Xvfb remains connected, appears in `frdpctl list-sessions`, and disappears after client termination.

The client mounts only the session-manager socket volume. This allows it to observe the real manager registry without inspecting server process memory. Logs, session listings and an XWD capture of the client display are written below `artifacts/<profile>/`. The harness also preserves the rendered Compose model, timestamped aggregate logs, per-container logs, per-container inspect JSON and the component profile CTest `LastTest.log` when available.

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

Clean all test state, including the FreeIPA data volume:

```bash
docker compose -f server/frdp/test/e2e/compose.yaml down --volumes --remove-orphans
```

## Coverage still required

This harness does not yet prove Kerberos-only CredSSP, reconnect semantics, RDPGFX/RFX policy, clipboard/audio channels, logind/cgroups, durable session reconciliation, a joined FreeIPA host with HBAC, full graphical session load/soak behavior, broad protocol regression coverage, or Windows `mstsc` interoperability. Those should be added as separate profiles or an external lab matrix rather than weakening the deterministic baseline tests.

All committed passwords are test-only defaults for an isolated Compose network. Do not expose provider ports or reuse these credentials outside the testbed.
