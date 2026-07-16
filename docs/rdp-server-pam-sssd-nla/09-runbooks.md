# 09. Operational runbooks

These runbooks provide guidance for deploying and operating the FreeRDP-based RDP server in production.

## Joining Active Directory

1. Ensure the host has time synchronisation (NTP) with the domain controllers.
2. Install `realmd`, `sssd` and Kerberos packages.
3. Join the domain:

   ```bash
   realm join --membership-software=samba --user=Administrator your.domain.example.com
   ```

4. Verify that `id <user>` returns domain users. Update `sssd.conf` as described in the Kerberos guide.
5. Place the server keytab at `/etc/frdpd/frdpd.keytab` and set correct permissions (600).

## Keytab rotation

Rotate the service key periodically:

1. Use `ktutil` or `setspn`/`ktpass` to generate a new keytab for the SPN (TERMSRV/hostname).
2. Copy the new keytab to each RDP server.
3. `frdpctl reload` asks `frdp-sesmand --config <path>` to reread `[auth].pam_service`, supported `[session]` resource guards, display-backend policy, and agent heartbeat policy. Existing sessions keep their PAM handles and launch-time display backend, receive a reset failure counter, and use the new heartbeat schedule. Separately, `SIGHUP` asks `frdpd --config <path>` to atomically publish reloaded `[channels]` and `[clipboard]` policy to future peers; existing peers retain their connection-time snapshots, and a parse failure retains the last policy. Restart the affected daemon during a maintenance window for listener sockets, TLS material, authentication/NTLM state, helper topology, and all other fields.
4. Installed `frdp-authd`, `frdp-sesmand`, and `frdpd` units use `Restart=on-failure`. `frdpd` performs role-bound helper health checks before listening and fails authentication/session creation closed during a helper restart. Investigate repeated restart loops rather than raising startup or IPC timeouts.
5. Remove old keys from Active Directory to prevent reuse.

## NTLM SAM provisioning and rotation

The default build enables NTLM proof verification, but PAM/SSSD cannot provide
the NT hash required to verify an NTLMv2 challenge. Provision
`/etc/frdpd/ntlm.sam` as a separate password-equivalent secret store and keep
its identities synchronized with the accounts that PAM/SSSD will authorize.

1. Obtain NT hashes through an approved directory provisioning process. Do not
   pass plaintext passwords in command arguments, shell history, logs, or the
   SAM file. Each record uses `user:domain:lm-hash:nt-hash:::`; leave the LM
   field empty and provide exactly 32 hexadecimal characters for the NT hash.
   A local/no-domain record therefore has the form
   `user:::0123456789abcdef0123456789abcdef:::`.
   When an approved secret source supplies a plaintext password, pipe it to
   `winpr-hash -u user -d domain --password-stdin -f sam`; do not use the
   legacy `-p` form. Protect the command output as password-equivalent data.
2. Build the complete replacement in a root-only staging directory. The final
   file must be non-empty, structurally valid, regular, single-link, mode
   `0600`, and owned by the effective UID of `frdpd` (`root` for the shipped
   preview unit). Never edit the active file in place.
3. Stop `frdpd`, install the staged file under a temporary name in
   `/etc/frdpd`, then atomically rename it to `ntlm.sam` and start `frdpd`.
   Startup validates every non-comment record and fails before helper probing or
   listening on an empty, comments-only, or malformed store.
4. Treat restart as mandatory after rotation. `frdpd` pins the validated SAM
   inode for its lifetime, so `frdpctl reload` and replacing the pathname do not
   move a running listener to the new store. Remove the staging copy after the
   restarted service is healthy.

An explicit `-DWITH_FRDPD_NTLM=OFF` build generates a configuration without an
active SAM path, omits `winpr-hash` from the server component, and does not
require this store. The default-on preview Debian and RPM packages include the
tool with the server runtime.

## Troubleshooting

- **Authentication fails**: Check `/var/log/auth.log` for PAM/SSSD errors. Verify SPN and keytab, ensure the client’s clock is within 5 minutes of the server.
- **NTLM listener does not start**: Check ownership, mode, link count, and every SAM record. An empty or comments-only file is intentionally rejected. A valid NTLM proof is still followed by mandatory PAM authentication and account management, so also inspect PAM/SSSD denial logs.
- **Sessions do not start**: For `xvfb`, confirm that Xvfb is installed and accessible. For `xorg-dummy`, install the distro Xorg server and dummy-video-driver packages, use the raw Xorg executable rather than its console wrapper, and verify that `xorg_path`, `xorg_config`, and every parent component are root-owned, non-symlink, and not group- or world-writable. Inspect `journalctl -u frdp-sesmand` for a rejected path, Xauthority creation failure, or backend startup error.
- **Resize is rejected**: Confirm that `display_backend = "xorg-dummy"`, the requested size is an explicit mode in `xorg-dummy.conf`, and the active Xorg CRTC drives exactly one connected output. Xvfb intentionally accepts only its initial geometry. A reconnect synchronizes the retained desktop to the new client's requested size before framebuffer delivery and fails closed if that mode cannot be applied.
- **Performance issues**: Use the load testing harness to measure resource usage and adjust `max_connections` and session timeouts. Monitor CPU and memory with `top` or systemd metrics.
- **Blocked channels**: Channel filtering supports `blocklist`/`blacklist` and `allowlist`/`whitelist` modes. The default is empty blocklist mode; use `[channels].static_deny` to reject exact static names, or switch to static allowlist mode with `[channels].static_allow` when a restrictive deployment is required. `[channels].dynamic_deny` / `[channels].dynamic_allow` feed the DVC authorization callback for the implemented Display Control handler. Allowing a name does not by itself enable a handler: `cliprdr` additionally requires active text clipboard policy, while arbitrary static channels, `rdpsnd` audio output, `rdpdr` device redirection, and non-text clipboard formats remain runtime-denied.

## Dashboards and alert rules

The package installs starter monitoring examples under
`/usr/share/frdpd/monitoring`:

- `frdpd-node-exporter-textfile.sh` calls `frdpctl status` and writes
  Prometheus node_exporter textfile metrics for session-manager reachability,
  scrape success, collector freshness and active sessions. Set
  `FRDP_MAX_CONNECTIONS` or pass `--max-connections` to emit the optional
  capacity and utilization metrics used by the alert rules.
- `frdpd-prometheus-alerts.yml` contains starter alerts for an unreachable
  session manager, failed or stale textfile scrapes and high session capacity.

Example cron or systemd timer command:

```bash
FRDP_MAX_CONNECTIONS=64 \
  /usr/share/frdpd/monitoring/frdpd-node-exporter-textfile.sh \
    --socket /run/frdp-sesmand/sesmand.sock \
    --output /var/lib/node_exporter/textfile_collector/frdpd.prom
```

These examples currently export:

- Number of active sessions from `frdpctl status`.
- Configured peer-worker limit and active-session-to-worker utilization ratio
  when `max_connections` is supplied to the collector. The collector does not
  yet export `[session].max_sessions`.
- Session-manager control-socket reachability.
- Textfile scrape freshness, success or the last scrape error.

Integrate with Prometheus and Grafana:

1. Enable node_exporter's textfile collector and schedule the FRDP collector.
2. Import the Prometheus rules and tune severity/thresholds for the pilot.
3. Import the shipped starter Grafana dashboard, then extend it for pilot
   host CPU/memory panels from node_exporter and authentication-rate panels
   from system logs or a future native metrics endpoint.

## Migration/fallback to xrdp

To fall back to xrdp:

1. Install `xrdp` from your distribution.
2. Stop `frdpd` and start `xrdp` (`systemctl stop frdpd && systemctl start xrdp`).
3. Copy or translate configuration options: xrdp uses `/etc/xrdp/xrdp.ini` for listening and `/etc/pam.d/xrdp-sesman` for PAM.
4. Adjust firewall rules if xrdp listens on a different port (default 3389).
5. Test authentication and session creation with domain users.

## GA support matrix

The current branch does not claim GA support. Use
`14-support-matrix.md` as the pilot validation target and evidence checklist.
Do not call a platform, client, identity provider, channel, or package format
supported until the matrix evidence is reproducible from a clean release
artifact.
