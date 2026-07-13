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
3. `frdpctl reload` asks `frdp-sesmand --config <path>` to reread `[auth].pam_service`, supported `[session]` resource guards, and agent heartbeat policy. Existing sessions keep their PAM handles, receive a reset failure counter, and use the new heartbeat schedule. Restart the affected daemon during a maintenance window for listener sockets, TLS material, channel policy, clipboard policy, and helper-topology changes.
4. Installed `frdp-authd`, `frdp-sesmand`, and `frdpd` units use `Restart=on-failure`. `frdpd` performs role-bound helper health checks before listening and fails authentication/session creation closed during a helper restart. Investigate repeated restart loops rather than raising startup or IPC timeouts.
4. Remove old keys from Active Directory to prevent reuse.

## Troubleshooting

- **Authentication fails**: Check `/var/log/auth.log` for PAM/SSSD errors. Verify SPN and keytab, ensure the client’s clock is within 5 minutes of the server.
- **Sessions do not start**: Confirm that Xvfb is installed and accessible. Inspect `journalctl -u frdp-sesmand` for session errors.
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
- Configured session limit and active-session utilization ratio when
  `max_connections` is supplied to the collector.
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
