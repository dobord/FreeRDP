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
3. Reload the daemon (`systemctl reload frdpd`) to pick up the new key without dropping active sessions.
4. Remove old keys from Active Directory to prevent reuse.

## Troubleshooting

- **Authentication fails**: Check `/var/log/auth.log` for PAM/SSSD errors. Verify SPN and keytab, ensure the client’s clock is within 5 minutes of the server.
- **Sessions do not start**: Confirm that Xvfb is installed and accessible. Inspect `journalctl -u frdp-sesmand` for session errors.
- **Performance issues**: Use the load testing harness to measure resource usage and adjust `max_connections` and session timeouts. Monitor CPU and memory with `top` or systemd metrics.
- **Blocked channels**: Static virtual channels are denied by default. Add exact static channel names to `[channels].static_allow` only after the corresponding handler is implemented and approved; allowing a name does not by itself enable clipboard/audio/device support. `[channels].dynamic_allow` is parsed as preparatory policy only; `drdynvc` is rejected until dynamic virtual-channel open enforcement is implemented.

## Dashboards and alert rules

Export metrics such as:

- Number of active sessions.
- Authentication failures per minute.
- CPU and memory utilisation.
- Average frame latency.

Integrate with Prometheus and Grafana:

1. Expose metrics via a `/metrics` endpoint or systemd cgroups.
2. Create Grafana dashboards showing session counts, CPU/memory and authentication rates.
3. Set alert thresholds (e.g. sessions > 90% of `max_connections`, authentication failures > 10/min).

## Migration/fallback to xrdp

To fall back to xrdp:

1. Install `xrdp` from your distribution.
2. Stop `frdpd` and start `xrdp` (`systemctl stop frdpd && systemctl start xrdp`).
3. Copy or translate configuration options: xrdp uses `/etc/xrdp/xrdp.ini` for listening and `/etc/pam.d/xrdp-sesman` for PAM.
4. Adjust firewall rules if xrdp listens on a different port (default 3389).
5. Test authentication and session creation with domain users.

## GA support matrix

| Component                 | Supported versions                    |
|---------------------------|----------------------------------------|
| Operating system          | Ubuntu 22.04 LTS, RHEL 9, Debian 12    |
| PAM providers             | pam_sss (SSSD 2.7+), pam_krb5 (1.19+)  |
| Kerberos                  | MIT Kerberos 1.19+, AD 2016–2022       |
| Clients                   | Windows 10/11 mstsc, FreeRDP 3.0+      |
| Desktop backends          | Xvfb 1.20+, XFCE 4.16+, Wayland (beta) |
| Encryption algorithms     | TLS 1.2/1.3, AES128/AES256, disabled NTLM |

Use this matrix to determine compatibility during the pilot and GA phases.
