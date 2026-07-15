#!/usr/bin/env bash
set -Eeuo pipefail

if [[ $# -ne 1 ]]; then
  echo "usage: $0 FRDPD_DEB" >&2
  exit 2
fi

deb_path=$(realpath "$1")
if [[ ! -s "$deb_path" ]]; then
  echo "Debian package is missing: $deb_path" >&2
  exit 2
fi
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
session_smoke="$script_dir/e2e/scripts/rdp-session-smoke.sh"
if [[ ! -s "$session_smoke" ]]; then
  echo "RDP session smoke fixture is missing: $session_smoke" >&2
  exit 2
fi
command -v docker >/dev/null

suffix="$$-$RANDOM"
image="frdp-systemd-lifecycle:$suffix"
container="frdp-systemd-lifecycle-$suffix"

cleanup() {
  local status=$?
  if (( status != 0 )) && docker inspect "$container" >/dev/null 2>&1; then
    docker exec "$container" systemctl --no-pager --full status \
      frdp-authd.service frdp-sesmand.service frdpd.service >&2 || true
    docker exec "$container" journalctl --no-pager -n 200 >&2 || true
    if [[ "${FRDP_LIFECYCLE_KEEP_CONTAINER:-0}" == 1 ]]; then
      echo "preserving lifecycle failure container: $container (image: $image)" >&2
      trap - EXIT
      exit "$status"
    fi
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  docker image rm "$image" >/dev/null 2>&1 || true
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

docker build -q -t "$image" - <<'EOF'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
    && apt-get install -qq -y --no-install-recommends \
      freerdp3-x11 netcat-openbsd openssl procps systemd systemd-sysv \
      x11-apps x11-utils \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF

docker run -d --privileged --name "$container" --tmpfs /run --tmpfs /run/lock \
  "$image" >/dev/null
for _ in $(seq 1 30); do
  state=$(docker exec "$container" systemctl is-system-running 2>/dev/null || true)
  if [[ "$state" == running || "$state" == degraded ]]; then
    break
  fi
  sleep 1
done
if [[ "$state" != running && "$state" != degraded ]]; then
  echo "systemd did not become ready: $state" >&2
  exit 1
fi

docker cp "$deb_path" "$container:/tmp/frdpd-base.deb"
docker cp "$session_smoke" "$container:/tmp/rdp-session-smoke.sh"
docker exec -e DEBIAN_FRONTEND=noninteractive "$container" bash -Eeuo pipefail -c '
  trap '\''echo "lifecycle failure at line $LINENO: $BASH_COMMAND" >&2'\'' ERR
  chmod 0755 /tmp/rdp-session-smoke.sh

  assert_real_services() {
    local entry unit binary pid argv0

    for entry in \
      "frdp-authd.service:/usr/bin/frdp-authd" \
      "frdp-sesmand.service:/usr/bin/frdp-sesmand" \
      "frdpd.service:/usr/bin/frdpd"; do
      unit=${entry%%:*}
      binary=${entry#*:}
      test "$(systemctl show --property=FragmentPath --value "$unit")" = \
        "/usr/lib/systemd/system/$unit"
      test -z "$(systemctl show --property=DropInPaths --value "$unit")"
      systemctl --quiet is-active "$unit"
      pid=$(systemctl show --property=MainPID --value "$unit")
      test "$pid" -gt 1
      argv0=$(tr "\0" "\n" < "/proc/$pid/cmdline" | head -n 1)
      test "${argv0##*/}" = "${binary##*/}"
      test "$(cat "/proc/$pid/comm")" = "${binary##*/}"
    done
    test -S /run/frdp-authd/authd.sock
    test -S /run/frdp-sesmand/sesmand.sock
    test "$(stat -c %a /run/frdp-auth-token)" = 700
    test "$(systemctl is-enabled frdpd.service)" = enabled
    test "$(systemctl is-enabled frdp-authd.service 2>/dev/null || true)" = disabled
    test "$(systemctl is-enabled frdp-sesmand.service 2>/dev/null || true)" = disabled
    frdpctl status --socket /run/frdp-sesmand/sesmand.sock | \
      grep -Fxq "Session manager: reachable"
    timeout 5 bash -c "</dev/tcp/127.0.0.1/3389"
  }

  run_session_smoke() {
    local stage=$1

    FRDP_RDP_TARGET=127.0.0.1:3389 \
    FRDP_TEST_USER=lifecycle \
    FRDP_TEST_PASSWORD="RdpPassw0rd!" \
    FRDP_SESSION_MINIMAL_CHANNELS=1 \
    FRDP_SESSION_HOLD_SECONDS=1 \
    FRDP_SESSION_TIMEOUT=30 \
    FRDP_ARTIFACT_DIR="/tmp/lifecycle-smoke-$stage" \
      /tmp/rdp-session-smoke.sh
  }

  start_transition_session() {
    local stage=$1 i

    transition_display=:91
    transition_artifacts="/tmp/lifecycle-transition-$stage"
    mkdir -p "$transition_artifacts"
    Xvfb "$transition_display" -screen 0 800x600x24 -nolisten tcp \
      > "$transition_artifacts/client-xvfb.log" 2>&1 &
    transition_xvfb_pid=$!
    for i in $(seq 1 100); do
      if DISPLAY="$transition_display" xdpyinfo >/dev/null 2>&1; then
        break
      fi
      sleep 0.1
    done
    DISPLAY="$transition_display" xdpyinfo >/dev/null

    DISPLAY="$transition_display" xfreerdp3 \
      /v:127.0.0.1:3389 /u:lifecycle /p:RdpPassw0rd! /cert:ignore /sec:nla \
      /size:800x600 /bpp:24 /audio-mode:2 /network:modem \
      -gfx -disp -dynamic-resolution -clipboard -heartbeat -multitransport \
      -auto-reconnect /log-level:INFO \
      > "$transition_artifacts/client.log" 2>&1 &
    transition_client_pid=$!
    transition_session_id=
    transition_agent_pid=
    for i in $(seq 1 30); do
      kill -0 "$transition_client_pid"
      frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock \
        > "$transition_artifacts/session-list.txt" 2>&1 || true
      read -r transition_session_id transition_agent_pid < <(
        awk '\''NR > 1 && $2 == "lifecycle" && $4 == "active" { print $1, $5; exit }'\'' \
          "$transition_artifacts/session-list.txt") || true
      if [[ -n "$transition_session_id" && -n "$transition_agent_pid" ]]; then
        if assert_transition_session_active; then
          return 0
        fi
      fi
      sleep 1
    done
    return 1
  }

  assert_transition_session_active() {
    local state

    kill -0 "$transition_xvfb_pid"
    kill -0 "$transition_client_pid"
    state=$(ps -o stat= -p "$transition_agent_pid" | tr -d "[:space:]")
    [[ -n "$state" && "$state" != Z* ]]
    frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock \
      > "$transition_artifacts/session-list-before-transition.txt"
    awk -v id="$transition_session_id" -v pid="$transition_agent_pid" '\''
      NR > 1 && $2 == "lifecycle" { count++ }
      NR > 1 && $1 == id && $2 == "lifecycle" && $4 == "active" && $5 == pid {
        matched++
      }
      END { exit (count == 1 && matched == 1) ? 0 : 1 }
    '\'' "$transition_artifacts/session-list-before-transition.txt"
  }

  assert_transition_session_closed() {
    local i

    for i in $(seq 1 30); do
      if ! kill -0 "$transition_client_pid" 2>/dev/null; then
        wait "$transition_client_pid" || true
        break
      fi
      sleep 1
    done
    ! kill -0 "$transition_client_pid" 2>/dev/null
    for i in $(seq 1 30); do
      frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock \
        > "$transition_artifacts/session-list-after.txt" 2>&1 || true
      if grep -Fxq "No active sessions" "$transition_artifacts/session-list-after.txt"; then
        break
      fi
      sleep 1
    done
    grep -Fxq "No active sessions" "$transition_artifacts/session-list-after.txt"
    for i in $(seq 1 300); do
      if ! kill -0 "$transition_agent_pid" 2>/dev/null; then
        break
      fi
      sleep 0.1
    done
    ! kill -0 "$transition_agent_pid" 2>/dev/null
    kill -TERM "$transition_xvfb_pid" 2>/dev/null || true
    wait "$transition_xvfb_pid" || true
  }

  echo "stage=install"
  apt-get update -qq
  apt-get install -qq -y /tmp/frdpd-base.deb
  dpkg -V frdpd
  for unit in frdpd.service frdp-authd.service frdp-sesmand.service; do
    test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = disabled
    ! systemctl --quiet is-active "$unit"
  done
  rm -f /usr/sbin/policy-rc.d
  useradd --create-home --shell /bin/bash lifecycle
  printf "%s\n" "lifecycle:RdpPassw0rd!" | chpasswd
  printf "%s\n" \
    "auth required pam_env.so" \
    "auth required pam_unix.so try_first_pass" \
    "account required pam_unix.so" \
    "session required pam_limits.so" \
    "session required pam_mkhomedir.so skel=/etc/skel umask=0077" \
    "session optional pam_unix.so" > /etc/pam.d/frdpd
  pam_hash=$(sha256sum /etc/pam.d/frdpd | cut -d" " -f1)

  echo "stage=start"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout /etc/frdpd/tls.key -out /etc/frdpd/tls.crt >/dev/null 2>&1
  chmod 0600 /etc/frdpd/tls.key
  chmod 0644 /etc/frdpd/tls.crt
  printf "%s" "RdpPassw0rd!" | \
    winpr-hash -u lifecycle --password-stdin -f sam > /etc/frdpd/ntlm.sam
  chmod 0600 /etc/frdpd/ntlm.sam
  secret_hashes=$(sha256sum /etc/frdpd/tls.crt /etc/frdpd/tls.key /etc/frdpd/ntlm.sam)
  systemctl enable --now frdpd.service
  assert_real_services
  run_session_smoke base

  env_hash=$(sha256sum /etc/frdpd/frdpd.env | cut -d" " -f1)
  printf "%s\n" "# lifecycle-preserved" "FRDPD_ARGS=" > /etc/frdpd/frdpd.env
  modified_env_hash=$(sha256sum /etc/frdpd/frdpd.env | cut -d" " -f1)
  test "$env_hash" != "$modified_env_hash"

  for unit in frdp-authd.service frdp-sesmand.service frdpd.service; do
    systemctl show --property=InvocationID --value "$unit"
  done > /tmp/invocations-base

  rm -rf /tmp/frdpd-upgrade-root
  dpkg-deb --raw-extract /tmp/frdpd-base.deb /tmp/frdpd-upgrade-root
  base_version=$(dpkg-deb --field /tmp/frdpd-base.deb Version)
  upgrade_version="${base_version}+lifecycle1"
  dpkg --compare-versions "$upgrade_version" gt "$base_version"
  sed -i "s/^Version: .*/Version: $upgrade_version/" \
    /tmp/frdpd-upgrade-root/DEBIAN/control
  mkdir -p /tmp/frdpd-upgrade-root/usr/share/frdpd
  printf "%s\n" "$upgrade_version" \
    > /tmp/frdpd-upgrade-root/usr/share/frdpd/lifecycle-version
  rm -f /tmp/frdpd-upgrade-root/DEBIAN/md5sums
  dpkg-deb --build /tmp/frdpd-upgrade-root /tmp/frdpd-upgrade.deb >/dev/null
  start_transition_session upgrade

  echo "stage=upgrade"
  assert_transition_session_active
  apt-get install -qq -y /tmp/frdpd-upgrade.deb
  test "$(dpkg-query -W -f="\${Version}" frdpd)" = "$upgrade_version"
  test "$(cat /usr/share/frdpd/lifecycle-version)" = "$upgrade_version"
  test "$(sha256sum /etc/frdpd/frdpd.env | cut -d" " -f1)" = "$modified_env_hash"
  test "$(sha256sum /etc/pam.d/frdpd | cut -d" " -f1)" = "$pam_hash"
  test "$(sha256sum /etc/frdpd/tls.crt /etc/frdpd/tls.key /etc/frdpd/ntlm.sam)" = \
    "$secret_hashes"
  assert_real_services
  assert_transition_session_closed
  run_session_smoke upgrade
  for unit in frdp-authd.service frdp-sesmand.service frdpd.service; do
    systemctl show --property=InvocationID --value "$unit"
  done > /tmp/invocations-upgrade
  while read -r before after; do
    test -n "$before"
    test -n "$after"
    test "$before" != "$after"
  done < <(paste /tmp/invocations-base /tmp/invocations-upgrade)
  start_transition_session rollback

  echo "stage=rollback"
  assert_transition_session_active
  apt-get install -qq -y --allow-downgrades /tmp/frdpd-base.deb
  test "$(dpkg-query -W -f="\${Version}" frdpd)" = "$base_version"
  test ! -e /usr/share/frdpd/lifecycle-version
  test "$(sha256sum /etc/frdpd/frdpd.env | cut -d" " -f1)" = "$modified_env_hash"
  test "$(sha256sum /etc/pam.d/frdpd | cut -d" " -f1)" = "$pam_hash"
  test "$(sha256sum /etc/frdpd/tls.crt /etc/frdpd/tls.key /etc/frdpd/ntlm.sam)" = \
    "$secret_hashes"
  assert_real_services
  assert_transition_session_closed
  run_session_smoke rollback
  for unit in frdp-authd.service frdp-sesmand.service frdpd.service; do
    systemctl show --property=InvocationID --value "$unit"
  done > /tmp/invocations-rollback
  while read -r before after; do
    test -n "$before"
    test -n "$after"
    test "$before" != "$after"
  done < <(paste /tmp/invocations-upgrade /tmp/invocations-rollback)

  echo "stage=remove"
  apt-get remove -qq -y frdpd
  for unit in frdpd.service frdp-authd.service frdp-sesmand.service; do
    ! systemctl --quiet is-active "$unit"
  done
  test -e /etc/frdpd/frdpd.env
  test -e /etc/frdpd/frdpd.toml
  test -e /etc/pam.d/frdpd
  test "$(sha256sum /etc/frdpd/tls.crt /etc/frdpd/tls.key /etc/frdpd/ntlm.sam)" = \
    "$secret_hashes"
  test -L /etc/systemd/system/multi-user.target.wants/frdpd.service
  test ! -L /etc/systemd/system/multi-user.target.wants/frdp-authd.service
  test ! -L /etc/systemd/system/multi-user.target.wants/frdp-sesmand.service
  echo "stage=purge"
  apt-get purge -qq -y frdpd
  test ! -e /etc/frdpd/frdpd.env
  test ! -e /etc/frdpd/frdpd.toml
  test ! -e /etc/pam.d/frdpd
  test ! -L /etc/systemd/system/multi-user.target.wants/frdpd.service
  test ! -L /etc/systemd/system/multi-user.target.wants/frdp-authd.service
  test ! -L /etc/systemd/system/multi-user.target.wants/frdp-sesmand.service
  test "$(sha256sum /etc/frdpd/tls.crt /etc/frdpd/tls.key /etc/frdpd/ntlm.sam)" = \
    "$secret_hashes"
  rm -rf /etc/frdpd

  printf "base=%s\nupgrade=%s\nrollback=%s\nauth_smoke=base,upgrade,rollback\nactive_transition=upgrade,rollback\nresult=pass\n" \
    "$base_version" "$upgrade_version" "$base_version"
'
