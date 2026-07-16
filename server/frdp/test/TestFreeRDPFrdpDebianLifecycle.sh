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
repo_root=$(realpath "$script_dir/../../..")
session_smoke="$script_dir/e2e/scripts/rdp-session-smoke.sh"
if [[ ! -s "$session_smoke" ]]; then
  echo "RDP session smoke fixture is missing: $session_smoke" >&2
  exit 2
fi
command -v docker >/dev/null

provider=${FRDP_LIFECYCLE_PROVIDER:-local}
case "$provider" in
  local|samba) ;;
  *)
    echo "unsupported lifecycle identity provider: $provider" >&2
    exit 2
    ;;
esac

suffix="$$-$RANDOM"
image="frdp-systemd-lifecycle:$suffix"
container="frdp-systemd-lifecycle-$suffix"
dc_image=""
dc_container=""
network=""

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
  if (( status != 0 )) && [[ -n "$dc_container" ]] &&
     docker inspect "$dc_container" >/dev/null 2>&1; then
    docker logs --tail 200 "$dc_container" >&2 || true
  fi
  docker rm -f "$container" >/dev/null 2>&1 || true
  if [[ -n "$dc_container" ]]; then
    docker rm -f "$dc_container" >/dev/null 2>&1 || true
  fi
  if [[ -n "$network" ]]; then
    docker network rm "$network" >/dev/null 2>&1 || true
  fi
  docker image rm "$image" >/dev/null 2>&1 || true
  if [[ -n "$dc_image" ]]; then
    docker image rm "$dc_image" >/dev/null 2>&1 || true
  fi
  trap - EXIT
  exit "$status"
}
trap cleanup EXIT

docker build -q -t "$image" - <<'EOF'
FROM ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update -qq \
    && sed -i '\|^path-exclude=/usr/share/man/|d' /etc/dpkg/dpkg.cfg.d/excludes \
    && apt-get install -qq -y --no-install-recommends \
      adcli freerdp3-x11 krb5-user libnss-sss libpam-sss netcat-openbsd \
      openssl procps sssd sssd-ad sssd-tools systemd systemd-sysv \
      x11-apps x11-utils xvfb \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*
STOPSIGNAL SIGRTMIN+3
CMD ["/sbin/init"]
EOF

run_args=(
  -d --privileged --name "$container" --tmpfs /run --tmpfs /run/lock
)
if [[ "$provider" == samba ]]; then
  dc_image="frdp-samba-lifecycle:$suffix"
  dc_container="frdp-samba-lifecycle-$suffix"
  network="frdp-samba-lifecycle-$suffix"
  docker build -q -t "$dc_image" -f "$script_dir/e2e/Dockerfile.samba" \
    "$repo_root" >/dev/null
  docker network create "$network" >/dev/null
  docker run -d --name "$dc_container" --cap-add SYS_ADMIN --network "$network" \
    --network-alias dc.ad.test --hostname dc.ad.test \
    -e FRDP_AD_REALM=AD.TEST \
    -e FRDP_AD_NETBIOS_DOMAIN=AD \
    -e 'FRDP_AD_ADMIN_PASSWORD=SambaAdminPassw0rd!' \
    -e FRDP_TEST_USER=rdpuser \
    -e 'FRDP_TEST_PASSWORD=RdpPassw0rd!' \
    -e FRDP_TEST_GROUP=rdp-users \
    -e FRDP_DENY_USER=rdpgpodenied \
    -e 'FRDP_DENY_PASSWORD=DeniedPassw0rd!' \
    "$dc_image" >/dev/null
  for _ in $(seq 1 120); do
    if docker exec "$dc_container" test -f /run/frdp-gpo-ready &&
       docker exec "$dc_container" samba-tool user show rdpuser >/dev/null 2>&1 &&
       docker exec "$dc_container" samba-tool group listmembers rdp-users 2>/dev/null |
         grep -Fxq rdpuser; then
      break
    fi
    sleep 1
  done
  docker exec "$dc_container" test -f /run/frdp-gpo-ready
  docker exec "$dc_container" samba-tool user show rdpuser >/dev/null
  docker logs "$dc_container" 2>&1 |
    grep -E 'Samba AD enforcing GPO \{[0-9A-F-]{36}\}' |
    grep -Fq 'allows rdp-users and denies enabled user rdpgpodenied for frdpd'
  dc_ip=$(docker inspect --format "{{with index .NetworkSettings.Networks \"$network\"}}{{.IPAddress}}{{end}}" \
    "$dc_container")
  [[ "$dc_ip" =~ ^[0-9]+([.][0-9]+){3}$ ]]
  run_args+=(--network "$network" --dns "$dc_ip" --dns-search ad.test \
    --hostname frdpd.ad.test)
else
  run_args+=(--hostname frdpd.local.test)
fi

docker run "${run_args[@]}" "$image" >/dev/null
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
docker exec -e DEBIAN_FRONTEND=noninteractive \
  -e FRDP_LIFECYCLE_PROVIDER="$provider" "$container" bash -Eeuo pipefail -c '
  trap '\''echo "lifecycle failure at line $LINENO: $BASH_COMMAND" >&2'\'' ERR

  case "$FRDP_LIFECYCLE_PROVIDER" in
    local)
      test_user=lifecycle
      test_password="RdpPassw0rd!"
      gpo_policy=not-applicable
      rdp_domain=
      ;;
    samba)
      test_user=rdpuser
      test_password="RdpPassw0rd!"
      deny_user=rdpgpodenied
      deny_password="DeniedPassw0rd!"
      gpo_policy=base,upgrade,rollback
      rdp_domain=AD
      ;;
    *) exit 2 ;;
  esac
  client_domain_args=()
  if [[ -n "$rdp_domain" ]]; then
    client_domain_args+=("/d:$rdp_domain")
  fi
  chmod 0755 /tmp/rdp-session-smoke.sh

  assert_samba_gpo_policy() {
    local checks

    checks=$(LC_ALL=C sssctl user-checks -a acct -s frdpd "$test_user" 2>&1)
    grep -Fq "pam_acct_mgmt: Success" <<< "$checks"
    checks=$(LC_ALL=C sssctl user-checks -a acct -s frdpd "$deny_user" 2>&1 || true)
    grep -Fq "pam_acct_mgmt: Permission denied" <<< "$checks"
  }

  assert_real_services() {
    local attempt argv0 binary comm entry pid unit

    for entry in \
      "frdp-authd.service:/usr/bin/frdp-authd" \
      "frdp-sesmand.service:/usr/bin/frdp-sesmand" \
      "frdpd.service:/usr/bin/frdpd"; do
      unit=${entry%%:*}
      binary=${entry#*:}
      test "$(systemctl show --property=FragmentPath --value "$unit")" = \
        "/usr/lib/systemd/system/$unit"
      test -z "$(systemctl show --property=DropInPaths --value "$unit")"
      pid=
      argv0=
      comm=
      for attempt in $(seq 1 50); do
        systemctl --quiet is-active "$unit" || true
        pid=$(systemctl show --property=MainPID --value "$unit")
        if [[ "$pid" =~ ^[0-9]+$ ]] && (( pid > 1 )) &&
           [[ -r "/proc/$pid/cmdline" && -r "/proc/$pid/comm" ]]; then
          argv0=$(tr "\0" "\n" < "/proc/$pid/cmdline" | head -n 1) || argv0=
          comm=$(cat "/proc/$pid/comm") || comm=
          if [[ "${argv0##*/}" == "${binary##*/}" && "$comm" == "${binary##*/}" ]]; then
            break
          fi
        fi
        sleep 0.1
      done
      systemctl --quiet is-active "$unit"
      test "$pid" -gt 1
      test "${argv0##*/}" = "${binary##*/}"
      test "$comm" = "${binary##*/}"
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
    if [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]; then
      systemctl --quiet is-active sssd.service
      test "$(systemctl show --property=InvocationID --value sssd.service)" = \
        "$sssd_invocation"
      adcli testjoin --domain=ad.test --domain-controller=dc.ad.test >/dev/null
      getent passwd "$test_user" >/dev/null
      id -nG "$test_user" | tr " " "\n" | grep -Fxq rdp-users
      assert_samba_gpo_policy
    fi
  }

  run_session_smoke() {
    local stage=$1

    FRDP_RDP_TARGET=127.0.0.1:3389 \
    FRDP_TEST_USER="$test_user" \
    FRDP_TEST_PASSWORD="$test_password" \
    FRDP_RDP_DOMAIN="$rdp_domain" \
    FRDP_SESSION_MINIMAL_CHANNELS=1 \
    FRDP_SESSION_HOLD_SECONDS=1 \
    FRDP_SESSION_TIMEOUT=30 \
    FRDP_ARTIFACT_DIR="/tmp/lifecycle-smoke-$stage" \
      /tmp/rdp-session-smoke.sh
  }

  run_samba_gpo_denial() {
    local auth_only_arg help_output journal_cursor stage=$1 status=0
    local artifacts="/tmp/lifecycle-gpo-$1"

    [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]
    help_output=$(xfreerdp3 /help 2>&1 || true)
    if grep -q "/auth-only" <<< "$help_output"; then
      auth_only_arg=/auth-only
    else
      grep -q "+auth-only" <<< "$help_output"
      auth_only_arg=+auth-only
    fi
    mkdir -p "$artifacts"
    journal_cursor=$(journalctl -u frdpd.service -n 1 --show-cursor --no-pager | \
      sed -n "s/^-- cursor: //p")
    test -n "$journal_cursor"
    if timeout 20 xvfb-run -a xfreerdp3 \
         /v:127.0.0.1:3389 "/u:$deny_user" "/p:$deny_password" \
         "${client_domain_args[@]}" /cert:ignore /sec:nla \
         /size:800x600 /bpp:24 /audio-mode:2 /network:modem \
         -gfx -disp -dynamic-resolution -clipboard -heartbeat -multitransport \
         -auto-reconnect /log-level:INFO "$auth_only_arg" \
         > "$artifacts/client.log" 2>&1; then
      status=0
    else
      status=$?
    fi
    case "$status" in
      0|124|125|126|127) return 1 ;;
    esac
    journalctl --sync
    journalctl -u frdpd.service --after-cursor "$journal_cursor" --no-pager \
      > "$artifacts/server.log"
    grep -F "PAM rejected RDP login for $deny_user from" "$artifacts/server.log" |
      grep -Fq ": denied "
    ! grep -Fq "Message Integrity Check (MIC) verification failed" \
      "$artifacts/server.log"
    frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock \
      > "$artifacts/session-list.txt"
    grep -Fxq "No active sessions" "$artifacts/session-list.txt"
    test -z "$(find /run/frdp-sesmand -mindepth 1 ! -name sesmand.sock -print -quit)"
    printf "stage=%s user=%s result=gpo-denied\n" "$stage" "$deny_user"
  }

  run_failed_auth_only() {
    local auth_only_arg client_marker help_output journal_cursor server_marker
    local stage=$1 status=0

    help_output=$(xfreerdp3 /help 2>&1 || true)
    if grep -q "/auth-only" <<< "$help_output"; then
      auth_only_arg=/auth-only
    else
      grep -q "+auth-only" <<< "$help_output"
      auth_only_arg=+auth-only
    fi
    mkdir -p "/tmp/lifecycle-outage-$stage"
    journal_cursor=$(journalctl -u frdpd.service -n 1 --show-cursor --no-pager | \
      sed -n "s/^-- cursor: //p")
    test -n "$journal_cursor"
    if timeout 20 xvfb-run -a xfreerdp3 \
         /v:127.0.0.1:3389 "/u:$test_user" "/p:$test_password" \
         "${client_domain_args[@]}" /cert:ignore /sec:nla \
         /size:800x600 /bpp:24 /audio-mode:2 /network:modem \
         -gfx -disp -dynamic-resolution -clipboard -heartbeat -multitransport \
         -auto-reconnect /log-level:INFO "$auth_only_arg" \
         > "/tmp/lifecycle-outage-$stage/client.log" 2>&1; then
      status=0
    else
      status=$?
    fi
    case "$status" in
      0|124|125|126|127) return 1 ;;
    esac
    journalctl --sync
    journalctl -u frdpd.service --after-cursor "$journal_cursor" --no-pager \
      > "/tmp/lifecycle-outage-$stage/server.log"
    case "$stage" in
      authd-outage-*)
        client_marker="ERRCONNECT_CONNECT_TRANSPORT_FAILED"
        server_marker="broker_error=unable to connect to auth broker"
        ;;
      sesmand-outage-*)
        client_marker="ERRCONNECT_CONNECT_CANCELLED"
        server_marker="session manager rejected login for $test_user: IPC failure"
        ;;
      *) return 1 ;;
    esac
    grep -Fq "$client_marker" "/tmp/lifecycle-outage-$stage/client.log"
    grep -Fq "$server_marker" "/tmp/lifecycle-outage-$stage/server.log"

    if [[ -S /run/frdp-sesmand/sesmand.sock ]]; then
      frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock \
        > "/tmp/lifecycle-outage-$stage/session-list.txt"
      grep -Fxq "No active sessions" \
        "/tmp/lifecycle-outage-$stage/session-list.txt"
      test -z "$(find /run/frdp-sesmand -mindepth 1 ! -name sesmand.sock -print -quit)"
    else
      test ! -e /run/frdp-sesmand
    fi
  }

  assert_helper_outage_recovery() {
    local i new_invocation new_pid new_socket_inode
    local old_invocation old_pid old_socket_inode socket=$2 stage=$3 unit=$1

    old_pid=$(systemctl show --property=MainPID --value "$unit")
    old_invocation=$(systemctl show --property=InvocationID --value "$unit")
    old_socket_inode=$(stat -c %i "$socket")
    test "$old_pid" -gt 1
    test -n "$old_invocation"

    systemctl stop "$unit"
    ! systemctl --quiet is-active "$unit"
    test ! -S "$socket"
    sleep 3
    ! systemctl --quiet is-active "$unit"
    test ! -S "$socket"
    systemctl --quiet is-active frdpd.service
    timeout 5 bash -c "</dev/tcp/127.0.0.1/3389"
    run_failed_auth_only "${stage}-initial"
    sleep 10
    ! systemctl --quiet is-active "$unit"
    test ! -S "$socket"
    systemctl --quiet is-active frdpd.service
    timeout 5 bash -c "</dev/tcp/127.0.0.1/3389"
    run_failed_auth_only "${stage}-sustained"

    systemctl start "$unit"
    new_pid=
    new_socket_inode=
    for i in $(seq 1 50); do
      new_pid=$(systemctl show --property=MainPID --value "$unit")
      if systemctl --quiet is-active "$unit" &&
         [[ "$new_pid" =~ ^[0-9]+$ ]] && (( new_pid > 1 )) &&
         [[ "$new_pid" != "$old_pid" ]] && [[ -S "$socket" ]]; then
        new_socket_inode=$(stat -c %i "$socket")
        if [[ "$new_socket_inode" != "$old_socket_inode" ]]; then
          break
        fi
      fi
      sleep 0.1
    done
    test "$new_pid" != "$old_pid"
    test -n "$new_socket_inode"
    test "$new_socket_inode" != "$old_socket_inode"
    new_invocation=$(systemctl show --property=InvocationID --value "$unit")
    test -n "$new_invocation"
    test "$new_invocation" != "$old_invocation"
    assert_real_services
    run_session_smoke "post-$stage"
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
      /v:127.0.0.1:3389 "/u:$test_user" "/p:$test_password" \
      "${client_domain_args[@]}" /cert:ignore /sec:nla \
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
        awk -v user="$test_user" '\''NR > 1 && $2 == user && $4 == "active" { print $1, $5; exit }'\'' \
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
    awk -v id="$transition_session_id" -v pid="$transition_agent_pid" \
      -v user="$test_user" '\''
      NR > 1 && $2 == user { count++ }
      NR > 1 && $1 == id && $2 == user && $4 == "active" && $5 == pid {
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

  assert_sesmand_active_session_recovery() {
    local i old_invocation old_pid old_socket_inode
    local new_invocation new_pid new_socket_inode

    start_transition_session sesmand-crash
    old_pid=$(systemctl show --property=MainPID --value frdp-sesmand.service)
    old_invocation=$(systemctl show --property=InvocationID --value frdp-sesmand.service)
    old_socket_inode=$(stat -c %i /run/frdp-sesmand/sesmand.sock)
    test "$old_pid" -gt 1
    test -n "$old_invocation"
    test "$old_pid" != "$transition_agent_pid"

    systemctl kill --signal=SIGKILL --kill-who=main frdp-sesmand.service
    new_pid=
    new_socket_inode=
    for i in $(seq 1 60); do
      new_pid=$(systemctl show --property=MainPID --value frdp-sesmand.service)
      if systemctl --quiet is-active frdp-sesmand.service &&
         [[ "$new_pid" =~ ^[0-9]+$ ]] && (( new_pid > 1 )) &&
         [[ "$new_pid" != "$old_pid" ]] && [[ -S /run/frdp-sesmand/sesmand.sock ]]; then
        new_socket_inode=$(stat -c %i /run/frdp-sesmand/sesmand.sock)
        if [[ "$new_socket_inode" != "$old_socket_inode" ]] &&
           frdpctl status --socket /run/frdp-sesmand/sesmand.sock |
             grep -Fxq "Session manager: reachable"; then
          break
        fi
      fi
      sleep 1
    done
    test -n "$new_socket_inode"
    test "$new_socket_inode" != "$old_socket_inode"
    test "$new_pid" != "$old_pid"
    new_invocation=$(systemctl show --property=InvocationID --value frdp-sesmand.service)
    test -n "$new_invocation"
    test "$new_invocation" != "$old_invocation"

    assert_transition_session_closed
    test -z "$(find /run/frdp-sesmand -mindepth 1 ! -name sesmand.sock -print -quit)"
    assert_real_services
    run_session_smoke post-sesmand-crash
  }

  assert_authd_inflight_recovery() {
    local auth_only_arg client_pid delay_pid help_output i journal_cursor
    local new_invocation new_pid new_socket_inode old_invocation old_pid old_socket_inode
    local status
    local artifacts=/tmp/lifecycle-authd-inflight-crash
    local marker=/run/frdp-authd/pam-delay-entered
    local pam_backup=/tmp/frdpd-pam-before-inflight-crash
    local pam_delay=/usr/local/libexec/frdp-pam-delay

    mkdir -p "$artifacts" /usr/local/libexec
    help_output=$(xfreerdp3 /help 2>&1 || true)
    if grep -q "/auth-only" <<< "$help_output"; then
      auth_only_arg=/auth-only
    else
      grep -q "+auth-only" <<< "$help_output"
      auth_only_arg=+auth-only
    fi
    cp --preserve=mode,ownership,timestamps /etc/pam.d/frdpd "$pam_backup"
    printf "%s\n" "#!/bin/sh" "set -eu" \
      "echo \"\$\$\" > /run/frdp-authd/pam-delay-entered" \
      "sleep 30" > "$pam_delay"
    chmod 0755 "$pam_delay"
    {
      printf "%s\n" "auth optional pam_exec.so quiet $pam_delay"
      cat "$pam_backup"
    } > /etc/pam.d/frdpd
    rm -f "$marker"

    old_pid=$(systemctl show --property=MainPID --value frdp-authd.service)
    old_invocation=$(systemctl show --property=InvocationID --value frdp-authd.service)
    old_socket_inode=$(stat -c %i /run/frdp-authd/authd.sock)
    journal_cursor=$(journalctl -u frdpd.service -n 1 --show-cursor --no-pager | \
      sed -n "s/^-- cursor: //p")
    test "$old_pid" -gt 1
    test -n "$old_invocation"
    test -n "$journal_cursor"

    (
      if timeout 20 xvfb-run -a xfreerdp3 \
           /v:127.0.0.1:3389 "/u:$test_user" "/p:$test_password" \
           "${client_domain_args[@]}" /cert:ignore /sec:nla \
           /size:800x600 /bpp:24 /audio-mode:2 /network:modem \
           -gfx -disp -dynamic-resolution -clipboard -heartbeat -multitransport \
           -auto-reconnect /log-level:INFO "$auth_only_arg" \
           > "$artifacts/client.log" 2>&1; then
        status=0
      else
        status=$?
      fi
      printf "%s\n" "$status" > "$artifacts/client.status"
    ) &
    client_pid=$!
    for i in $(seq 1 100); do
      if [[ -f "$marker" ]]; then
        break
      fi
      kill -0 "$client_pid"
      sleep 0.1
    done
    test -f "$marker"
    delay_pid=$(cat "$marker")
    [[ "$delay_pid" =~ ^[0-9]+$ ]]
    test "$delay_pid" -gt 1
    kill -0 "$delay_pid"
    kill -0 "$client_pid"
    test "$(systemctl show --property=MainPID --value frdp-authd.service)" = "$old_pid"

    systemctl kill --signal=SIGKILL --kill-who=main frdp-authd.service
    cp --preserve=mode,ownership,timestamps "$pam_backup" /etc/pam.d/frdpd
    rm -f "$pam_delay" "$marker"
    wait "$client_pid"
    status=$(cat "$artifacts/client.status")
    case "$status" in
      0|124|125|126|127) return 1 ;;
    esac
    grep -Fq "ERRCONNECT_CONNECT_TRANSPORT_FAILED" "$artifacts/client.log"
    journalctl --sync
    journalctl -u frdpd.service --after-cursor "$journal_cursor" --no-pager \
      > "$artifacts/server.log"
    grep -Fq "broker_error=unable to receive auth broker response" "$artifacts/server.log"

    new_pid=
    new_socket_inode=
    for i in $(seq 1 100); do
      new_pid=$(systemctl show --property=MainPID --value frdp-authd.service)
      if systemctl --quiet is-active frdp-authd.service &&
         [[ "$new_pid" =~ ^[0-9]+$ ]] && (( new_pid > 1 )) &&
         [[ "$new_pid" != "$old_pid" ]] && [[ -S /run/frdp-authd/authd.sock ]]; then
        new_socket_inode=$(stat -c %i /run/frdp-authd/authd.sock)
        if [[ "$new_socket_inode" != "$old_socket_inode" ]]; then
          break
        fi
      fi
      sleep 0.1
    done
    test "$new_pid" != "$old_pid"
    test -n "$new_socket_inode"
    test "$new_socket_inode" != "$old_socket_inode"
    new_invocation=$(systemctl show --property=InvocationID --value frdp-authd.service)
    test -n "$new_invocation"
    test "$new_invocation" != "$old_invocation"
    ! kill -0 "$delay_pid" 2>/dev/null
    test "$(sha256sum /etc/pam.d/frdpd | cut -d" " -f1)" = "$pam_hash"
    frdpctl list-sessions --socket /run/frdp-sesmand/sesmand.sock \
      > "$artifacts/session-list.txt"
    grep -Fxq "No active sessions" "$artifacts/session-list.txt"
    test -z "$(find /run/frdp-sesmand -mindepth 1 ! -name sesmand.sock -print -quit)"
    assert_real_services
    run_session_smoke post-authd-inflight-crash
  }

  configure_samba_identity() {
    local i

    for i in $(seq 1 120); do
      if getent hosts dc.ad.test >/dev/null 2>&1 &&
         timeout 1 bash -c "</dev/tcp/dc.ad.test/389" 2>/dev/null; then
        break
      fi
      sleep 1
    done
    getent hosts dc.ad.test >/dev/null
    timeout 1 bash -c "</dev/tcp/dc.ad.test/389"
    cat > /etc/krb5.conf <<EOF
[libdefaults]
 default_realm = AD.TEST
 dns_lookup_realm = false
 dns_lookup_kdc = true
 rdns = false
 udp_preference_limit = 0

[domain_realm]
 .ad.test = AD.TEST
 ad.test = AD.TEST
EOF
    printf "%s\n" "SambaAdminPassw0rd!" | adcli join ad.test \
      --domain-controller=dc.ad.test \
      --host-fqdn=frdpd.ad.test \
      --computer-name=FRDPD \
      --login-user=Administrator \
      --stdin-password
    adcli testjoin --domain=ad.test --domain-controller=dc.ad.test

    install -d -m 0700 /etc/sssd
    cat > /etc/sssd/sssd.conf <<EOF
[sssd]
config_file_version = 2
services = nss, pam
domains = ad.test

[nss]

[pam]

[domain/ad.test]
id_provider = ad
auth_provider = ad
access_provider = ad
ad_domain = ad.test
ad_server = dc.ad.test
krb5_realm = AD.TEST
krb5_ccname_template = FILE:/tmp/krb5cc_%U
ldap_id_mapping = true
cache_credentials = false
krb5_store_password_if_offline = false
use_fully_qualified_names = false
fallback_homedir = /home/%u
default_shell = /bin/bash
dyndns_update = false
ad_gpo_access_control = enforcing
ad_gpo_map_remote_interactive = +frdpd
EOF
    chmod 0600 /etc/sssd/sssd.conf
    for database in passwd group; do
      if ! awk -v db="$database" '\''
        $1 == db ":" { for (i = 2; i <= NF; i++) if ($i == "sss") found = 1 }
        END { exit found ? 0 : 1 }
      '\'' /etc/nsswitch.conf; then
        sed -ri "s/^(${database}:[^#]*)$/\\1 sss/" /etc/nsswitch.conf
      fi
    done
    printf "%s\n" \
      "auth required pam_env.so" \
      "auth required pam_sss.so try_first_pass" \
      "account required pam_sss.so" \
      "session required pam_limits.so" \
      "session required pam_mkhomedir.so skel=/etc/skel umask=0077" \
      "session optional pam_sss.so" > /etc/pam.d/frdpd
    sssctl config-check
    systemctl enable --now sssd.service
    for i in $(seq 1 120); do
      if getent passwd "$test_user" >/dev/null 2>&1; then
        break
      fi
      sleep 1
    done
    getent passwd "$test_user"
    id -nG "$test_user" | tr " " "\n" | grep -Fxq rdp-users
    getent passwd "$deny_user"
    assert_samba_gpo_policy
  }

  echo "stage=install"
  apt-get update -qq
  apt-get install -qq -y /tmp/frdpd-base.deb
  package_verification=$(dpkg -V frdpd)
  test -z "$package_verification"
  for unit in frdpd.service frdp-authd.service frdp-sesmand.service; do
    test "$(systemctl is-enabled "$unit" 2>/dev/null || true)" = disabled
    ! systemctl --quiet is-active "$unit"
  done
  rm -f /usr/sbin/policy-rc.d
  if [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]; then
    configure_samba_identity
    sssd_invocation=$(systemctl show --property=InvocationID --value sssd.service)
    test -n "$sssd_invocation"
  else
    useradd --create-home --shell /bin/bash "$test_user"
    printf "%s:%s\n" "$test_user" "$test_password" | chpasswd
    printf "%s\n" \
      "auth required pam_env.so" \
      "auth required pam_unix.so try_first_pass" \
      "account required pam_unix.so" \
      "session required pam_limits.so" \
      "session required pam_mkhomedir.so skel=/etc/skel umask=0077" \
      "session optional pam_unix.so" > /etc/pam.d/frdpd
  fi
  pam_hash=$(sha256sum /etc/pam.d/frdpd | cut -d" " -f1)

  echo "stage=start"
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 1 \
    -subj "/CN=localhost" \
    -addext "subjectAltName=DNS:localhost,IP:127.0.0.1" \
    -keyout /etc/frdpd/tls.key -out /etc/frdpd/tls.crt >/dev/null 2>&1
  chmod 0600 /etc/frdpd/tls.key
  chmod 0644 /etc/frdpd/tls.crt
  printf "%s" "$test_password" | \
    winpr-hash -u "$test_user" --password-stdin -f sam > /etc/frdpd/ntlm.sam
  if [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]; then
    printf "%s" "$deny_password" | \
      winpr-hash -u "$deny_user" --password-stdin -f sam >> /etc/frdpd/ntlm.sam
  fi
  chmod 0600 /etc/frdpd/ntlm.sam
  secret_hashes=$(sha256sum /etc/frdpd/tls.crt /etc/frdpd/tls.key /etc/frdpd/ntlm.sam)
  systemctl enable --now frdpd.service
  assert_real_services
  run_session_smoke base
  if [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]; then
    run_samba_gpo_denial base
  fi
  echo "stage=active-sesmand-crash"
  assert_sesmand_active_session_recovery
  echo "stage=authd-outage"
  assert_helper_outage_recovery frdp-authd.service /run/frdp-authd/authd.sock authd-outage
  echo "stage=sesmand-outage"
  assert_helper_outage_recovery frdp-sesmand.service /run/frdp-sesmand/sesmand.sock sesmand-outage
  echo "stage=authd-inflight-crash"
  assert_authd_inflight_recovery

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
  if [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]; then
    run_samba_gpo_denial upgrade
  fi
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
  if [[ "$FRDP_LIFECYCLE_PROVIDER" == samba ]]; then
    run_samba_gpo_denial rollback
  fi
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

  printf "provider=%s\nbase=%s\nupgrade=%s\nrollback=%s\nauth_smoke=base,post-sesmand-crash,post-authd-outage,post-sesmand-outage,post-authd-inflight-crash,upgrade,rollback\ngpo_policy=%s\nactive_helper_crash=frdp-sesmand\ninflight_helper_crash=frdp-authd\nhelper_outage=frdp-authd,frdp-sesmand\nactive_transition=upgrade,rollback\nresult=pass\n" \
    "$FRDP_LIFECYCLE_PROVIDER" "$base_version" "$upgrade_version" "$base_version" \
    "$gpo_policy"
'
