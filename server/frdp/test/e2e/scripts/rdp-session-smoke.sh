#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_RDP_TARGET=${FRDP_RDP_TARGET:-frdpd-local:3389}
FRDP_TEST_USER=${FRDP_TEST_USER:-rdpuser}
FRDP_TEST_PASSWORD=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
FRDP_RDP_DOMAIN=${FRDP_RDP_DOMAIN:-}
FRDP_SESSION_SOCKET=${FRDP_SESSION_SOCKET:-/run/frdp-sesmand/sesmand.sock}
FRDP_SESSION_TIMEOUT=${FRDP_SESSION_TIMEOUT:-60}
FRDP_SESSION_HOLD_SECONDS=${FRDP_SESSION_HOLD_SECONDS:-5}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts/session-smoke}
FRDP_SESSION_EXPECT_MANAGER_CRASH=${FRDP_SESSION_EXPECT_MANAGER_CRASH:-0}
FRDP_E2E_CONTROL_DIR=${FRDP_E2E_CONTROL_DIR:-/run/frdp-e2e-control}

mkdir -p "$FRDP_ARTIFACT_DIR"

log()
{
	printf '[frdp-session-smoke] %s\n' "$*" | tee -a "$FRDP_ARTIFACT_DIR/session-smoke.log" >&2
}

fail()
{
	log "ERROR: $*"
	exit 1
}

positive_integer()
{
	[[ $1 =~ ^[1-9][0-9]*$ ]]
}

process_is_running()
{
	local pid=$1
	local state=

	kill -0 "$pid" 2>/dev/null || return 1
	state=$(ps -o stat= -p "$pid" 2>/dev/null) || return 1
	state=${state//[[:space:]]/}
	[[ -n $state && $state != Z* ]]
}

session_identity_is_exclusively_active()
{
	local file=$1
	local id=$2
	local user=$3
	local display=$4
	local pid=$5

	awk -v id="$id" -v user="$user" -v display="$display" -v pid="$pid" \
		'NR > 1 && $2 == user { count++ }
		NR > 1 && $1 == id && $2 == user && $3 == display && $4 == "active" && $5 == pid {
			matched = 1
		}
		END { exit (count == 1 && matched) ? 0 : 1 }' "$file"
}

find_xfreerdp()
{
	local candidate
	for candidate in xfreerdp3 xfreerdp /usr/local/bin/xfreerdp3 /usr/local/bin/xfreerdp; do
		if command -v "$candidate" >/dev/null 2>&1; then
			command -v "$candidate"
			return 0
		fi
	done
	return 1
}

wait_tcp()
{
	local host=${FRDP_RDP_TARGET%:*}
	local port=${FRDP_RDP_TARGET##*:}

	for ((i = 0; i < 120; i++)); do
		if nc -z -w 1 "$host" "$port" >/dev/null 2>&1; then
			return 0
		fi
		sleep 1
	done
	return 1
}

allocate_display()
{
	local display

	for ((display = 90; display < 200; display++)); do
		if [[ ! -S /tmp/.X11-unix/X${display} && ! -e /tmp/.X${display}-lock ]]; then
			printf '%d' "$display"
			return 0
		fi
	done
	return 1
}

stop_process()
{
	local pid=$1

	if ! process_is_running "$pid"; then
		wait "$pid" 2>/dev/null || true
		return
	fi
	kill -TERM "$pid" 2>/dev/null || true
	for ((i = 0; i < 50; i++)); do
		if ! process_is_running "$pid"; then
			wait "$pid" 2>/dev/null || true
			return
		fi
		sleep 0.1
	done
	kill -KILL "$pid" 2>/dev/null || true
	wait "$pid" 2>/dev/null || true
}

build_args()
{
	RDP_ARGS=(
		"/v:${FRDP_RDP_TARGET}"
		"/u:${FRDP_TEST_USER}"
		"/p:${FRDP_TEST_PASSWORD}"
		"/cert:ignore"
		"/sec:nla"
		"/size:1024x768"
		"/bpp:24"
		"/audio-mode:2"
		"/network:modem"
		"-gfx"
		"-heartbeat"
		"-multitransport"
		"/tune:FreeRDP_NetworkAutoDetect:false"
		"/log-level:INFO"
	)
	if [[ ${FRDP_SESSION_MINIMAL_CHANNELS:-0} == 1 ]]; then
		RDP_ARGS+=("-disp" "-dynamic-resolution" "-clipboard")
	else
		RDP_ARGS+=("+disp" "+dynamic-resolution" "+clipboard")
	fi
	if [[ -n $FRDP_RDP_DOMAIN ]]; then
		RDP_ARGS+=("/d:${FRDP_RDP_DOMAIN}")
	fi
}

positive_integer "$FRDP_SESSION_TIMEOUT" || fail "FRDP_SESSION_TIMEOUT must be positive"
positive_integer "$FRDP_SESSION_HOLD_SECONDS" || fail "FRDP_SESSION_HOLD_SECONDS must be positive"
[[ $FRDP_SESSION_EXPECT_MANAGER_CRASH == 0 || $FRDP_SESSION_EXPECT_MANAGER_CRASH == 1 ]] ||
	fail "FRDP_SESSION_EXPECT_MANAGER_CRASH must be 0 or 1"
command -v Xvfb >/dev/null 2>&1 || fail "Xvfb executable was not found"
command -v xdpyinfo >/dev/null 2>&1 || fail "xdpyinfo executable was not found"
command -v xwd >/dev/null 2>&1 || fail "xwd executable was not found"
command -v ps >/dev/null 2>&1 || fail "ps executable was not found"
command -v nc >/dev/null 2>&1 || fail "nc executable was not found"
command -v frdpctl >/dev/null 2>&1 || fail "frdpctl executable was not found"

XFREERDP=$(find_xfreerdp) || fail "xfreerdp executable was not found"
wait_tcp || fail "RDP endpoint $FRDP_RDP_TARGET did not become reachable"
for ((i = 0; i < 120; i++)); do
	[[ -S $FRDP_SESSION_SOCKET ]] && break
	sleep 0.25
done
[[ -S $FRDP_SESSION_SOCKET ]] || fail "shared frdp-sesmand socket is unavailable"

frdpctl status --socket "$FRDP_SESSION_SOCKET" | tee "$FRDP_ARTIFACT_DIR/session-status-before.txt"

display_num=$(allocate_display) || fail "no free client X display was found"
display_name=":${display_num}"
xvfb_pid=
Xvfb "$display_name" -screen 0 1024x768x24 -nolisten tcp >"$FRDP_ARTIFACT_DIR/client-xvfb.log" 2>&1 &
xvfb_pid=$!
client_pid=
# ShellCheck cannot infer that the EXIT trap invokes this function after the crash-mode exit.
# shellcheck disable=SC2317
cleanup()
{
	if [[ -n ${client_pid:-} ]]; then
		stop_process "$client_pid"
	fi
	if [[ -n ${xvfb_pid:-} ]]; then
		stop_process "$xvfb_pid"
	fi
}
trap cleanup EXIT TERM INT

for ((i = 0; i < 100; i++)); do
	xvfb_state=$(ps -o stat= -p "$xvfb_pid" 2>/dev/null | tr -d '[:space:]')
	if [[ -z $xvfb_state || $xvfb_state == Z* ]]; then
		wait "$xvfb_pid" || status=$?
		fail "client Xvfb exited before display became ready (status ${status:-unknown})"
	fi
	if [[ -S /tmp/.X11-unix/X${display_num} ]] &&
		xdpyinfo -display "$display_name" >/dev/null 2>&1; then
		break
	fi
	sleep 0.1
done
[[ -S /tmp/.X11-unix/X${display_num} ]] || fail "client Xvfb did not start"
xdpyinfo -display "$display_name" >/dev/null 2>&1 || fail "client Xvfb did not accept connections"

export DISPLAY=$display_name
build_args
"$XFREERDP" "${RDP_ARGS[@]}" >"$FRDP_ARTIFACT_DIR/rdp-session.log" 2>&1 &
client_pid=$!

session_id=
open_user=
open_display=
open_state=
open_pid=
for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	if ! process_is_running "$client_pid"; then
		wait "$client_pid" || status=$?
		fail "xfreerdp exited before a managed session appeared (status ${status:-unknown})"
	fi
	set +e
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-current.txt" 2>&1
	list_status=$?
	set -e
	if [[ $list_status -eq 0 ]]; then
		read -r session_id open_user open_display open_state open_pid < <(
			awk -v user="$FRDP_TEST_USER" 'NR > 1 && $2 == user && $4 == "active" {
				print $1, $2, $3, $4, $5
				exit
			}' "$FRDP_ARTIFACT_DIR/session-list-current.txt") || true
		if [[ -n $session_id ]]; then
			break
		fi
	fi
	sleep 1
done
[[ -n $session_id ]] || fail "no managed session for $FRDP_TEST_USER appeared"

log "managed RDP session opened: $session_id"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" | tee "$FRDP_ARTIFACT_DIR/session-list-open.txt"
[[ $open_user == "$FRDP_TEST_USER" && $open_state == active ]] ||
	fail "managed session $session_id did not open as active"
[[ -n $open_display ]] || fail "managed session $session_id has no display"
positive_integer "$open_pid" || fail "managed session $session_id has invalid agent PID '$open_pid'"
if [[ $FRDP_SESSION_EXPECT_MANAGER_CRASH == 1 ]]; then
	observed_file="$FRDP_E2E_CONTROL_DIR/client-session-observed"
	printf 'session_id=%s\nagent_pid=%s\n' "$session_id" "$open_pid" >"${observed_file}.tmp"
	mv -f "${observed_file}.tmp" "$observed_file"
	recovery_file="$FRDP_E2E_CONTROL_DIR/sesmand-recovery"
	for ((i = 0; i < FRDP_SESSION_TIMEOUT * 10; i++)); do
		[[ ! -f $recovery_file ]] || break
		process_is_running "$client_pid" || true
		sleep 0.1
	done
	[[ -f $recovery_file ]] || fail "session manager crash recovery did not complete"
	for key in session_id agent_pid old_pid new_pid old_inode new_inode result; do
		count=$(grep -c "^${key}=" "$recovery_file" || true)
		[[ $count -eq 1 ]] || fail "recovery result has an invalid $key field"
	done
	recovered_session_id=$(sed -n 's/^session_id=//p' "$recovery_file")
	recovered_agent_pid=$(sed -n 's/^agent_pid=//p' "$recovery_file")
	old_manager_pid=$(sed -n 's/^old_pid=//p' "$recovery_file")
	new_manager_pid=$(sed -n 's/^new_pid=//p' "$recovery_file")
	old_socket_inode=$(sed -n 's/^old_inode=//p' "$recovery_file")
	new_socket_inode=$(sed -n 's/^new_inode=//p' "$recovery_file")
	grep -Fxq 'result=pass' "$recovery_file" || fail "session manager recovery did not pass"
	[[ $recovered_session_id == "$session_id" && $recovered_agent_pid == "$open_pid" ]] ||
		fail "recovery result does not identify the held session"
	positive_integer "$old_manager_pid" || fail "recovery result has an invalid old manager PID"
	positive_integer "$new_manager_pid" || fail "recovery result has an invalid new manager PID"
	positive_integer "$old_socket_inode" || fail "recovery result has an invalid old socket inode"
	positive_integer "$new_socket_inode" || fail "recovery result has an invalid new socket inode"
	[[ $new_manager_pid != "$old_manager_pid" && $new_socket_inode != "$old_socket_inode" ]] ||
		fail "session manager endpoint identity was not replaced"
	for ((i = 0; i < FRDP_SESSION_TIMEOUT * 10; i++)); do
		process_is_running "$client_pid" || break
		sleep 0.1
	done
	process_is_running "$client_pid" && fail "xfreerdp remained connected after session cleanup"
	wait "$client_pid" 2>/dev/null || true
	client_pid=
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after-manager-crash.txt" 2>&1 ||
		fail "replacement session manager is unreachable"
	grep -Fxq 'No active sessions' "$FRDP_ARTIFACT_DIR/session-list-after-manager-crash.txt" ||
		fail "replacement session manager retained stale session state"
	log "manager crash closed and cleaned held session $session_id"
	exit 0
fi

sleep "$FRDP_SESSION_HOLD_SECONDS"
process_is_running "$client_pid" || fail "xfreerdp did not remain connected"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
	>"$FRDP_ARTIFACT_DIR/session-list-open-held.txt" 2>&1 ||
	fail "failed to list the held managed session"
session_identity_is_exclusively_active "$FRDP_ARTIFACT_DIR/session-list-open-held.txt" \
	"$session_id" "$FRDP_TEST_USER" "$open_display" "$open_pid" ||
	fail "managed session $session_id did not remain exclusively active"
xwd -display "$display_name" -root -silent -out "$FRDP_ARTIFACT_DIR/client-root.xwd" ||
	fail "failed to capture the client Xvfb display"

stop_process "$client_pid"
client_pid=

for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	list_status=0
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after.txt" 2>&1 || list_status=$?
	if [[ $list_status -eq 0 ]]; then
		if awk -v id="$session_id" 'NR > 1 && $1 == id && $4 == "disconnected" { found = 1 }
			END { exit found ? 0 : 1 }' \
			"$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
			log "managed RDP session detached after client disconnect"
			break
		fi
	fi
	sleep 1
done

if ! awk -v id="$session_id" 'NR > 1 && $1 == id && $4 == "disconnected" { found = 1 }
	END { exit found ? 0 : 1 }' "$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
	fail "managed session $session_id did not become disconnected after client disconnect"
fi

build_args
"$XFREERDP" "${RDP_ARGS[@]}" >"$FRDP_ARTIFACT_DIR/rdp-reconnect.log" 2>&1 &
client_pid=$!
for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	if ! process_is_running "$client_pid"; then
		wait "$client_pid" || status=$?
		fail "reconnecting xfreerdp exited before session attach (status ${status:-unknown})"
	fi
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-reconnected.txt" 2>&1 || true
	if session_identity_is_exclusively_active \
		"$FRDP_ARTIFACT_DIR/session-list-reconnected.txt" "$session_id" "$FRDP_TEST_USER" \
		"$open_display" "$open_pid"; then
		log "managed RDP session reattached with stable id/display/PID: $session_id"
		break
	fi
	sleep 1
done

if ! session_identity_is_exclusively_active "$FRDP_ARTIFACT_DIR/session-list-reconnected.txt" \
	"$session_id" "$FRDP_TEST_USER" "$open_display" "$open_pid"; then
	fail "reconnect did not attach exclusively to managed session $session_id"
fi
sleep "$FRDP_SESSION_HOLD_SECONDS"
process_is_running "$client_pid" || fail "reconnected xfreerdp did not remain connected"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
	>"$FRDP_ARTIFACT_DIR/session-list-reconnected-held.txt" 2>&1 ||
	fail "failed to list the held reconnected session"
session_identity_is_exclusively_active "$FRDP_ARTIFACT_DIR/session-list-reconnected-held.txt" \
	"$session_id" "$FRDP_TEST_USER" "$open_display" "$open_pid" ||
	fail "reconnected session $session_id did not remain exclusively active"
stop_process "$client_pid"
client_pid=

for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after-reconnect.txt" 2>&1 || true
	if awk -v id="$session_id" -v display="$open_display" -v pid="$open_pid" \
		'NR > 1 && $1 == id && $3 == display && $4 == "disconnected" && $5 == pid {
			found = 1
		}
		END { exit found ? 0 : 1 }' "$FRDP_ARTIFACT_DIR/session-list-after-reconnect.txt"; then
		log "reattached RDP session detached after second client disconnect"
		break
	fi
	sleep 1
done
if ! awk -v id="$session_id" -v display="$open_display" -v pid="$open_pid" \
	'NR > 1 && $1 == id && $3 == display && $4 == "disconnected" && $5 == pid { found = 1 }
	END { exit found ? 0 : 1 }' "$FRDP_ARTIFACT_DIR/session-list-after-reconnect.txt"; then
	fail "reattached session $session_id did not become disconnected"
fi

frdpctl kill-session "$session_id" --socket "$FRDP_SESSION_SOCKET" \
	>"$FRDP_ARTIFACT_DIR/session-kill.txt" 2>&1 || fail "failed to kill detached session $session_id"
for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-cleanup.txt" 2>&1 || true
	if grep -q '^No active sessions$' "$FRDP_ARTIFACT_DIR/session-list-cleanup.txt"; then
		log "managed RDP session was cleaned after explicit kill-session"
		exit 0
	fi
	sleep 1
done

fail "managed session $session_id was not cleaned after explicit kill-session"
