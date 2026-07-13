#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_RDP_TARGET=${FRDP_RDP_TARGET:-frdpd-local:3389}
FRDP_TEST_USER=${FRDP_TEST_USER:-rdpuser}
FRDP_TEST_PASSWORD=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
FRDP_DENY_USER=${FRDP_DENY_USER:-rdpdisabled}
FRDP_DENY_PASSWORD=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}
FRDP_RDP_DOMAIN=${FRDP_RDP_DOMAIN:-}
FRDP_SESSION_SOCKET=${FRDP_SESSION_SOCKET:-/run/frdp-sesmand/sesmand.sock}
FRDP_E2E_TIMEOUT=${FRDP_E2E_TIMEOUT:-60}
FRDP_AUTH_TIMEOUT=${FRDP_AUTH_TIMEOUT:-45}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts}

mkdir -p "$FRDP_ARTIFACT_DIR"

log()
{
	printf '[frdp-e2e-client] %s\n' "$*" | tee -a "$FRDP_ARTIFACT_DIR/probe.log" >&2
}

fail()
{
	log "ERROR: $*"
	exit 1
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

build_args()
{
	local user=$1
	local password=$2
	RDP_ARGS=(
		"/v:${FRDP_RDP_TARGET}"
		"/u:${user}"
		"/p:${password}"
		"/cert:ignore"
		"/sec:nla"
		"/size:1024x768"
		"/bpp:24"
		"/audio-mode:none"
		"-gfx"
		"-disp"
		"-dynamic-resolution"
		"-clipboard"
		"-heartbeat"
		"-multitransport"
		"/tune:FreeRDP_NetworkAutoDetect:false"
		"/log-level:TRACE"
	)
	if [[ -n $FRDP_RDP_DOMAIN ]]; then
		RDP_ARGS+=("/d:${FRDP_RDP_DOMAIN}")
	fi
}

run_auth_only()
{
	local label=$1
	local expected=$2
	local user=$3
	local password=$4
	local logfile="$FRDP_ARTIFACT_DIR/auth-${label}.log"
	local status=0

	build_args "$user" "$password"
	set +e
	timeout "${FRDP_AUTH_TIMEOUT}s" xvfb-run -a "$XFREERDP" "${RDP_ARGS[@]}" \
		"$AUTH_ONLY_ARG" >"$logfile" 2>&1
	status=$?
	set -e

	if [[ $expected == success ]]; then
		[[ $status -eq 0 ]] || fail "auth-only '$label' failed with status $status"
	else
		[[ $status -ne 0 ]] || fail "auth-only '$label' unexpectedly succeeded"
	fi
	log "auth-only '$label' produced expected result: $expected"
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

positive_integer "$FRDP_E2E_TIMEOUT" || fail "FRDP_E2E_TIMEOUT must be positive"
positive_integer "$FRDP_AUTH_TIMEOUT" || fail "FRDP_AUTH_TIMEOUT must be positive"
command -v timeout >/dev/null 2>&1 || fail "timeout executable was not found"
command -v xvfb-run >/dev/null 2>&1 || fail "xvfb-run executable was not found"
command -v Xvfb >/dev/null 2>&1 || fail "Xvfb executable was not found"
command -v xwd >/dev/null 2>&1 || fail "xwd executable was not found"
command -v ps >/dev/null 2>&1 || fail "ps executable was not found"
command -v nc >/dev/null 2>&1 || fail "nc executable was not found"
command -v frdpctl >/dev/null 2>&1 || fail "frdpctl executable was not found"

XFREERDP=$(find_xfreerdp) || fail "xfreerdp executable was not found"
help_output=$("$XFREERDP" /help 2>&1 || true)
if grep -q '/auth-only' <<<"$help_output"; then
	AUTH_ONLY_ARG=/auth-only
elif grep -q '+auth-only' <<<"$help_output"; then
	AUTH_ONLY_ARG=+auth-only
else
	fail "the built xfreerdp does not expose auth-only mode"
fi

wait_tcp || fail "RDP endpoint $FRDP_RDP_TARGET did not become reachable"
for ((i = 0; i < 120; i++)); do
	[[ -S $FRDP_SESSION_SOCKET ]] && break
	sleep 0.25
done
[[ -S $FRDP_SESSION_SOCKET ]] || fail "shared frdp-sesmand socket is unavailable"
frdpctl status --socket "$FRDP_SESSION_SOCKET" | tee "$FRDP_ARTIFACT_DIR/session-status-before.txt"

run_auth_only valid success "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
run_auth_only wrong-password failure "$FRDP_TEST_USER" "${FRDP_TEST_PASSWORD}--wrong"
run_auth_only disabled-account failure "$FRDP_DENY_USER" "$FRDP_DENY_PASSWORD"

Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >"$FRDP_ARTIFACT_DIR/client-xvfb.log" 2>&1 &
xvfb_pid=$!
client_pid=
cleanup()
{
	if [[ -n ${client_pid:-} ]]; then
		stop_process "$client_pid"
	fi
	stop_process "$xvfb_pid"
}
trap cleanup EXIT TERM INT

for ((i = 0; i < 100; i++)); do
	[[ -S /tmp/.X11-unix/X99 ]] && break
	sleep 0.1
done
[[ -S /tmp/.X11-unix/X99 ]] || fail "client Xvfb did not start"

export DISPLAY=:99
build_args "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
"$XFREERDP" "${RDP_ARGS[@]}" >"$FRDP_ARTIFACT_DIR/rdp-session.log" 2>&1 &
client_pid=$!

session_id=
open_user=
open_display=
open_state=
open_pid=
for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
	if ! process_is_running "$client_pid"; then
		wait "$client_pid" || status=$?
		fail "xfreerdp exited before a managed session appeared (status ${status:-unknown})"
	fi
	set +e
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_ARTIFACT_DIR/session-list-current.txt" 2>&1
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
sleep 3
process_is_running "$client_pid" || fail "xfreerdp did not remain connected"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
	>"$FRDP_ARTIFACT_DIR/session-list-open-held.txt" 2>&1 ||
	fail "failed to list the held managed session"
session_identity_is_exclusively_active "$FRDP_ARTIFACT_DIR/session-list-open-held.txt" \
	"$session_id" "$FRDP_TEST_USER" "$open_display" "$open_pid" ||
	fail "managed session $session_id did not remain exclusively active"
xwd -display :99 -root -silent -out "$FRDP_ARTIFACT_DIR/client-root.xwd" ||
	fail "failed to capture the client Xvfb display"

stop_process "$client_pid"
client_pid=

for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_ARTIFACT_DIR/session-list-after.txt" 2>&1 || true
	if awk -v id="$session_id" 'NR > 1 && $1 == id && $4 == "disconnected" { found = 1 }
		END { exit found ? 0 : 1 }' "$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
		log "managed RDP session detached after client disconnect"
		break
	fi
	sleep 1
done

if ! awk -v id="$session_id" 'NR > 1 && $1 == id && $4 == "disconnected" { found = 1 }
	END { exit found ? 0 : 1 }' "$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
	fail "managed session $session_id did not become disconnected after client disconnect"
fi

build_args "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
"$XFREERDP" "${RDP_ARGS[@]}" >"$FRDP_ARTIFACT_DIR/rdp-reconnect.log" 2>&1 &
client_pid=$!
for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
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
sleep 3
process_is_running "$client_pid" || fail "reconnected xfreerdp did not remain connected"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
	>"$FRDP_ARTIFACT_DIR/session-list-reconnected-held.txt" 2>&1 ||
	fail "failed to list the held reconnected session"
session_identity_is_exclusively_active "$FRDP_ARTIFACT_DIR/session-list-reconnected-held.txt" \
	"$session_id" "$FRDP_TEST_USER" "$open_display" "$open_pid" ||
	fail "reconnected session $session_id did not remain exclusively active"
stop_process "$client_pid"
client_pid=

for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
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
for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_ARTIFACT_DIR/session-list-cleanup.txt" 2>&1 || true
	if grep -q '^No active sessions$' "$FRDP_ARTIFACT_DIR/session-list-cleanup.txt"; then
		log "managed RDP session was cleaned after explicit kill-session"
		exit 0
	fi
	sleep 1
done

fail "managed session $session_id was not cleaned after explicit kill-session"
