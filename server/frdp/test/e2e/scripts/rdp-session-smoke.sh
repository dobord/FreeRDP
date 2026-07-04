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

	if ! kill -0 "$pid" 2>/dev/null; then
		wait "$pid" 2>/dev/null || true
		return
	fi
	kill -TERM "$pid" 2>/dev/null || true
	for ((i = 0; i < 50; i++)); do
		if ! kill -0 "$pid" 2>/dev/null; then
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
		"/network:lan"
		"/log-level:INFO"
	)
	if [[ -n $FRDP_RDP_DOMAIN ]]; then
		RDP_ARGS+=("/d:${FRDP_RDP_DOMAIN}")
	fi
}

positive_integer "$FRDP_SESSION_TIMEOUT" || fail "FRDP_SESSION_TIMEOUT must be positive"
positive_integer "$FRDP_SESSION_HOLD_SECONDS" || fail "FRDP_SESSION_HOLD_SECONDS must be positive"
command -v Xvfb >/dev/null 2>&1 || fail "Xvfb executable was not found"
command -v xdpyinfo >/dev/null 2>&1 || fail "xdpyinfo executable was not found"

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
for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	if ! kill -0 "$client_pid" 2>/dev/null; then
		wait "$client_pid" || status=$?
		fail "xfreerdp exited before a managed session appeared (status ${status:-unknown})"
	fi
	set +e
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-current.txt" 2>&1
	list_status=$?
	set -e
	if [[ $list_status -eq 0 ]]; then
		session_id=$(awk -v user="$FRDP_TEST_USER" 'NR > 1 && $2 == user { print $1; exit }' \
			"$FRDP_ARTIFACT_DIR/session-list-current.txt")
		if [[ -n $session_id ]]; then
			break
		fi
	fi
	sleep 1
done
[[ -n $session_id ]] || fail "no managed session for $FRDP_TEST_USER appeared"

log "managed RDP session opened: $session_id"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" | tee "$FRDP_ARTIFACT_DIR/session-list-open.txt"
sleep "$FRDP_SESSION_HOLD_SECONDS"
kill -0 "$client_pid" 2>/dev/null || fail "xfreerdp did not remain connected"
xwd -display "$display_name" -root -silent -out "$FRDP_ARTIFACT_DIR/client-root.xwd" || true

stop_process "$client_pid"
client_pid=

for ((i = 0; i < FRDP_SESSION_TIMEOUT; i++)); do
	list_status=0
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after.txt" 2>&1 || list_status=$?
	if [[ $list_status -eq 0 ]]; then
		if grep -q '^No active sessions$' "$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
			log "managed RDP session was cleaned after client disconnect"
			exit 0
		fi
		if ! awk -v id="$session_id" 'NR > 1 && $1 == id { found = 1 } END { exit found ? 0 : 1 }' \
			"$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
			log "managed RDP session was cleaned after client disconnect"
			exit 0
		fi
	fi
	sleep 1
done

fail "managed session $session_id was not cleaned after disconnect"
