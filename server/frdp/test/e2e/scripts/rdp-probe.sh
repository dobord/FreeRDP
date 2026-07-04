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
		"/network:lan"
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

positive_integer "$FRDP_E2E_TIMEOUT" || fail "FRDP_E2E_TIMEOUT must be positive"
positive_integer "$FRDP_AUTH_TIMEOUT" || fail "FRDP_AUTH_TIMEOUT must be positive"
command -v timeout >/dev/null 2>&1 || fail "timeout executable was not found"
command -v xvfb-run >/dev/null 2>&1 || fail "xvfb-run executable was not found"
command -v Xvfb >/dev/null 2>&1 || fail "Xvfb executable was not found"

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
for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
	if ! kill -0 "$client_pid" 2>/dev/null; then
		wait "$client_pid" || status=$?
		fail "xfreerdp exited before a managed session appeared (status ${status:-unknown})"
	fi
	set +e
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_ARTIFACT_DIR/session-list-current.txt" 2>&1
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
sleep 3
kill -0 "$client_pid" 2>/dev/null || fail "xfreerdp did not remain connected"
xwd -display :99 -root -silent -out "$FRDP_ARTIFACT_DIR/client-root.xwd" || true

stop_process "$client_pid"
client_pid=

for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$FRDP_ARTIFACT_DIR/session-list-after.txt" 2>&1 || true
	if grep -q '^No active sessions$' "$FRDP_ARTIFACT_DIR/session-list-after.txt"; then
		log "managed RDP session was cleaned after client disconnect"
		exit 0
	fi
	sleep 1
done

fail "managed session $session_id was not cleaned after disconnect"
