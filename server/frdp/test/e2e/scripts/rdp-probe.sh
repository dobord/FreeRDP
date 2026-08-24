#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_RDP_TARGET=${FRDP_RDP_TARGET:-frdpd-local:3389}
FRDP_TEST_USER=${FRDP_TEST_USER:-rdpuser}
FRDP_TEST_PASSWORD=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
FRDP_DENY_USER=${FRDP_DENY_USER:-rdpdisabled}
FRDP_DENY_PASSWORD=${FRDP_DENY_PASSWORD:-DeniedPassw0rd!}
FRDP_DENY_LABEL=${FRDP_DENY_LABEL:-disabled-account}
FRDP_RDP_DOMAIN=${FRDP_RDP_DOMAIN:-}
FRDP_SESSION_SOCKET=${FRDP_SESSION_SOCKET:-/run/frdp-sesmand/sesmand.sock}
FRDP_E2E_TIMEOUT=${FRDP_E2E_TIMEOUT:-60}
FRDP_AUTH_TIMEOUT=${FRDP_AUTH_TIMEOUT:-45}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts}
FRDP_E2E_POLICY_RELOAD=${FRDP_E2E_POLICY_RELOAD:-0}
FRDP_E2E_FRDPD_RESTART=${FRDP_E2E_FRDPD_RESTART:-0}
FRDP_E2E_GRAPHICAL_LOAD_CONCURRENCY=${FRDP_E2E_GRAPHICAL_LOAD_CONCURRENCY:-0}
FRDP_E2E_CONTROL_DIR=${FRDP_E2E_CONTROL_DIR:-/run/frdp-e2e-control}
FRDP_DESKTOP_TYPE=${FRDP_DESKTOP_TYPE:-openbox}

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

nonnegative_integer()
{
	[[ $1 == 0 || $1 =~ ^[1-9][0-9]*$ ]]
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

wait_display_geometry()
{
	local display=$1
	local expected=$2
	local geometry=

	for ((attempt = 0; attempt < 100; attempt++)); do
		geometry=$(xdpyinfo -display "$display" 2>/dev/null |
			awk '$1 == "dimensions:" { print $2; exit }' || true)
		[[ $geometry == "$expected" ]] && return 0
		sleep 0.1
	done
	return 1
}

request_session_xauthority()
{
	local agent_pid=$1
	local request="$FRDP_E2E_CONTROL_DIR/xauthority-$agent_pid-request"
	local authority="$FRDP_E2E_CONTROL_DIR/xauthority-$agent_pid"

	: >"$request"
	for ((attempt = 0; attempt < 100; attempt++)); do
		if [[ -f $authority ]]; then
			[[ $(stat -c %a "$authority") == 400 ]] || return 1
			printf '%s\n' "$authority"
			return 0
		fi
		sleep 0.1
	done
	return 1
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
		"+disp"
		"+dynamic-resolution"
		"+clipboard"
		"-heartbeat"
		"-multitransport"
		"-auto-reconnect"
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

run_policy_denied_connection()
{
	local label=$1
	local logfile="$FRDP_ARTIFACT_DIR/auth-${label}.log"
	local status=0

	build_args "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
	set +e
	timeout "${FRDP_AUTH_TIMEOUT}s" xvfb-run -a "$XFREERDP" "${RDP_ARGS[@]}" \
		>"$logfile" 2>&1
	status=$?
	set -e
	[[ $status -ne 124 ]] || fail "policy-denied connection '$label' timed out"
	[[ $(grep -c 'Authentication complete' "$logfile" || true) -eq 1 ]] ||
		fail "policy-denied connection '$label' did not complete exactly one authentication"
	if grep -q "Caught signal 'Segmentation fault'" "$logfile"; then
		fail "policy-denied connection '$label' crashed"
	fi
	log "policy-denied connection '$label' completed with client status $status"
}

run_peer_limit_denied_connection()
{
	local label=$1
	local logfile="$FRDP_ARTIFACT_DIR/peer-limit-denied-${label}.log"
	local status=0

	build_args "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
	set +e
	timeout "${FRDP_AUTH_TIMEOUT}s" xvfb-run -a "$XFREERDP" "${RDP_ARGS[@]}" \
		>"$logfile" 2>&1
	status=$?
	set -e
	[[ $status -ne 124 ]] || fail "peer-limit denied connection timed out"
	[[ $(grep -c 'Authentication complete' "$logfile" || true) -eq 0 ]] ||
		fail "peer-limit denied connection reached authentication"
	if grep -q "Caught signal 'Segmentation fault'" "$logfile"; then
		fail "peer-limit denied connection crashed"
	fi
	log "peer-limit denied connection '$label' completed before authentication with client status $status"
}

request_policy_reload()
{
	local mode=$1
	local ready="$FRDP_E2E_CONTROL_DIR/policy-reload-${mode}-ready"
	local request="$FRDP_E2E_CONTROL_DIR/policy-reload-${mode}-request"

	rm -f "$ready"
	: >"$request"
	for ((i = 0; i < 100; i++)); do
		if [[ -f $ready ]] && grep -Fxq "mode=$mode" "$ready" &&
			grep -Fxq 'result=pass' "$ready"; then
			log "frdpd policy reload command completed: $mode"
			return 0
		fi
		sleep 0.1
	done
	fail "frdpd policy reload command timed out: $mode"
}

request_frdpd_restart()
{
	local state="$FRDP_E2E_CONTROL_DIR/frdpd-state"
	local old_pid=
	local new_pid=
	local generation=

	old_pid=$(sed -n 's/^pid=//p' "$state")
	generation=$(sed -n 's/^generation=//p' "$state")
	[[ $old_pid =~ ^[1-9][0-9]*$ && $generation == 0 ]] ||
		fail "initial frdpd supervisor state is invalid"
	: >"$FRDP_E2E_CONTROL_DIR/frdpd-restart-request"
	for ((i = 0; i < FRDP_E2E_TIMEOUT * 10; i++)); do
		new_pid=$(sed -n 's/^pid=//p' "$state" 2>/dev/null || true)
		generation=$(sed -n 's/^generation=//p' "$state" 2>/dev/null || true)
		if [[ $new_pid =~ ^[1-9][0-9]*$ && $generation == 1 && $new_pid != "$old_pid" ]]; then
			wait_tcp || fail "restarted frdpd did not reopen the RDP endpoint"
			printf 'old_pid=%s\nnew_pid=%s\nresult=pass\n' "$old_pid" "$new_pid" \
				>"$FRDP_ARTIFACT_DIR/frdpd-restart.txt"
			log "frdpd restarted cleanly: $old_pid -> $new_pid"
			return 0
		fi
		sleep 0.1
	done
	fail "frdpd restart did not publish a replacement process"
}

assert_no_managed_sessions()
{
	local label=$1
	local logfile="$FRDP_ARTIFACT_DIR/session-list-after-auth-${label}.txt"
	local runtime_log="$FRDP_ARTIFACT_DIR/session-runtime-after-auth-${label}.txt"
	local socket_dir socket_name

	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$logfile" 2>&1 ||
		fail "failed to list sessions after auth-only '$label'"
	grep -Fxq 'No active sessions' "$logfile" ||
		fail "auth-only '$label' left a managed session"
	socket_dir=$(dirname "$FRDP_SESSION_SOCKET")
	socket_name=$(basename "$FRDP_SESSION_SOCKET")
	find "$socket_dir" -mindepth 1 -maxdepth 1 ! -name "$socket_name" -printf '%f\n' \
		>"$runtime_log"
	[[ ! -s $runtime_log ]] ||
		fail "auth-only '$label' left managed session runtime artifacts"
}

cleanup_auth_only_session()
{
	local i session_id='' session_user='' session_count=0
	local logfile="$FRDP_ARTIFACT_DIR/session-list-after-auth-valid.txt"

	for ((i = 0; i < 20; i++)); do
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$logfile" 2>&1 ||
			fail "failed to list sessions after valid auth-only probe"
		if grep -Fxq 'No active sessions' "$logfile"; then
			session_count=0
			session_id=''
			session_user=''
		else
			session_count=$(awk 'NR > 1 { count++ } END { print count + 0 }' "$logfile")
			read -r session_id session_user < <(awk 'NR == 2 { print $1, $2 }' "$logfile") || true
		fi
		if [[ $session_count -eq 1 && $session_user == "$FRDP_TEST_USER" && -n $session_id ]]; then
			break
		fi
		sleep 0.25
	done
	[[ $session_count -eq 1 && $session_user == "$FRDP_TEST_USER" && -n $session_id ]] ||
		fail "valid auth-only probe produced an unexpected session registry"
	frdpctl kill-session "$session_id" --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-kill-after-auth-valid.txt" 2>&1 ||
		fail "failed to clean the valid auth-only session $session_id"
	for ((i = 0; i < FRDP_E2E_TIMEOUT; i++)); do
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
			>"$FRDP_ARTIFACT_DIR/session-list-after-auth-valid-cleanup.txt" 2>&1 || true
		if grep -Fxq 'No active sessions' \
			"$FRDP_ARTIFACT_DIR/session-list-after-auth-valid-cleanup.txt"; then
			log "valid auth-only managed session was cleaned"
			return 0
		fi
		sleep 1
	done
	fail "valid auth-only managed session $session_id was not cleaned"
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

run_graphical_load()
{
	local concurrency=$1
	local active_list="$FRDP_ARTIFACT_DIR/graphical-load-active.txt"
	local current_list="$FRDP_ARTIFACT_DIR/graphical-load-current.txt"
	local detached_list="$FRDP_ARTIFACT_DIR/graphical-load-detached.txt"
	local cleanup_list="$FRDP_ARTIFACT_DIR/graphical-load-cleanup.txt"
	local capacity_list="$FRDP_ARTIFACT_DIR/graphical-load-at-capacity.txt"
	local reconnect_detached_list="$FRDP_ARTIFACT_DIR/graphical-load-reconnect-detached.txt"
	local reconnect_list="$FRDP_ARTIFACT_DIR/graphical-load-reconnected.txt"
	local reconnect_log="$FRDP_ARTIFACT_DIR/graphical-load-reconnect.log"
	local rejected_log="$FRDP_ARTIFACT_DIR/graphical-load-limit-rejected.log"
	local runtime_log="$FRDP_ARTIFACT_DIR/graphical-load-runtime.txt"
	local attempt socket_dir socket_name session_id pid worker rejected_status=0
	local -a session_ids=()

	((concurrency > 0)) || return 0
	rm -f "$active_list" "$current_list" "$detached_list" "$cleanup_list" "$capacity_list" \
		"$reconnect_detached_list" "$reconnect_list" "$reconnect_log" "$rejected_log" \
		"$runtime_log" "$FRDP_ARTIFACT_DIR/graphical-load-result.txt"
	build_args "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
	load_pids=()
	for ((worker = 1; worker <= concurrency; worker++)); do
		stdbuf -oL -eL "$XFREERDP" "${RDP_ARGS[@]}" \
			>"$FRDP_ARTIFACT_DIR/graphical-load-worker-$worker.log" 2>&1 &
		load_pids+=("$!")
	done

	for ((attempt = 0; attempt < FRDP_E2E_TIMEOUT * 10; attempt++)); do
		for pid in "${load_pids[@]}"; do
			process_is_running "$pid" || fail "graphical load client $pid exited before activation"
		done
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$current_list" 2>&1 || true
		if awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
			NR > 1 {
				total++
				if ($1 == "" || $2 != user || $3 !~ /^:[0-9]+$/ || $4 != "active" ||
				    $5 !~ /^[1-9][0-9]*$/ || seen_id[$1]++ || seen_display[$3]++ ||
				    seen_pid[$5]++)
					bad = 1
			}
			END { exit (total == expected && !bad) ? 0 : 1 }
		' "$current_list"; then
			cp "$current_list" "$active_list"
			break
		fi
		sleep 0.1
	done
	[[ -s $active_list ]] || fail "graphical load did not activate $concurrency unique sessions"
	mapfile -t session_ids < <(awk 'NR > 1 { print $1 }' "$active_list")
	[[ ${#session_ids[@]} -eq $concurrency ]] || fail "graphical load session count changed"

	stop_process "${load_pids[0]}"
	for ((attempt = 0; attempt < FRDP_E2E_TIMEOUT * 10; attempt++)); do
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$reconnect_detached_list" 2>&1 || true
		if awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
			NR > 1 {
				total++
				if ($2 != user || ($4 != "active" && $4 != "disconnected")) bad = 1
				if ($4 == "disconnected") disconnected++
			}
			END { exit (total == expected && disconnected == 1 && !bad) ? 0 : 1 }
		' "$reconnect_detached_list"; then
			break
		fi
		sleep 0.1
	done
	awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
		NR > 1 {
			total++
			if ($2 != user || ($4 != "active" && $4 != "disconnected")) bad = 1
			if ($4 == "disconnected") disconnected++
		}
		END { exit (total == expected && disconnected == 1 && !bad) ? 0 : 1 }
	' "$reconnect_detached_list" || fail "graphical load client did not detach at capacity"
	stdbuf -oL -eL "$XFREERDP" "${RDP_ARGS[@]}" >"$reconnect_log" 2>&1 &
	load_pids[0]=$!
	for ((attempt = 0; attempt < FRDP_E2E_TIMEOUT * 10; attempt++)); do
		for pid in "${load_pids[@]}"; do
			process_is_running "$pid" || fail "graphical load client $pid exited during reconnect"
		done
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$reconnect_list" 2>&1 || true
		if awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
			NR > 1 {
				total++
				if ($1 == "" || $2 != user || $3 !~ /^:[0-9]+$/ || $4 != "active" ||
				    $5 !~ /^[1-9][0-9]*$/ || seen_id[$1]++ || seen_display[$3]++ || seen_pid[$5]++)
					bad = 1
			}
			END { exit (total == expected && !bad) ? 0 : 1 }
		' "$reconnect_list" &&
			cmp -s <(awk 'NR > 1 { print $1, $2, $3, $5 }' "$active_list" | sort) \
				<(awk 'NR > 1 { print $1, $2, $3, $5 }' "$reconnect_list" | sort); then
			break
		fi
		sleep 0.1
	done
	[[ $(grep -c 'Authentication complete' "$reconnect_log" || true) -eq 1 ]] ||
		fail "graphical load reconnect did not complete exactly one authentication"
	cmp -s <(awk 'NR > 1 { print $1, $2, $3, $5 }' "$active_list" | sort) \
		<(awk 'NR > 1 && $4 == "active" { print $1, $2, $3, $5 }' "$reconnect_list" | sort) ||
		fail "graphical load reconnect at capacity changed managed session identity"

	set +e
	timeout "${FRDP_AUTH_TIMEOUT}s" "$XFREERDP" "${RDP_ARGS[@]}" >"$rejected_log" 2>&1
	rejected_status=$?
	set -e
	[[ $rejected_status -ne 124 ]] || fail "graphical load capacity probe timed out"
	[[ $(grep -c 'Authentication complete' "$rejected_log" || true) -eq 1 ]] ||
		fail "graphical load capacity probe did not complete exactly one authentication"
	for pid in "${load_pids[@]}"; do
		process_is_running "$pid" || fail "graphical load client $pid exited during capacity rejection"
	done
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$capacity_list" 2>&1 ||
		fail "failed to list graphical sessions after capacity rejection"
	awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
		NR > 1 {
			total++
			if ($1 == "" || $2 != user || $3 !~ /^:[0-9]+$/ || $4 != "active" ||
			    $5 !~ /^[1-9][0-9]*$/ || seen_id[$1]++ || seen_display[$3]++ || seen_pid[$5]++)
				bad = 1
		}
		END { exit (total == expected && !bad) ? 0 : 1 }
	' "$capacity_list" || fail "capacity rejection changed the held graphical sessions"

	for pid in "${load_pids[@]}"; do
		stop_process "$pid"
	done
	load_pids=()
	for ((attempt = 0; attempt < FRDP_E2E_TIMEOUT * 10; attempt++)); do
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$detached_list" 2>&1 || true
		if awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
			NR > 1 { total++; if ($2 != user || $4 != "disconnected") bad = 1 }
			END { exit (total == expected && !bad) ? 0 : 1 }
		' "$detached_list"; then
			break
		fi
		sleep 0.1
	done
	awk -v expected="$concurrency" -v user="$FRDP_TEST_USER" '
		NR > 1 { total++; if ($2 != user || $4 != "disconnected") bad = 1 }
		END { exit (total == expected && !bad) ? 0 : 1 }
	' "$detached_list" || fail "graphical load sessions did not detach cleanly"

	for session_id in "${session_ids[@]}"; do
		frdpctl kill-session "$session_id" --socket "$FRDP_SESSION_SOCKET" >/dev/null ||
			fail "failed to clean graphical load session $session_id"
	done
	for ((attempt = 0; attempt < FRDP_E2E_TIMEOUT * 10; attempt++)); do
		frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" >"$cleanup_list" 2>&1 || true
		grep -Fxq 'No active sessions' "$cleanup_list" && break
		sleep 0.1
	done
	grep -Fxq 'No active sessions' "$cleanup_list" ||
		fail "graphical load sessions remained after cleanup"
	socket_dir=$(dirname "$FRDP_SESSION_SOCKET")
	socket_name=$(basename "$FRDP_SESSION_SOCKET")
	find "$socket_dir" -mindepth 1 -maxdepth 1 ! -name "$socket_name" -printf '%f\n' \
		>"$runtime_log"
	[[ ! -s $runtime_log ]] || fail "graphical load left managed session runtime artifacts"
	printf 'concurrency=%s\nunique_session_ids=pass\nunique_displays=pass\nunique_agent_pids=pass\nreconnect_at_limit=pass\nlimit_rejection=pass\ncleanup=pass\n' \
		"$concurrency" >"$FRDP_ARTIFACT_DIR/graphical-load-result.txt"
	log "concurrent graphical load passed with admission limit for $concurrency managed sessions"
}

positive_integer "$FRDP_E2E_TIMEOUT" || fail "FRDP_E2E_TIMEOUT must be positive"
positive_integer "$FRDP_AUTH_TIMEOUT" || fail "FRDP_AUTH_TIMEOUT must be positive"
[[ $FRDP_E2E_POLICY_RELOAD == 0 || $FRDP_E2E_POLICY_RELOAD == 1 ]] ||
	fail "FRDP_E2E_POLICY_RELOAD must be 0 or 1"
[[ $FRDP_E2E_FRDPD_RESTART == 0 || $FRDP_E2E_FRDPD_RESTART == 1 ]] ||
	fail "FRDP_E2E_FRDPD_RESTART must be 0 or 1"
nonnegative_integer "$FRDP_E2E_GRAPHICAL_LOAD_CONCURRENCY" ||
	fail "FRDP_E2E_GRAPHICAL_LOAD_CONCURRENCY must be nonnegative"
command -v timeout >/dev/null 2>&1 || fail "timeout executable was not found"
command -v xvfb-run >/dev/null 2>&1 || fail "xvfb-run executable was not found"
command -v Xvfb >/dev/null 2>&1 || fail "Xvfb executable was not found"
command -v xwd >/dev/null 2>&1 || fail "xwd executable was not found"
command -v xdotool >/dev/null 2>&1 || fail "xdotool executable was not found"
command -v xclip >/dev/null 2>&1 || fail "xclip executable was not found"
command -v ps >/dev/null 2>&1 || fail "ps executable was not found"
command -v nc >/dev/null 2>&1 || fail "nc executable was not found"
command -v find >/dev/null 2>&1 || fail "find executable was not found"
command -v stdbuf >/dev/null 2>&1 || fail "stdbuf executable was not found"
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
cleanup_auth_only_session
run_auth_only wrong-password failure "$FRDP_TEST_USER" "${FRDP_TEST_PASSWORD}--wrong"
assert_no_managed_sessions wrong-password
run_auth_only "$FRDP_DENY_LABEL" failure "$FRDP_DENY_USER" "$FRDP_DENY_PASSWORD"
assert_no_managed_sessions "$FRDP_DENY_LABEL"

Xvfb :99 -screen 0 1024x768x24 -nolisten tcp >"$FRDP_ARTIFACT_DIR/client-xvfb.log" 2>&1 &
xvfb_pid=$!
client_pid=
client_clipboard_pid=
server_clipboard_pid=
load_pids=()
# ShellCheck cannot infer that the signal/exit trap invokes this function.
# shellcheck disable=SC2317
cleanup()
{
	if [[ -n ${client_clipboard_pid:-} ]]; then
		stop_process "$client_clipboard_pid"
	fi
	if [[ -n ${server_clipboard_pid:-} ]]; then
		stop_process "$server_clipboard_pid"
	fi
	if [[ -n ${client_pid:-} ]]; then
		stop_process "$client_pid"
	fi
	for pid in "${load_pids[@]}"; do
		stop_process "$pid"
	done
	stop_process "$xvfb_pid"
}
trap cleanup EXIT TERM INT

for ((i = 0; i < 100; i++)); do
	[[ -S /tmp/.X11-unix/X99 ]] && break
	sleep 0.1
done
[[ -S /tmp/.X11-unix/X99 ]] || fail "client Xvfb did not start"

export DISPLAY=:99
run_graphical_load "$FRDP_E2E_GRAPHICAL_LOAD_CONCURRENCY"
build_args "$FRDP_TEST_USER" "$FRDP_TEST_PASSWORD"
stdbuf -oL -eL "$XFREERDP" "${RDP_ARGS[@]}" >"$FRDP_ARTIFACT_DIR/rdp-session.log" 2>&1 &
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
XAUTHORITY=$(request_session_xauthority "$open_pid") ||
	fail "failed to obtain the isolated test Xauthority for agent $open_pid"
export XAUTHORITY
for ((i = 0; i < 450; i++)); do
	if DISPLAY="$open_display" xwininfo -root -tree 2>/dev/null |
		grep -F 'FRDP Test Desktop' >/dev/null; then
		break
	fi
	sleep 0.1
done
DISPLAY="$open_display" xwininfo -root -tree 2>/dev/null |
	grep -F 'FRDP Test Desktop' >/dev/null || fail "managed display did not start the test desktop"
desktop_property=$(DISPLAY="$open_display" xprop -root _FRDP_TEST_DESKTOP_TYPE 2>/dev/null || true)
grep -Fq "= \"$FRDP_DESKTOP_TYPE\"" <<<"$desktop_property" ||
	fail "managed display started the wrong desktop: $desktop_property"
log "managed display $FRDP_DESKTOP_TYPE test desktop is visible"

client_clipboard_text=$'client-to-server FreeRDP clipboard UTF-8: Привет \360\237\214\215'
printf '%s' "$client_clipboard_text" | xclip -selection clipboard -in &
client_clipboard_pid=$!
server_clipboard_text=
for ((i = 0; i < 100; i++)); do
	server_clipboard_text=$(DISPLAY="$open_display" timeout 1s xclip -selection clipboard -out 2>/dev/null || true)
	[[ $server_clipboard_text == "$client_clipboard_text" ]] && break
	sleep 0.1
done
[[ $server_clipboard_text == "$client_clipboard_text" ]] ||
	fail "client-to-server Unicode clipboard transfer failed"
log "client-to-server Unicode clipboard transfer passed"

server_clipboard_text=$'server-to-client FreeRDP clipboard UTF-8: Мир \360\237\232\200'
printf '%s' "$server_clipboard_text" | DISPLAY="$open_display" xclip -selection clipboard -in &
server_clipboard_pid=$!
client_clipboard_text=
for ((i = 0; i < 100; i++)); do
	client_clipboard_text=$(DISPLAY=:99 timeout 1s xclip -selection clipboard -out 2>/dev/null || true)
	[[ $client_clipboard_text == "$server_clipboard_text" ]] && break
	sleep 0.1
done
[[ $client_clipboard_text == "$server_clipboard_text" ]] ||
	fail "server-to-client Unicode clipboard transfer failed"
log "server-to-client Unicode clipboard transfer passed"
if [[ $FRDP_E2E_POLICY_RELOAD == 1 ]]; then
	request_policy_reload capacity
	run_peer_limit_denied_connection config-reload
	process_is_running "$client_pid" || fail "active peer was disconnected by admission reload"
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after-admission-reload.txt" 2>&1 ||
		fail "failed to list the active session after admission reload"
	session_identity_is_exclusively_active \
		"$FRDP_ARTIFACT_DIR/session-list-after-admission-reload.txt" "$session_id" \
		"$FRDP_TEST_USER" "$open_display" "$open_pid" ||
		fail "admission reload changed or duplicated the active managed session"
	request_policy_reload deny
	run_policy_denied_connection reload-denied
	process_is_running "$client_pid" || fail "active peer was disconnected by policy reload"
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after-policy-deny.txt" 2>&1 ||
		fail "failed to list the active session after policy deny reload"
	session_identity_is_exclusively_active \
		"$FRDP_ARTIFACT_DIR/session-list-after-policy-deny.txt" "$session_id" "$FRDP_TEST_USER" \
		"$open_display" "$open_pid" ||
		fail "policy reload changed or duplicated the active managed session"

	stop_process "$client_clipboard_pid"
	client_clipboard_pid=
	client_clipboard_text='client-to-server clipboard after deny reload'
	printf '%s' "$client_clipboard_text" | xclip -selection clipboard -in &
	client_clipboard_pid=$!
	server_clipboard_text=
	for ((i = 0; i < 100; i++)); do
		server_clipboard_text=$(DISPLAY="$open_display" timeout 1s xclip -selection clipboard -out 2>/dev/null || true)
		[[ $server_clipboard_text == "$client_clipboard_text" ]] && break
		sleep 0.1
	done
	[[ $server_clipboard_text == "$client_clipboard_text" ]] ||
		fail "active peer lost its clipboard policy snapshot after reload"
	log "active peer retained its channel and clipboard policy snapshot"

	request_policy_reload malformed
	run_policy_denied_connection reload-malformed-retained-deny
	process_is_running "$client_pid" || fail "active peer was disconnected by failed policy reload"
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after-malformed-policy-reload.txt" 2>&1 ||
		fail "failed to list the active session after malformed policy reload"
	session_identity_is_exclusively_active \
		"$FRDP_ARTIFACT_DIR/session-list-after-malformed-policy-reload.txt" "$session_id" \
		"$FRDP_TEST_USER" "$open_display" "$open_pid" ||
		fail "failed policy reload changed or duplicated the active managed session"
	request_policy_reload restore
	log "invalid reload retained the last policy and the original policy was restored"
fi
for ((i = 0; i < 100; i++)); do
	grep -q "DisplayControlCapsPdu" "$FRDP_ARTIFACT_DIR/rdp-session.log" && break
	sleep 0.1
done
grep -q "DisplayControlCapsPdu" "$FRDP_ARTIFACT_DIR/rdp-session.log" ||
	fail "xfreerdp did not receive Display Control capabilities"
window_id=$(xdotool search --onlyvisible --class xfreerdp | head -n 1 || true)
[[ -n $window_id ]] || fail "xfreerdp window was not found"
xdotool windowsize --sync "$window_id" 800 600 || fail "failed to resize the xfreerdp window"
for ((i = 0; i < 100; i++)); do
	grep -q "ConfigureNotify (800x600)" "$FRDP_ARTIFACT_DIR/rdp-session.log" && break
	sleep 0.1
done
grep -q "ConfigureNotify (800x600)" "$FRDP_ARTIFACT_DIR/rdp-session.log" ||
	fail "xfreerdp did not observe the requested window resize"
wait_display_geometry "$open_display" 800x600 ||
	fail "managed display did not apply the 800x600 Display Control layout"
xdotool windowsize --sync "$window_id" 1024 768 || fail "failed to restore the xfreerdp window size"
wait_display_geometry "$open_display" 1024x768 ||
	fail "managed display did not apply the restored 1024x768 layout"
xdotool windowsize --sync "$window_id" 800 600 || fail "failed to repeat the xfreerdp window resize"
wait_display_geometry "$open_display" 800x600 ||
	fail "managed display did not apply the repeated 800x600 layout"
log "managed Xorg dummy display completed 800x600 -> 1024x768 -> 800x600 resize churn"
sleep 1
process_is_running "$client_pid" || fail "xfreerdp did not remain connected"
frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
	>"$FRDP_ARTIFACT_DIR/session-list-open-held.txt" 2>&1 ||
	fail "failed to list the held managed session"
session_identity_is_exclusively_active "$FRDP_ARTIFACT_DIR/session-list-open-held.txt" \
	"$session_id" "$FRDP_TEST_USER" "$open_display" "$open_pid" ||
	fail "managed session $session_id did not remain exclusively active"
xwd -display :99 -root -silent -out "$FRDP_ARTIFACT_DIR/client-root.xwd" ||
	fail "failed to capture the client Xvfb display"

if [[ $FRDP_E2E_FRDPD_RESTART == 1 ]]; then
	request_frdpd_restart
	for ((i = 0; i < FRDP_E2E_TIMEOUT * 10; i++)); do
		process_is_running "$client_pid" || break
		sleep 0.1
	done
	process_is_running "$client_pid" && fail "old frdpd did not disconnect the active client"
	wait "$client_pid" 2>/dev/null || true
	client_pid=
	log "daemon restart disconnected the peer before reconnect"
else
	stop_process "$client_pid"
	client_pid=
fi

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
stdbuf -oL -eL "$XFREERDP" "${RDP_ARGS[@]}" >"$FRDP_ARTIFACT_DIR/rdp-reconnect.log" 2>&1 &
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
if [[ $FRDP_E2E_POLICY_RELOAD == 1 ]]; then
	request_policy_reload cli
	run_peer_limit_denied_connection cli-override
	process_is_running "$client_pid" || fail "CLI admission override reload disconnected the active peer"
	frdpctl list-sessions --socket "$FRDP_SESSION_SOCKET" \
		>"$FRDP_ARTIFACT_DIR/session-list-after-cli-admission-reload.txt" 2>&1 ||
		fail "failed to list the active session after CLI admission override reload"
	session_identity_is_exclusively_active \
		"$FRDP_ARTIFACT_DIR/session-list-after-cli-admission-reload.txt" "$session_id" \
		"$FRDP_TEST_USER" "$open_display" "$open_pid" ||
		fail "CLI admission override reload changed or duplicated the active managed session"
	log "explicit CLI admission limit remained authoritative after config reload"
fi
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
		sleep 2
		exit 0
	fi
	sleep 1
done

fail "managed session $session_id was not cleaned after explicit kill-session"
