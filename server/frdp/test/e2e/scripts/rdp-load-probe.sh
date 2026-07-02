#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_RDP_TARGET=${FRDP_RDP_TARGET:-frdpd-local:3389}
FRDP_TEST_USER=${FRDP_TEST_USER:-rdpuser}
FRDP_TEST_PASSWORD=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
FRDP_RDP_DOMAIN=${FRDP_RDP_DOMAIN:-}
FRDP_LOAD_CONCURRENCY=${FRDP_LOAD_CONCURRENCY:-2}
FRDP_LOAD_ITERATIONS=${FRDP_LOAD_ITERATIONS:-3}
FRDP_LOAD_TIMEOUT=${FRDP_LOAD_TIMEOUT:-45}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts/load}

mkdir -p "$FRDP_ARTIFACT_DIR"

log()
{
	printf '[frdp-load-probe] %s\n' "$*" | tee -a "$FRDP_ARTIFACT_DIR/load.log" >&2
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

run_worker()
{
	local worker=$1
	local worker_dir="$FRDP_ARTIFACT_DIR/worker-$worker"

	mkdir -p "$worker_dir"
	for ((iteration = 1; iteration <= FRDP_LOAD_ITERATIONS; iteration++)); do
		local logfile="$worker_dir/auth-only-$iteration.log"
		local child_pid=
		local child_uses_process_group=0

		# shellcheck disable=SC2317
		cleanup_child()
		{
			if [[ -z ${child_pid:-} ]]; then
				return
			fi
			if [[ $child_uses_process_group -eq 1 ]]; then
				kill -TERM -- "-$child_pid" 2>/dev/null || true
			fi
			kill -TERM "$child_pid" 2>/dev/null || true
		}

		build_args
		trap cleanup_child TERM INT
		if command -v setsid >/dev/null 2>&1; then
			setsid timeout "${FRDP_LOAD_TIMEOUT}s" xvfb-run -a "$XFREERDP" "${RDP_ARGS[@]}" \
				"$AUTH_ONLY_ARG" >"$logfile" 2>&1 &
			child_uses_process_group=1
		else
			timeout "${FRDP_LOAD_TIMEOUT}s" xvfb-run -a "$XFREERDP" "${RDP_ARGS[@]}" \
				"$AUTH_ONLY_ARG" >"$logfile" 2>&1 &
		fi
		child_pid=$!
		if ! wait "$child_pid"; then
			child_pid=
			trap - TERM INT
			log "worker=$worker iteration=$iteration failed"
			return 1
		fi
		child_pid=
		trap - TERM INT
		log "worker=$worker iteration=$iteration ok"
	done
}

positive_integer "$FRDP_LOAD_CONCURRENCY" || fail "FRDP_LOAD_CONCURRENCY must be positive"
positive_integer "$FRDP_LOAD_ITERATIONS" || fail "FRDP_LOAD_ITERATIONS must be positive"
positive_integer "$FRDP_LOAD_TIMEOUT" || fail "FRDP_LOAD_TIMEOUT must be positive"

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
log "starting auth-only load: target=$FRDP_RDP_TARGET concurrency=$FRDP_LOAD_CONCURRENCY iterations=$FRDP_LOAD_ITERATIONS"

pids=()
cleanup_workers()
{
	for pid in "${pids[@]}"; do
		kill "$pid" 2>/dev/null || true
	done
}
trap cleanup_workers EXIT TERM INT

for ((worker = 1; worker <= FRDP_LOAD_CONCURRENCY; worker++)); do
	run_worker "$worker" &
	pids+=("$!")
done

status=0
for pid in "${pids[@]}"; do
	if ! wait "$pid"; then
		status=1
	fi
done

if [[ $status -ne 0 ]]; then
	fail "one or more load workers failed"
fi

log "auth-only load completed"
