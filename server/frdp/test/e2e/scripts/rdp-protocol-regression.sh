#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_RDP_TARGET=${FRDP_RDP_TARGET:-frdpd-local:3389}
FRDP_TEST_USER=${FRDP_TEST_USER:-rdpuser}
FRDP_TEST_PASSWORD=${FRDP_TEST_PASSWORD:-RdpPassw0rd!}
FRDP_RDP_DOMAIN=${FRDP_RDP_DOMAIN:-}
FRDP_PROTOCOL_TIMEOUT=${FRDP_PROTOCOL_TIMEOUT:-45}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts/protocol}

mkdir -p "$FRDP_ARTIFACT_DIR"

log()
{
	printf '[frdp-protocol-regression] %s\n' "$*" | tee -a "$FRDP_ARTIFACT_DIR/protocol.log" >&2
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

build_base_args()
{
	RDP_ARGS=(
		"/v:${FRDP_RDP_TARGET}"
		"/u:${FRDP_TEST_USER}"
		"/p:${FRDP_TEST_PASSWORD}"
		"/cert:ignore"
		"/sec:nla"
		"/log-level:INFO"
	)
	if [[ -n $FRDP_RDP_DOMAIN ]]; then
		RDP_ARGS+=("/d:${FRDP_RDP_DOMAIN}")
	fi
}

run_case()
{
	local label=$1
	shift
	local logfile="$FRDP_ARTIFACT_DIR/${label}.log"
	local status=0

	build_base_args
	log "case=$label args=$*"
	set +e
	timeout "${FRDP_PROTOCOL_TIMEOUT}s" xvfb-run -a "$XFREERDP" "${RDP_ARGS[@]}" "$@" \
		"$AUTH_ONLY_ARG" >"$logfile" 2>&1
	status=$?
	set -e

	if [[ $status -ne 0 ]]; then
		log "case=$label failed status=$status logfile=$logfile"
		return 1
	fi
	log "case=$label ok"
	return 0
}

positive_integer "$FRDP_PROTOCOL_TIMEOUT" || fail "FRDP_PROTOCOL_TIMEOUT must be positive"
command -v timeout >/dev/null 2>&1 || fail "timeout executable was not found"
command -v xvfb-run >/dev/null 2>&1 || fail "xvfb-run executable was not found"
command -v nc >/dev/null 2>&1 || fail "nc executable was not found"

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

status=0
run_case nla-24bpp-lan "/size:1024x768" "/bpp:24" "/network:lan" || status=1
run_case nla-32bpp-broadband "/size:1280x720" "/bpp:32" "/network:broadband" || status=1
run_case nla-16bpp-modem "/size:800x600" "/bpp:16" "/network:modem" || status=1

if [[ $status -ne 0 ]]; then
	fail "one or more protocol regression cases failed"
fi

log "protocol regression completed"
