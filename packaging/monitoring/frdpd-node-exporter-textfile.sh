#!/usr/bin/env bash
set -Eeuo pipefail

socket=/run/frdp-sesmand/sesmand.sock
output=/var/lib/node_exporter/textfile_collector/frdpd.prom
max_connections=${FRDP_MAX_CONNECTIONS:-}

usage()
{
	cat >&2 <<EOF
Usage: $0 [--socket <path>] [--output <path>] [--max-connections <count>]

Scrape frdp-sesmand through frdpctl and write Prometheus node_exporter
textfile metrics atomically.
EOF
}

positive_integer()
{
	[[ $1 =~ ^[1-9][0-9]*$ ]]
}

escape_label()
{
	local value=$1

	value=${value//\\/\\\\}
	value=${value//\"/\\\"}
	value=${value//$'\n'/\\n}
	printf '%s' "$value"
}

escape_comment()
{
	local value=$1

	value=${value//$'\n'/; }
	printf '%s' "$value"
}

record_session_state()
{
	local state=$1
	local index

	for index in "${!session_states[@]}"; do
		if [[ ${session_states[$index]} == "$state" ]]; then
			session_state_counts[$index]=$((session_state_counts[$index] + 1))
			return
		fi
	done
	session_states+=("$state")
	session_state_counts+=(1)
}

while [[ $# -gt 0 ]]; do
	case "$1" in
		--socket)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			socket=$2
			shift 2
			;;
		--output)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			output=$2
			shift 2
			;;
		--max-connections)
			[[ $# -ge 2 ]] || { usage; exit 2; }
			max_connections=$2
			shift 2
			;;
		-h|--help)
			usage
			exit 0
			;;
		*)
			usage
			exit 2
			;;
	esac
done

if [[ -n $max_connections ]] && ! positive_integer "$max_connections"; then
	echo "max connections must be a positive integer" >&2
	exit 2
fi

output_dir=$(dirname "$output")
mkdir -p "$output_dir"
tmp=$(mktemp "${output}.XXXXXX")
cleanup()
{
	rm -f "$tmp"
}
trap cleanup EXIT

status=0
scrape_timestamp=$(date +%s)
status_output=$(frdpctl status --socket "$socket" 2>&1) || status=$?
reachable=0
scrape_success=0
detail_scrape_success=0
active_sessions=0
session_details=()
session_states=()
session_state_counts=()
error=""

if [[ $status -eq 0 ]]; then
	reachable=1
	if [[ $status_output =~ Active[[:space:]]sessions:[[:space:]]([0-9]+) ]]; then
		active_sessions=${BASH_REMATCH[1]}
		scrape_success=1
		detail_status=0
		detail_output=$(frdpctl list-sessions --socket "$socket" 2>&1) || detail_status=$?
		if [[ $detail_status -eq 0 ]]; then
			detail_scrape_success=1
			while IFS= read -r line; do
				[[ -n $line ]] || continue
				[[ $line == SESSION* ]] && continue
				[[ $line == "No active sessions" ]] && continue
				read -r session_id session_user session_display session_state session_pid _ <<<"$line"
				if [[ -n ${session_id:-} && -n ${session_user:-} && -n ${session_display:-} &&
				      -n ${session_state:-} &&
				      ${session_pid:-} =~ ^-?[0-9]+$ ]]; then
					session_details+=("${session_id}"$'\t'"${session_user}"$'\t'"${session_display}"$'\t'"${session_state}"$'\t'"${session_pid}")
					record_session_state "$session_state"
				fi
			done <<<"$detail_output"
		else
			error="session detail scrape failed: $detail_output"
		fi
	else
		error="missing active session count"
	fi
else
	error=$status_output
fi

{
	printf '# HELP frdp_sesmand_reachable Whether frdpctl can reach frdp-sesmand over the configured control socket.\n'
	printf '# TYPE frdp_sesmand_reachable gauge\n'
	printf 'frdp_sesmand_reachable{socket="%s"} %d\n' "$(escape_label "$socket")" "$reachable"
	printf '# HELP frdp_exporter_scrape_success Whether this textfile scrape completed and parsed successfully.\n'
	printf '# TYPE frdp_exporter_scrape_success gauge\n'
	printf 'frdp_exporter_scrape_success{socket="%s"} %d\n' "$(escape_label "$socket")" "$scrape_success"
	printf '# HELP frdp_exporter_last_scrape_timestamp_seconds Unix timestamp when this FRDP textfile collector last ran.\n'
	printf '# TYPE frdp_exporter_last_scrape_timestamp_seconds gauge\n'
	printf 'frdp_exporter_last_scrape_timestamp_seconds{socket="%s"} %d\n' \
		"$(escape_label "$socket")" "$scrape_timestamp"
	printf '# HELP frdp_sessions_active Active sessions reported by frdp-sesmand.\n'
	printf '# TYPE frdp_sessions_active gauge\n'
	printf 'frdp_sessions_active{socket="%s"} %d\n' "$(escape_label "$socket")" "$active_sessions"
	printf '# HELP frdp_sessions_detail_scrape_success Whether per-session detail scraping completed and parsed successfully.\n'
	printf '# TYPE frdp_sessions_detail_scrape_success gauge\n'
	printf 'frdp_sessions_detail_scrape_success{socket="%s"} %d\n' \
		"$(escape_label "$socket")" "$detail_scrape_success"
	if [[ ${#session_details[@]} -gt 0 ]]; then
		printf '# HELP frdp_sessions_info Per-session metadata reported by frdpctl list-sessions.\n'
		printf '# TYPE frdp_sessions_info gauge\n'
		for detail in "${session_details[@]}"; do
			IFS=$'\t' read -r session_id session_user session_display session_state session_pid <<<"$detail"
			printf 'frdp_sessions_info{socket="%s",session_id="%s",user="%s",display="%s",state="%s",agent_pid="%s"} 1\n' \
				"$(escape_label "$socket")" "$(escape_label "$session_id")" \
				"$(escape_label "$session_user")" "$(escape_label "$session_display")" \
				"$(escape_label "$session_state")" \
				"$(escape_label "$session_pid")"
		done
		printf '# HELP frdp_sessions_state Sessions grouped by lifecycle state reported by frdpctl list-sessions.\n'
		printf '# TYPE frdp_sessions_state gauge\n'
		for index in "${!session_states[@]}"; do
			printf 'frdp_sessions_state{socket="%s",state="%s"} %d\n' \
				"$(escape_label "$socket")" "$(escape_label "${session_states[$index]}")" \
				"${session_state_counts[$index]}"
		done
	fi
	if [[ -n $max_connections ]]; then
		printf '# HELP frdp_sessions_max Configured maximum concurrent frdpd sessions.\n'
		printf '# TYPE frdp_sessions_max gauge\n'
		printf 'frdp_sessions_max{socket="%s"} %d\n' "$(escape_label "$socket")" "$max_connections"
		if [[ $scrape_success -eq 1 ]]; then
			utilization=$(awk -v active="$active_sessions" -v max="$max_connections" \
				'BEGIN { printf "%.6f", active / max }')
			printf '# HELP frdp_sessions_utilization_ratio Active sessions divided by configured maximum sessions.\n'
			printf '# TYPE frdp_sessions_utilization_ratio gauge\n'
			printf 'frdp_sessions_utilization_ratio{socket="%s"} %s\n' \
				"$(escape_label "$socket")" "$utilization"
		fi
	fi
	if [[ -n $error ]]; then
		printf '# Last frdpctl scrape error: %s\n' "$(escape_comment "$error")"
		printf '# HELP frdp_exporter_last_error Last frdpctl scrape error exposed as an info metric.\n'
		printf '# TYPE frdp_exporter_last_error gauge\n'
		printf 'frdp_exporter_last_error{socket="%s"} 1\n' "$(escape_label "$socket")"
	fi
} >"$tmp"

chmod 0644 "$tmp"
mv "$tmp" "$output"
trap - EXIT
