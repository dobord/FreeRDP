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
status_output=$(frdpctl status --socket "$socket" 2>&1) || status=$?
reachable=0
scrape_success=0
active_sessions=0
error=""

if [[ $status -eq 0 ]]; then
	reachable=1
	if [[ $status_output =~ Active[[:space:]]sessions:[[:space:]]([0-9]+) ]]; then
		active_sessions=${BASH_REMATCH[1]}
		scrape_success=1
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
	printf '# HELP frdp_sessions_active Active sessions reported by frdp-sesmand.\n'
	printf '# TYPE frdp_sessions_active gauge\n'
	printf 'frdp_sessions_active{socket="%s"} %d\n' "$(escape_label "$socket")" "$active_sessions"
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
