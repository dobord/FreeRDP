#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
tmp=$(mktemp -d "${TMPDIR:-/tmp}/frdp-e2e-runner-test.XXXXXX")

cleanup()
{
	rm -rf "$tmp"
}
trap cleanup EXIT

mkdir -p "$tmp/bin"
cat >"$tmp/bin/git" <<'EOF'
#!/usr/bin/env bash
printf '%040d\n' 0
EOF
cat >"$tmp/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu

for arg in "$@"; do
	if [[ $arg == version ]]; then
		exit 0
	fi
	if [[ $arg == down ]]; then
		printf '%s\n' "$*" >>"$FRDP_FAKE_DOWN_LOG"
		exit 0
	fi
	if [[ $arg == up ]]; then
		printf '%s\n' "$*" >>"$FRDP_FAKE_UP_LOG"
		count=0
		[[ ! -f $FRDP_FAKE_COUNTER ]] || count=$(<"$FRDP_FAKE_COUNTER")
		count=$((count + 1))
		printf '%s\n' "$count" >"$FRDP_FAKE_COUNTER"
		IFS=, read -r -a statuses <<<"$FRDP_FAKE_STATUSES"
		if [[ ${FRDP_FAKE_INCOMPLETE:-0} == 1 && $count -eq 1 ]]; then
			: >"$FRDP_E2E_ARTIFACTS/component/container-logs"
		fi
		exit "${statuses[count - 1]:-${statuses[-1]}}"
	fi
done
exit 0
EOF
cat >"$tmp/bin/cp" <<'EOF'
#!/usr/bin/env bash
set -eu

if [[ ${FRDP_FAKE_FINALIZE_SIGNAL:-0} == 1 && ! -e $FRDP_FAKE_SIGNAL_MARKER ]]; then
	: >"$FRDP_FAKE_SIGNAL_MARKER"
	kill -TERM "$PPID"
fi
exec /bin/cp "$@"
EOF
cat >"$tmp/bin/mv" <<'EOF'
#!/usr/bin/env bash
set -eu

destination=${!#}
/bin/mv "$@"
status=$?
if [[ $status -eq 0 && ${FRDP_FAKE_MOVE_SIGNAL:-0} == 1 &&
	$destination == */run-1 && ! -e $FRDP_FAKE_MOVE_SIGNAL_MARKER ]]; then
	: >"$FRDP_FAKE_MOVE_SIGNAL_MARKER"
	kill -TERM "$PPID"
fi
exit "$status"
EOF
chmod 0755 "$tmp/bin/git" "$tmp/bin/docker" "$tmp/bin/cp" "$tmp/bin/mv"

run_case()
{
	local name=$1
	local repetitions=$2
	local statuses=$3
	local incomplete=${4:-0}
	local finalize_signal=${5:-0}
	local move_signal=${6:-0}
	local artifacts="$tmp/$name/artifacts"
	local status

	mkdir -p "$artifacts"
	set +e
	PATH="$tmp/bin:$PATH" \
		FRDP_E2E_ARTIFACTS="$artifacts" \
		FRDP_E2E_REPETITIONS="$repetitions" \
		FRDP_FAKE_COUNTER="$tmp/$name/counter" \
		FRDP_FAKE_UP_LOG="$tmp/$name/up.log" \
		FRDP_FAKE_DOWN_LOG="$tmp/$name/down.log" \
		FRDP_FAKE_STATUSES="$statuses" \
		FRDP_FAKE_INCOMPLETE="$incomplete" \
		FRDP_FAKE_FINALIZE_SIGNAL="$finalize_signal" \
		FRDP_FAKE_SIGNAL_MARKER="$tmp/$name/signal-marker" \
		FRDP_FAKE_MOVE_SIGNAL="$move_signal" \
		FRDP_FAKE_MOVE_SIGNAL_MARKER="$tmp/$name/move-signal-marker" \
		bash "$root/run.sh" component >"$tmp/$name/output.log" 2>&1
	status=$?
	set -e
	printf '%s\n' "$status"
}

status=$(run_case single 1 7)
[[ $status == 7 ]]
[[ $(<"$tmp/single/artifacts/component/exit-code.txt") == 7 ]]
[[ ! -e $tmp/single/artifacts/component/repetition-summary.txt ]]
[[ $(grep -c -- '--profile component down --volumes --remove-orphans' \
	"$tmp/single/down.log") == 2 ]]

status=$(run_case repeated 3 0,7)
[[ $status == 7 ]]
grep -Fxq 'requested=3 completed=2 status=7' \
	"$tmp/repeated/artifacts/component/repetition-summary.txt"
[[ $(<"$tmp/repeated/artifacts/component/run-1/exit-code.txt") == 0 ]]
[[ $(<"$tmp/repeated/artifacts/component/run-2/exit-code.txt") == 7 ]]
[[ ! -e $tmp/repeated/artifacts/component/run-3 ]]
[[ $(grep -c -- '--build' "$tmp/repeated/up.log") == 1 ]]
[[ $(grep -c -- '--no-build' "$tmp/repeated/up.log") == 1 ]]

status=$(run_case incomplete 2 0 1)
[[ $status == 1 ]]
grep -Fxq 'requested=2 completed=0 status=1' \
	"$tmp/incomplete/artifacts/component/repetition-summary.txt"
[[ -d $tmp/incomplete/artifacts/component/incomplete-run-1 ]]
[[ ! -e $tmp/incomplete/artifacts/component/incomplete-run-1/exit-code.txt ]]
[[ ! -e $tmp/incomplete/artifacts/component/run-1 ]]
[[ $(grep -c -- '--profile component down --volumes --remove-orphans' \
	"$tmp/incomplete/down.log") == 2 ]]

status=$(run_case finalize-signal 2 0,0 0 1)
[[ $status == 143 ]]
grep -Fxq 'requested=2 completed=2 status=143' \
	"$tmp/finalize-signal/artifacts/component/repetition-summary.txt"
[[ $(<"$tmp/finalize-signal/artifacts/component/run-1/exit-code.txt") == 0 ]]
[[ $(<"$tmp/finalize-signal/artifacts/component/run-2/exit-code.txt") == 0 ]]
[[ ! -e $tmp/finalize-signal/artifacts/component/run-1/component ]]

status=$(run_case move-signal 2 0,0 0 0 1)
[[ $status == 143 ]]
grep -Fxq 'requested=2 completed=1 status=143' \
	"$tmp/move-signal/artifacts/component/repetition-summary.txt"
[[ $(<"$tmp/move-signal/artifacts/component/run-1/exit-code.txt") == 0 ]]
[[ ! -e $tmp/move-signal/artifacts/component/run-2 ]]
