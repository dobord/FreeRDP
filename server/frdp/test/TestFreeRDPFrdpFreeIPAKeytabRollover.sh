#!/usr/bin/env bash
set -Eeuo pipefail

ready_script=${1:?path to freeipa-ready.sh is required}
test_root=$(mktemp -d "${TMPDIR:-/tmp}/frdp-keytab-rollover.XXXXXX")
trap 'rm -rf "$test_root"' EXIT

data_dir=$test_root/data
keytab_dir=$test_root/keytab
stub_dir=$test_root/bin
state_dir=$test_root/state
mkdir -p "$data_dir" "$keytab_dir" "$stub_dir" "$state_dir"
touch "$data_dir/frdp-e2e-seeded"

cat >"$stub_dir/ipactl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$stub_dir/kinit" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$stub_dir/kdestroy" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"$stub_dir/klist" <<'EOF'
#!/usr/bin/env bash
printf 'Keytab name: FILE:%s\nKVNO Principal\n---- --------------------------------------------------------------------------\n2 host/frdpd.ipa.test@IPA.TEST\n' "$2"
EOF
cat >"$stub_dir/ipa-getkeytab" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

keytab=
while (($# > 0)); do
	case "$1" in
		-k)
			keytab=$2
			shift 2
			;;
		*)
			shift
			;;
	esac
done
printf 'entered\n' >"$FRDP_TEST_STATE/ipa-getkeytab-entered"
if [[ ${FRDP_TEST_FAULT:-} == kill ]]; then
	kill -KILL "$PPID"
	exit 0
fi
: >"$keytab"
EOF
cat >"$stub_dir/mv" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail

if [[ ${FRDP_TEST_FAULT:-} == metadata-failure && ${!#} == */keytab-rollover-ready ]]; then
	exit 1
fi
exec /usr/bin/mv "$@"
EOF
chmod 0755 "$stub_dir"/*

run_ready()
{
	env \
		PATH="$stub_dir:$PATH" \
		PASSWORD=test-password \
		FRDP_E2E_DATA_DIR="$data_dir" \
		FRDP_E2E_KEYTAB_DIR="$keytab_dir" \
		FRDP_FREEIPA_HOST=frdpd.ipa.test \
		FRDP_FREEIPA_REALM=IPA.TEST \
		FRDP_TEST_STATE="$state_dir" \
		FRDP_TEST_FAULT="${1:-}" \
		bash "$ready_script"
}

write_request()
{
	printf 'principal=host/frdpd.ipa.test@IPA.TEST\nold_kvno=1\n' \
		>"$keytab_dir/keytab-rollover-request"
}

write_request
if run_ready kill 2>/dev/null; then
	printf 'killed rollover worker unexpectedly succeeded\n' >&2
	exit 1
fi
[[ -f $keytab_dir/keytab-rollover-in-progress ]] || {
	printf 'killed rollover worker did not leave an in-progress marker\n' >&2
	exit 1
}
if run_ready; then
	printf 'stale in-progress rollover unexpectedly retried\n' >&2
	exit 1
fi
[[ -f $keytab_dir/keytab-rollover-failed ]] || {
	printf 'stale in-progress rollover did not fail closed\n' >&2
	exit 1
}

rm -rf "$keytab_dir" "$state_dir"
mkdir -p "$keytab_dir" "$state_dir"
write_request
if run_ready metadata-failure; then
	printf 'post-rotation metadata failure unexpectedly succeeded\n' >&2
	exit 1
fi
[[ -f $keytab_dir/keytab-rollover-failed ]] || {
	printf 'post-rotation metadata failure did not publish a failure marker\n' >&2
	exit 1
}
[[ ! -f $keytab_dir/keytab-rollover-ready ]] || {
	printf 'post-rotation metadata failure published a ready marker\n' >&2
	exit 1
}
