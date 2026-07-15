#!/usr/bin/env bash
set -Eeuo pipefail

case "${0##*/}" in
  systemctl)
    printf 'systemctl %s\n' "$*" >> "$FRDP_MAINTSCRIPT_LOG"
    if [[ "$*" == "--system --quiet is-active "* ]]; then
      unit=${4:-}
      [[ ",${FRDP_ACTIVE_UNITS:-}," == *",$unit,"* ]]
    fi
    exit 0
    ;;
  deb-systemd-invoke)
    printf 'deb-systemd-invoke %s\n' "$*" >> "$FRDP_MAINTSCRIPT_LOG"
    exit "${FRDP_DEB_SYSTEMD_INVOKE_STATUS:-0}"
    ;;
  deb-systemd-helper)
    printf 'deb-systemd-helper %s\n' "$*" >> "$FRDP_HELPER_LOG"
    [[ "${1:-}" != "debian-installed" ]]
    exit 0
    ;;
  systemd-tmpfiles)
    exit 0
    ;;
esac

if [[ $# -ne 3 ]]; then
  echo "usage: $0 POSTINST PRERM POSTRM" >&2
  exit 2
fi

script_path=$(realpath "$0")
test_root=$(mktemp -d)
trap 'rm -rf "$test_root"' EXIT
mock_bin="$test_root/bin"
export FRDP_MAINTSCRIPT_LOG="$test_root/actions.log"
export FRDP_HELPER_LOG="$test_root/helper.log"
export FRDP_TEST_SYSTEMD_RUNTIME="$test_root/run/systemd/system"
mkdir -p "$mock_bin"
mkdir -p "$FRDP_TEST_SYSTEMD_RUNTIME"
ln -s "$script_path" "$mock_bin/systemctl"
ln -s "$script_path" "$mock_bin/deb-systemd-invoke"
ln -s "$script_path" "$mock_bin/deb-systemd-helper"
ln -s "$script_path" "$mock_bin/systemd-tmpfiles"
export PATH="$mock_bin:$PATH"

prepare_script() {
  local input=$1
  local output=$2
  sed 's#-d /run/systemd/system#-d "$FRDP_TEST_SYSTEMD_RUNTIME"#g' "$input" > "$output"
  chmod 0755 "$output"
}

postinst="$test_root/postinst"
prerm="$test_root/prerm"
postrm="$test_root/postrm"
prepare_script "$1" "$postinst"
prepare_script "$2" "$prerm"
prepare_script "$3" "$postrm"

expect_empty_log() {
  if [[ -s "$FRDP_MAINTSCRIPT_LOG" ]]; then
    echo "unexpected maintainer-script actions:" >&2
    cat "$FRDP_MAINTSCRIPT_LOG" >&2
    exit 1
  fi
}

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
"$postinst" configure
expect_empty_log

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
DPKG_ROOT="$test_root/root" "$postinst" configure 0.1.0-1
expect_empty_log

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
export FRDP_ACTIVE_UNITS="frdp-authd.service,frdpd.service"
export FRDP_DEB_SYSTEMD_INVOKE_STATUS=1
"$postinst" configure 0.1.0-1
cat > "$test_root/expected-upgrade.log" <<'EOF'
systemctl --system daemon-reload
systemctl --system --quiet is-active frdp-authd.service
deb-systemd-invoke restart frdp-authd.service
systemctl --system --quiet is-active frdp-sesmand.service
systemctl --system --quiet is-active frdpd.service
deb-systemd-invoke restart frdpd.service
EOF
cmp "$test_root/expected-upgrade.log" "$FRDP_MAINTSCRIPT_LOG"
unset FRDP_DEB_SYSTEMD_INVOKE_STATUS

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
"$prerm" upgrade 0.1.0-2
expect_empty_log

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
DPKG_ROOT="$test_root/root" "$prerm" remove
expect_empty_log

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
"$prerm" remove
cat > "$test_root/expected-remove.log" <<'EOF'
deb-systemd-invoke stop frdp-authd.service frdp-sesmand.service frdpd.service
EOF
cmp "$test_root/expected-remove.log" "$FRDP_MAINTSCRIPT_LOG"

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
DPKG_ROOT="$test_root/root" "$postrm" remove
expect_empty_log

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
"$postrm" remove
printf '%s\n' 'systemctl --system daemon-reload' > "$test_root/expected-postrm.log"
cmp "$test_root/expected-postrm.log" "$FRDP_MAINTSCRIPT_LOG"

: > "$FRDP_MAINTSCRIPT_LOG"
: > "$FRDP_HELPER_LOG"
DPKG_ROOT="$test_root/root" "$postrm" purge
expect_empty_log
printf '%s\n' \
  'deb-systemd-helper purge frdp-authd.service frdp-sesmand.service frdpd.service' \
  > "$test_root/expected-helper.log"
cmp "$test_root/expected-helper.log" "$FRDP_HELPER_LOG"
