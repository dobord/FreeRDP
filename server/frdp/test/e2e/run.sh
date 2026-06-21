#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
compose_file="$root/compose.yaml"
artifacts=${FRDP_E2E_ARTIFACTS:-$root/artifacts}
keep=${FRDP_E2E_KEEP:-0}

export FRDP_E2E_ARTIFACTS="$artifacts"
mkdir -p "$artifacts"

command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 2; }

compose=(docker compose -f "$compose_file")

cleanup()
{
	if [[ $keep != 1 ]]; then
		"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
}

run_profile()
{
	local profile=$1
	local exit_service=$2
	local status=0
	local output="$artifacts/$profile/compose-up.log"

	mkdir -p "$artifacts/$profile"
	: >"$output"
	"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true

	set +e
	"${compose[@]}" --profile "$profile" up --build \
		--abort-on-container-exit \
		--exit-code-from "$exit_service" \
		"$exit_service" 2>&1 | tee "$output"
	status=${PIPESTATUS[0]}
	set -e

	"${compose[@]}" --profile "$profile" logs --no-color >"$artifacts/$profile/compose.log" 2>&1 || true
	"${compose[@]}" --profile "$profile" ps -a >"$artifacts/$profile/compose-ps.txt" 2>&1 || true
	printf '%s\n' "$status" >"$artifacts/$profile/exit-code.txt"
	cleanup
	return "$status"
}

usage()
{
	cat >&2 <<EOF
Usage: bash $0 component|local|samba|freeipa|all

  component  Build and run focused CTest/component coverage.
  local      Real TLS/NLA/CredSSP, local PAM and managed-session lifecycle.
  samba      Samba AD DC + adcli + SSSD AD + PAM + real RDP lifecycle.
  freeipa    Official FreeIPA server + SSSD LDAP/Kerberos + PAM + real RDP lifecycle.
  all        Run all profiles sequentially.

Set FRDP_E2E_KEEP=1 to leave failed containers and volumes running for diagnosis.
EOF
}

profile=${1:-}
case "$profile" in
	component)
		run_profile component component-tests
		;;
	local)
		run_profile local rdp-client-local
		;;
	samba)
		run_profile samba rdp-client-samba
		;;
	freeipa)
		if [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
			echo "warning: the FreeIPA profile is designed for a cgroups-v2 Docker host" >&2
		fi
		run_profile freeipa rdp-client-freeipa
		;;
	all)
		run_profile component component-tests
		run_profile local rdp-client-local
		run_profile samba rdp-client-samba
		run_profile freeipa rdp-client-freeipa
		;;
	*)
		usage
		exit 2
		;;
esac
