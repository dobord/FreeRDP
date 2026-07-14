#!/usr/bin/env bash
set -Eeuo pipefail

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
repo_root=$(cd "$root/../../../.." && pwd)
compose_file="$root/compose.yaml"
artifacts=${FRDP_E2E_ARTIFACTS:-$root/artifacts}
keep=${FRDP_E2E_KEEP:-0}
profile_timeout=${FRDP_E2E_PROFILE_TIMEOUT:-1800}

mkdir -p "$artifacts"
artifacts=$(cd "$artifacts" && pwd -P)
if [[ $(basename "$artifacts") != artifacts || $artifacts == /artifacts ||
	$artifacts == "$repo_root" ]]; then
	echo "FRDP_E2E_ARTIFACTS must be a dedicated non-root directory named artifacts" >&2
	exit 2
fi
export FRDP_E2E_ARTIFACTS="$artifacts"

positive_integer()
{
	[[ $1 =~ ^[1-9][0-9]*$ ]]
}

positive_integer "$profile_timeout" || { echo "FRDP_E2E_PROFILE_TIMEOUT must be positive" >&2; exit 2; }
command -v git >/dev/null 2>&1 || { echo "git is required" >&2; exit 2; }
command -v tar >/dev/null 2>&1 || { echo "tar is required" >&2; exit 2; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 2; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required" >&2; exit 2; }
command -v timeout >/dev/null 2>&1 || { echo "timeout is required" >&2; exit 2; }

snapshot_excluded_paths=("${root#"$repo_root/"}/artifacts")
if [[ $artifacts == "$repo_root/"* &&
	${artifacts#"$repo_root/"} != "${snapshot_excluded_paths[0]}" ]]; then
	snapshot_excluded_paths+=("${artifacts#"$repo_root/"}")
fi
snapshot_excludes=()
for excluded_path in "${snapshot_excluded_paths[@]}"; do
	snapshot_excludes+=("--exclude=$excluded_path")
done
source_archive=$(mktemp "${TMPDIR:-/tmp}/frdp-source.XXXXXX.tar.gz")
cleanup_source_archive()
{
	[[ -z ${source_archive:-} ]] || rm -f "$source_archive"
}
trap cleanup_source_archive EXIT

git -C "$repo_root" rev-parse 'HEAD^{tree}' >"$artifacts/base-tree-sha.txt"
tar -C "$repo_root" -czf "$source_archive" "${snapshot_excludes[@]}" \
	server/frdp tools/frdpctl include/freerdp/channels/wtsvc.h \
	libfreerdp/core/server.c libfreerdp/core/server.h \
	.github/workflows/frdpd-compose.yml
for excluded_path in "${snapshot_excluded_paths[@]}"; do
	while IFS= read -r archive_entry; do
		if [[ $archive_entry == "$excluded_path" || $archive_entry == "$excluded_path/"* ]]; then
			echo "source snapshot contains excluded path: $excluded_path" >&2
			exit 2
		fi
	done < <(tar -tzf "$source_archive")
done
mv "$source_archive" "$artifacts/frdp-source.tar.gz"
source_archive=

compose=(docker compose -f "$compose_file")

cleanup()
{
	if [[ $keep != 1 ]]; then
		"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	fi
}

validate_rdp_auth_artifacts()
{
	local profile=$1
	local server_service=$2
	local server_id server_log server_env test_user deny_user accepted rejected
	local total_accepted total_rejected
	local ntlm_proof_rejected wrong_password_rejected disabled_account_rejected

	server_id=$("${compose[@]}" --profile "$profile" ps -a -q "$server_service" 2>/dev/null || true)
	if [[ -z $server_id || $server_id == *$'\n'* ]]; then
		printf 'profile %s did not produce exactly one %s container\n' \
			"$profile" "$server_service" >&2
		return 1
	fi
	server_log="$artifacts/$profile/server-auth.log"
	docker logs --timestamps "$server_id" >"$server_log" 2>&1 || return 1
	server_env=$(docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' "$server_id") ||
		return 1
	test_user=$(sed -n 's/^FRDP_TEST_USER=//p' <<<"$server_env")
	deny_user=$(sed -n 's/^FRDP_DENY_USER=//p' <<<"$server_env")
	if [[ -z $test_user || $test_user == *$'\n'* || -z $deny_user || $deny_user == *$'\n'* ]]; then
		printf 'profile %s server has ambiguous E2E user configuration\n' "$profile" >&2
		return 1
	fi
	accepted=$(grep -Fc "PAM accepted RDP login for $test_user from" "$server_log" || true)
	total_accepted=$(grep -c 'PAM accepted RDP login' "$server_log" || true)
	wrong_password_rejected=$(
		grep -F "PAM rejected RDP login for $test_user from" "$server_log" |
			grep -c ': denied ' || true
	)
	disabled_account_rejected=$(
		grep -F "PAM rejected RDP login for $deny_user from" "$server_log" |
			grep -c ': denied ' || true
	)
	ntlm_proof_rejected=$(grep -Fc 'Message Integrity Check (MIC) verification failed!' \
		"$server_log" || true)
	rejected=$((wrong_password_rejected + disabled_account_rejected))
	total_rejected=$(grep -c 'PAM rejected RDP login.*: denied ' "$server_log" || true)
	if [[ $accepted -ne 3 || $total_accepted -ne 3 || $rejected -ne 2 ||
		$total_rejected -ne 2 ]]; then
		printf 'profile %s expected 3 PAM accepts and 2 PAM denials, got %s and %s\n' \
			"$profile" "$total_accepted" "$total_rejected" >&2
		return 1
	fi
	if [[ $ntlm_proof_rejected -ne 1 || $wrong_password_rejected -ne 0 ||
		$disabled_account_rejected -ne 2 ]]; then
		printf 'profile %s did not produce one NTLM proof rejection and two disabled-user PAM denials\n' \
			"$profile" >&2
		return 1
	fi
	if grep -q 'proof identity does not match the delegated credentials' "$server_log"; then
		printf 'profile %s encountered an NTLM proof/delegated identity mismatch\n' \
			"$profile" >&2
		return 1
	fi
}

run_profile()
{
	local profile=$1
	local exit_service=$2
	local auth_server_service=${3:-}
	local status=0
	local output="$artifacts/$profile/compose-up.log"
	local container_ids="$artifacts/$profile/container-ids.txt"

	rm -rf -- "${artifacts:?}/$profile"
	mkdir -p "$artifacts/$profile"
	: >"$output"
	"${compose[@]}" down --volumes --remove-orphans >/dev/null 2>&1 || true
	"${compose[@]}" --profile "$profile" config >"$artifacts/$profile/compose-config.yaml" 2>&1 || true

	set +e
	timeout "${profile_timeout}s" "${compose[@]}" --profile "$profile" up --build \
		--abort-on-container-exit \
		--exit-code-from "$exit_service" \
		"$exit_service" 2>&1 | tee "$output"
	status=${PIPESTATUS[0]}
	set -e
	if [[ $status -eq 124 ]]; then
		printf 'profile %s exceeded FRDP_E2E_PROFILE_TIMEOUT=%s seconds\n' \
			"$profile" "$profile_timeout" | tee -a "$output" >&2
	fi

	"${compose[@]}" --profile "$profile" logs --no-color --timestamps >"$artifacts/$profile/compose.log" 2>&1 || true
	"${compose[@]}" --profile "$profile" ps -a >"$artifacts/$profile/compose-ps.txt" 2>&1 || true
	"${compose[@]}" --profile "$profile" ps -a -q >"$container_ids" 2>/dev/null || true
	mkdir -p "$artifacts/$profile/container-logs" "$artifacts/$profile/container-inspect"
	while IFS= read -r container_id; do
		[[ -n $container_id ]] || continue
		local container_name
		container_name=$(docker inspect --format '{{.Name}}' "$container_id" 2>/dev/null || true)
		container_name=${container_name#/}
		container_name=${container_name//[^A-Za-z0-9_.-]/_}
		if [[ -z $container_name ]]; then
			container_name=$container_id
		fi
		docker logs --timestamps "$container_id" >"$artifacts/$profile/container-logs/$container_name.log" 2>&1 || true
		docker inspect "$container_id" >"$artifacts/$profile/container-inspect/$container_name.json" 2>&1 || true
	done <"$container_ids"
	if [[ $status -eq 0 && -n $auth_server_service ]] &&
		! validate_rdp_auth_artifacts "$profile" "$auth_server_service"; then
		status=1
	fi
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
Set FRDP_E2E_PROFILE_TIMEOUT=<seconds> to bound each Compose profile run.
EOF
}

profile=${1:-}
case "$profile" in
	component)
		run_profile component component-tests
		;;
	local)
		run_profile local rdp-client-local frdpd-local
		;;
	samba)
		run_profile samba rdp-client-samba frdpd-samba
		;;
	freeipa)
		if [[ ! -e /sys/fs/cgroup/cgroup.controllers ]]; then
			echo "warning: the FreeIPA profile is designed for a cgroups-v2 Docker host" >&2
		fi
		run_profile freeipa rdp-client-freeipa frdpd-freeipa
		;;
	all)
		run_profile component component-tests
		run_profile local rdp-client-local frdpd-local
		run_profile samba rdp-client-samba frdpd-samba
		run_profile freeipa rdp-client-freeipa frdpd-freeipa
		;;
	*)
		usage
		exit 2
		;;
esac
