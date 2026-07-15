#!/usr/bin/env bash
set -Eeuo pipefail

FRDP_E2E_CONTROL_DIR=${FRDP_E2E_CONTROL_DIR:-/run/frdp-e2e-control}
FRDP_ARTIFACT_DIR=${FRDP_ARTIFACT_DIR:-/artifacts}
FRDP_IDENTITY_PROVIDER=${FRDP_IDENTITY_PROVIDER:-}

case "$FRDP_IDENTITY_PROVIDER" in
	samba)
		provider_result=samba-ad-sssd
		;;
	freeipa)
		provider_result=freeipa-sssd
		;;
	*)
		printf 'unsupported recovery provider: %s\n' "$FRDP_IDENTITY_PROVIDER" >&2
		exit 1
		;;
esac

mkdir -p "$FRDP_ARTIFACT_DIR" "$FRDP_E2E_CONTROL_DIR"
mkdir -p "$FRDP_ARTIFACT_DIR/provider-sesmand-crash" \
	"$FRDP_ARTIFACT_DIR/provider-post-recovery"
chmod 0777 "$FRDP_ARTIFACT_DIR/provider-sesmand-crash" \
	"$FRDP_ARTIFACT_DIR/provider-post-recovery"

bash /opt/frdp-e2e/scripts/rdp-probe.sh

if [[ $FRDP_IDENTITY_PROVIDER == freeipa ]]; then
	rollover_result="$FRDP_E2E_CONTROL_DIR/keytab-rollover-result"
	[[ -s $rollover_result ]] || {
		printf 'FreeIPA keytab rollover result is missing\n' >&2
		exit 1
	}
	install -m 0644 "$rollover_result" "$FRDP_ARTIFACT_DIR/freeipa-keytab-rollover.txt"
	printf 'post_rollover_pam_sssd_rdp=pass\n' >>"$FRDP_ARTIFACT_DIR/freeipa-keytab-rollover.txt"
fi

: >"$FRDP_E2E_CONTROL_DIR/arm-sesmand-crash"
FRDP_ARTIFACT_DIR="$FRDP_ARTIFACT_DIR/provider-sesmand-crash" \
	FRDP_SESSION_EXPECT_MANAGER_CRASH=1 \
	bash /opt/frdp-e2e/scripts/rdp-session-smoke.sh

FRDP_ARTIFACT_DIR="$FRDP_ARTIFACT_DIR/provider-post-recovery" \
	bash /opt/frdp-e2e/scripts/rdp-session-smoke.sh

printf 'provider=%s\nhelper=frdp-sesmand\nactive_session_crash=pass\npost_recovery_session=pass\n' \
	"$provider_result" >"$FRDP_ARTIFACT_DIR/provider-recovery.txt"
